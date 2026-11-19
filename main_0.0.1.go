//go:build linux && (amd64 || arm64 || 386 || arm)

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var version = "0.0.1"

const (
	ethPIP              = 0x0800
	solPacket           = 0x107
	packetAddMembership = 1
	packetMrPromisc     = 1

	numWorkers    = 2
	chanSize      = 2048
	maxAlerts     = 100
	alertCooldown = 30 * time.Second
	tsLayout      = "2006-01-02 15:04:05"
)

// ---------------------------------------------------------------------------
// Kiểu dữ liệu & biến toàn cục
// ---------------------------------------------------------------------------

type AuthorizedServer struct {
	IP  string
	MAC string
}

type Config struct {
	Interface      string
	AllowedServers []AuthorizedServer
	LogShow        bool
	LogFilePath    string
	WebGUI         string
	Promisc        bool
}

type AlertEvent struct {
	FirstSeen   string
	LastSeen    string
	ServerIP    string
	ServerMAC   string
	Description string
	Count       int

	lastLogged time.Time // chỉ dùng nội bộ
}

var (
	cfg Config // chỉ ghi một lần lúc khởi động, sau đó chỉ đọc => không cần khoá

	mu         sync.Mutex // bảo vệ alerts, alertIndex, logFile
	alerts     []*AlertEvent
	alertIndex = map[string]*AlertEvent{}
	logFile    *os.File

	pktTotal, pktDropped atomic.Uint64
)

// Khai báo Pool quản lý buffer tối đa 4096 byte
var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// Gói dữ liệu truyền qua channel để phân tách rõ ràng buffer và kích thước thực
type PacketTask struct {
	Bytes []byte
	Size  int
}

// ---------------------------------------------------------------------------
// Cấu hình
// ---------------------------------------------------------------------------

func loadConfig(path string) (Config, error) {
	c := Config{
		LogShow:     true,
		LogFilePath: "dhcp_security.log",
		WebGUI:      "127.0.0.1:8888",
		Promisc:     true,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}

	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			log.Printf("[CONFIG]: line number %d is missing '=': %q", n+1, line)
			continue
		}
		val := strings.TrimSpace(v)

		switch strings.ToLower(strings.TrimSpace(k)) { // khoá không phân biệt hoa/thường
		case "interface":
			c.Interface = val
		case "allowdhcp":
			c.AllowedServers = parseAllowList(val, n+1)
		case "logshow":
			c.LogShow = isTrue(val)
		case "logfilepath":
			c.LogFilePath = val
		case "webgui":
			c.WebGUI = val
		case "promisc":
			c.Promisc = isTrue(val)
		default:
			log.Printf("[CONFIG]: line %d, bad argument %q", n+1, strings.TrimSpace(k))
		}
	}
	return c, nil
}

// Định dạng: IP[MAC];IP[MAC];...
func parseAllowList(val string, line int) []AuthorizedServer {
	var out []AuthorizedServer
	for _, e := range strings.Split(val, ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		o, c := strings.Index(e, "["), strings.Index(e, "]")
		if o < 0 || c < o {
			log.Printf("[CONFIG]: line %d, bad format %q (need IP[MAC])", line, e)
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(e[:o]))
		mac, err := net.ParseMAC(strings.TrimSpace(e[o+1 : c]))
		if ip == nil || ip.To4() == nil || err != nil || len(mac) != 6 {
			log.Printf("[CONFIG]: line %d, skipped invalid IPv4/MAC %q", line, e)
			continue
		}
		out = append(out, AuthorizedServer{
			IP:  ip.To4().String(),
			MAC: strings.ToUpper(mac.String()),
		})
	}
	return out
}

func isTrue(s string) bool {
	switch strings.ToLower(s) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

func isAuthorized(ip, mac string) bool {
	for _, s := range cfg.AllowedServers {
		if s.IP == ip && s.MAC == mac {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Bắt gói tin bằng AF_PACKET (raw socket tầng 2) + BPF lọc trong kernel
// ---------------------------------------------------------------------------

func htons(v uint16) uint16 { return v<<8 | v>>8 } // đúng cho CPU little-endian, hông hiểu lắm cái này, đi hỏi người ta nói vậy, kệ bỏ qua đi

// Bộ lọc BPF (classic): IPv4 + UDP + bỏ mảnh IP + cổng 67.
var dhcpReplyFilter = []syscall.SockFilter{
	{Code: 0x28, K: 12},                   // 0: ldh [12]          ; EtherType
	{Code: 0x15, Jt: 0, Jf: 8, K: ethPIP}, // 1: jeq 0x0800 ? tiếp : loại
	{Code: 0x30, K: 23},                   // 2: ldb [23]          ; IP protocol
	{Code: 0x15, Jt: 0, Jf: 6, K: 17},     // 3: jeq 17 (UDP) ? tiếp : loại
	{Code: 0x28, K: 20},                   // 4: ldh [20]          ; flags + fragment offset
	{Code: 0x45, Jt: 4, Jf: 0, K: 0x1fff}, // 5: jset 0x1fff ? loại : tiếp
	{Code: 0xb1, K: 14},                   // 6: ldxb 4*([14]&0xf) ; X = độ dài header IP
	{Code: 0x48, K: 14},                   // 7: ldh [x+14]        ; UDP source port
	{Code: 0x15, Jt: 0, Jf: 1, K: 67},     // 8: jeq 67 ? nhận : loại
	{Code: 0x06, K: 0x40000},              // 9: nhận
	{Code: 0x06, K: 0},                    // 10: loại
}

func openRawSocket(ifName string, promisc bool) (int, error) {
	ifi, err := net.InterfaceByName(ifName)
	if err != nil {
		return -1, fmt.Errorf("could not found interface %q: %w", ifName, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		return -1, fmt.Errorf("create AF_PACKET socket (need root/CAP_NET_RAW): %w", err)
	}
	fail := func(what string, err error) (int, error) {
		syscall.Close(fd)
		return -1, fmt.Errorf("%s: %w", what, err)
	}

	// Gắn socket vào đúng một interface, chỉ nhận EtherType IPv4
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: ifi.Index}); err != nil {
		return fail("bind interface", err)
	}

	// Timeout nhận 1 giây để vòng lặp còn kiểm tra được tín hiệu Ctrl+C
	tv := syscall.Timeval{Sec: 1}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fail("put SO_RCVTIMEO", err)
	}

	if err := syscall.AttachLsf(fd, dhcpReplyFilter); err != nil {
		return fail("set BPF filter", err)
	}

	if promisc {
		if err := setPromisc(fd, ifi.Index); err != nil {
			log.Printf("[WARNING]: can not turn on promiscuous mode %v (still running normal mode)", err)
		}
	}
	return fd, nil
}

// struct packet_mreq { int ifindex; u16 type; u16 alen; u8 addr[8]; } = 16 byte.
// Promiscuous tự tắt khi đóng socket nên không cần dọn dẹp.
func setPromisc(fd, ifindex int) error {
	mreq := make([]byte, 16)
	binary.LittleEndian.PutUint32(mreq[0:4], uint32(ifindex))
	binary.LittleEndian.PutUint16(mreq[4:6], packetMrPromisc)
	return syscall.SetsockoptString(fd, solPacket, packetAddMembership, string(mreq))
}

// Luồng 1: đọc frame từ kernel bằng sync.Pool, đẩy sang channel
func capture(ctx context.Context, fd int, out chan<- PacketTask, stop context.CancelFunc) {
	for ctx.Err() == nil {
		// Mượn buffer từ pool thay vì cấp phát mới
		buf := packetPool.Get().([]byte)

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Lỗi thì phải trả lại buffer ngay lập tức tránh rò rỉ
			packetPool.Put(buf)
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			log.Printf("[ERR]: Read socket failed %v", err)
			stop()
			return
		}

		select {
		case out <- PacketTask{Bytes: buf[:n], Size: n}:
		default:
			// Nếu channel đầy, trả lại buffer ngay vì worker không nhận được
			packetPool.Put(buf)
			pktDropped.Add(1)
		}
	}
}

// ---------------------------------------------------------------------------
// Phân tích gói tin (tự parse bằng encoding/binary)
// ---------------------------------------------------------------------------

type dhcpReply struct {
	SrcMAC   string // MAC nguồn ở header Ethernet
	SrcIP    string // IP nguồn ở header IPv4
	MsgType  byte   // option 53: 2=OFFER, 5=ACK, 6=NAK
	ServerID string // option 54 (nếu có)
}

func msgName(t byte) string {
	switch t {
	case 2:
		return "DHCPOFFER"
	case 5:
		return "DHCPACK"
	case 6:
		return "DHCPNAK"
	}
	return fmt.Sprintf("DHCP(type=%d)", t)
}

// Bố cục frame:
//
//	Ethernet 14 B: [0:6] MAC đích | [6:12] MAC nguồn | [12:14] EtherType
//	IPv4: byte 0 = version<<4 | IHL(đơn vị 4 byte), byte 9 = protocol, [12:16] IP nguồn
//	UDP 8 B: [0:2] cổng nguồn, [2:4] cổng đích
//	DHCP: [0] op (2 = BOOTREPLY) ... [236:240] magic cookie 0x63825363, sau đó là options TLV
func parseFrame(f []byte) (r dhcpReply, ok bool) {
	const ethLen = 14
	if len(f) < ethLen+20+8+240 {
		return
	}
	if binary.BigEndian.Uint16(f[12:14]) != ethPIP {
		return
	}

	ip := f[ethLen:]
	if ip[0]>>4 != 4 {
		return
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8+240 {
		return
	}
	if ip[9] != 17 { // không phải UDP
		return
	}
	if binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 { // mảnh IP
		return
	}

	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[0:2]) != 67 { // server luôn gửi từ cổng 67
		return
	}

	d := udp[8:]
	if d[0] != 2 { // phải là BOOTREPLY
		return
	}
	if binary.BigEndian.Uint32(d[236:240]) != 0x63825363 {
		return
	}

	opts := d[240:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == 255 { // end
			break
		}
		if code == 0 { // pad
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		val := opts[i+2 : i+2+l]
		switch code {
		case 53:
			if l == 1 {
				r.MsgType = val[0]
			}
		case 54:
			if l == 4 {
				r.ServerID = net.IP(val).String()
			}
		}
		i += 2 + l
	}

	if r.MsgType != 2 && r.MsgType != 5 && r.MsgType != 6 {
		return
	}
	r.SrcMAC = strings.ToUpper(net.HardwareAddr(f[6:12]).String())
	r.SrcIP = net.IP(ip[12:16]).String()
	return r, true
}

// Luồng 2: worker pool nhận task và hoàn trả buffer sau khi xử lý
func worker(in <-chan PacketTask, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range in {
		handleFrame(task.Bytes)

		// Xử lý xong, lấy lại capacity gốc (65536) rồi trả về pool
		fullBuf := task.Bytes[:cap(task.Bytes)]
		packetPool.Put(fullBuf)
	}
}

func handleFrame(f []byte) {
	r, ok := parseFrame(f)
	if !ok {
		return
	}
	pktTotal.Add(1) // chỉ đếm DHCP reply hợp lệ
	if isAuthorized(r.SrcIP, r.SrcMAC) {
		return
	}
	desc := "Rogue DHCP Server send " + msgName(r.MsgType)
	// Server ID do bên gửi tự khai nên không dùng để xác thực, chỉ ghi chú nếu lệch IP nguồn
	if r.ServerID != "" && r.ServerID != r.SrcIP {
		desc += fmt.Sprintf(" (Server ID khai báo %s khác IP nguồn)", r.ServerID)
	}
	recordAlert(r.SrcIP, r.SrcMAC, desc)
}

// ---------------------------------------------------------------------------
// Cảnh báo (có chống flood)
// ---------------------------------------------------------------------------

func recordAlert(ip, mac, desc string) {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	key := ip + "|" + mac

	if ev, ok := alertIndex[key]; ok {
		ev.Count++
		ev.LastSeen = now.Format(tsLayout)
		if now.Sub(ev.lastLogged) >= alertCooldown {
			ev.lastLogged = now
			writeLog(fmt.Sprintf("[%s] CẢNH BÁO (lặp lại, tổng %d lần): IP=%s, MAC=%s - %s",
				ev.LastSeen, ev.Count, ip, mac, desc))
		}
		return
	}

	ts := now.Format(tsLayout)
	ev := &AlertEvent{
		FirstSeen: ts, LastSeen: ts,
		ServerIP: ip, ServerMAC: mac, Description: desc,
		Count: 1, lastLogged: now,
	}
	alertIndex[key] = ev
	alerts = append([]*AlertEvent{ev}, alerts...)
	if len(alerts) > maxAlerts {
		for _, old := range alerts[maxAlerts:] {
			delete(alertIndex, old.ServerIP+"|"+old.ServerMAC)
		}
		alerts = alerts[:maxAlerts]
	}
	writeLog(fmt.Sprintf("[%s WARNING]: IP=%s, MAC=%s - %s", ts, ip, mac, desc))
}

// Gọi khi đang giữ mu.
func writeLog(msg string) {
	if cfg.LogShow {
		fmt.Println("\033[31m" + msg + "\033[0m")
	}
	if logFile != nil {
		logFile.WriteString(msg + "\n")
	}
}

// ---------------------------------------------------------------------------
// Web GUI
// ---------------------------------------------------------------------------

type dashView struct {
	Cfg     Config
	Alerts  []AlertEvent
	Packets uint64
	Dropped uint64
}

var dashTmpl = template.Must(template.New("dash").Parse(`<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>DHCP Security Monitor</title>
<style>
 body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
 h1 { color: #4ec9b0; }
 table { width: 100%; border-collapse: collapse; margin-top: 20px; }
 th, td { border: 1px solid #333; padding: 10px; text-align: left; }
 th { background: #252526; color: #569cd6; }
 tr:nth-child(even) { background: #2d2d2d; }
 .alert { color: #f44747; font-weight: bold; }
 .status { padding: 10px; background: #264f78; margin-bottom: 20px; border-radius: 4px; }
 ul { background: #252526; padding: 15px 30px; border-radius: 4px; }
</style>
</head>
<body>
<h1>🛡️ DHCP Security Monitor (AF_PACKET + BPF)</h1>
<div class="status">
 <strong>Status:</strong> observing <code>{{.Cfg.Interface}}</code> |
 Legal servers: {{len .Cfg.AllowedServers}} |
 DHCP packages: {{.Packets}} | Skip packages (overload): {{.Dropped}}
</div>

<h2>Whitelist</h2>
<table>
<tr><th>DHCP server</th><th>MAC</th></tr>
{{range .Cfg.AllowedServers}}<tr>
 <td>{{.IP}}</td><td>{{.MAC}}</td>
</tr>
{{else}}<tr><td colspan="2">No valid servers in config file!</td></tr>
{{end}}</table>

<h2>Alert Rogue DHCP Server</h2>
<table>
<tr><th>First time</th><th>Last time</th><th>IP</th><th>MAC</th><th>Numbers</th><th>Description</th></tr>
{{range .Alerts}}<tr>
 <td>{{.FirstSeen}}</td><td>{{.LastSeen}}</td>
 <td class="alert">{{.ServerIP}}</td><td>{{.ServerMAC}}</td>
 <td>{{.Count}}</td><td class="alert">{{.Description}}</td>
</tr>
{{else}}<tr><td colspan="6">No illegal DHCP server is detected, yet</td></tr>
{{end}}</table>
</body>
</html>
`))

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Chỉ giữ khoá lúc sao chép dữ liệu; render và ghi mạng làm ngoài khoá
	mu.Lock()
	view := dashView{Cfg: cfg, Packets: pktTotal.Load(), Dropped: pktDropped.Load()}
	for _, a := range alerts {
		view.Alerts = append(view.Alerts, *a)
	}
	mu.Unlock()

	var buf bytes.Buffer
	if err := dashTmpl.Execute(&buf, view); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func interfaceNames() []string {
	var names []string
	if ifs, err := net.Interfaces(); err == nil {
		for _, i := range ifs {
			names = append(names, i.Name)
		}
	}
	return names
}

func main() {
	log.Printf("Go2DHCP %s", version)
	cfgPath := flag.String("c", "config.conf", "path of config file")
	flag.Parse()

	// 1. Cấu hình. Thiếu file là lỗi nặng: nếu chạy với whitelist rỗng thì
	//    server thật cũng bị báo là Rogue.
	var err error
	if cfg, err = loadConfig(*cfgPath); err != nil {
		log.Fatalf("[ERR]: Can not read config file %q, %v", *cfgPath, err)
	}
	if cfg.Interface == "" || strings.EqualFold(cfg.Interface, "any") {
		log.Fatalf("[ERR]: 'Interface' need strictly config by exact name of interface, now is: %s",
			strings.Join(interfaceNames(), ", "))
	}
	if len(cfg.AllowedServers) == 0 {
		log.Println("[WARNING]: Whitelist is empty, must set arguments for security.")
	}
	log.Printf("[CONFIG]: legal server(s) %d, interface=%s", len(cfg.AllowedServers), cfg.Interface)

	// 2. Mở raw socket (lỗi quyền sẽ báo ở đây)
	fd, err := openRawSocket(cfg.Interface, cfg.Promisc)
	if err != nil {
		log.Fatalf("[ERR] %v", err)
	}
	defer syscall.Close(fd)

	// 3. File log
	if cfg.LogFilePath != "" {
		f, err := os.OpenFile(cfg.LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			log.Printf("[ERR]: Can not open log file %s, %v", cfg.LogFilePath, err)
		} else {
			logFile = f
			defer f.Close()
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 4. Capture -> channel -> worker pool
	ch := make(chan PacketTask, chanSize)
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ch, &wg)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(ch) // đóng channel để worker tự thoát
		capture(ctx, fd, ch, stop)
	}()

	// 5. Web GUI
	var srv *http.Server
	if cfg.WebGUI != "" {
		host, _, _ := net.SplitHostPort(cfg.WebGUI)
		if host == "" || host == "0.0.0.0" || host == "::" {
			log.Printf("[WARNING] Web GUI (%s) is opening for all and not authorizing. "+
				"Should be WebGUi = 127.0.0.1:8888.", cfg.WebGUI)
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/", handleDashboard)
		srv = &http.Server{Addr: cfg.WebGUI, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[ERR]: Web GUI can not start %v", err)
			}
		}()
		log.Printf("🌐Web GUI: http://%s", cfg.WebGUI)
	}

	// Không cần gracefull shutdown, kích là nghỉ
	log.Println("🛡️ Observing, press Ctrl+C to quit.")
	<-ctx.Done()
	log.Println("Stopped.")
}