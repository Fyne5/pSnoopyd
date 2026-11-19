# Go2DHCP
Tìm mấy tay chơi ác cắm mấy cục wifi rồi phát ngược DHCP ra mạng. Chủ yếu dành cho người nghèo (như tui) không có tiền xài switch cứng có DHCP Snooping.

Find bad DHCP server (roguer) for POOR-MAN (same me) - who has no real switch hardware with DHCP Snooping supported.

## Mô tả / Describes
Nhìn hình rồi đoán tính năng thôi, chứ đã nghèo mà còn nói nhiều, giải thích chi nữa.

Just look at the image and guess the feature, no point in talking so much or trying to explain when you’re already broke.

<img width="1626" height="1147" alt="Screenshot 2026-11-19 100740" src="https://github.com/user-attachments/assets/6e84104c-7bf0-4970-af1e-504635511a1d" />

## Cách biên dịch ra nhị phân / How to build to binary
```
git clone https://github.com/Fyne5/Go2DHCP.git
cd Go2DHCP
go build -o Go2DHCP main.go
```
Chỉ xài cho Linux thôi

Run on Linux only.
```
GOOS=linux GOARCH=amd64 go build -o Go2DHCP-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o Go2DHCP-linux-arm64 main.go
GOOS=linux GOARCH=386 go build -o Go2DHCP-linux-386 main.go
```

## Cách xài / How to use
```
./Go2DHCP
```
Khai báo trong config.conf, mở trình duyệt lên vào coi `127.0.0.1:8888`.

Declare in the config.conf, open browser and go to `127.0.0.1:8888`.

## Docker bằng docker-compose.yaml / Docker with docker-compose.yaml
Xem trong thư mục docker rồi kích chạy RUN.sh

Look in the docker folder and click RUN.sh

## Đa tạ / Credits
Bởi tui không phải dân lập trình chuyên nghiệp, mà là học tới đâu mò tới đó, hỏi đồng nghiệp, dò A.I Gemini. Nên ai thấy ổn thì xài.

I’m not a professional programmer; I just learn as I go—figuring things out, asking colleagues, and consulting AI tools like Gemini. So, feel free to use it if it works for you.
