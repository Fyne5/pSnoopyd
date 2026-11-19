#!/bin/bash

FILE="main_0.0.1.go"

if [ "$1" == "run" ]; then
    echo "Running debug with race detector..."
    CGO_ENABLED=1 go run --race "$FILE" --config config.conf
    exit 0
fi

rm -f Go2DHCP-*

BUILD_FLAGS=(-trimpath "-ldflags=-s -w")
# Khi build kết hợp 2 tham số này, thì sẽ chỉ còn thấy "-trimpath=true", đó là bình thường.
# Còn "-ldflags=-s -w" sẽ không hiện trực tiếp, khi so dung lượng binary xuất ra mới thấy nhỏ hơn.
# go version -m Go2DHCP-linux-amd64
# Go2DHCP-linux-amd64: go1.24.4
#         path    command-line-arguments
#         build   -buildmode=exe
#         build   -compiler=gc
#         build   -trimpath=true
#         build   CGO_ENABLED=0
#         build   GOARCH=amd64
#         build   GOOS=linux
#         build   GOAMD64=v1

PLATFORMS=(
  "linux/amd64/Go2DHCP-linux-amd64"
  "linux/arm64/Go2DHCP-linux-arm64"
  "linux/386/Go2DHCP-linux-386"
)

echo "Compiling..."

for entry in "${PLATFORMS[@]}"; do
  IFS="/" read -r os arch output <<< "$entry"
  (
    echo " -> Building $output ($os/$arch)..."
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build "${BUILD_FLAGS[@]}" -o "$output" "$FILE"
  ) &
done

wait

chmod +x Go2DHCP-* 2>/dev/null

echo "Done!"