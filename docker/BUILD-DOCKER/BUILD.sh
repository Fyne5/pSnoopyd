#!/bin/bash

BUILD_NUM="0.0.1"

cat << EOF > Dockerfile_go2dhcp
FROM alpine:3.22.0

RUN apk update && apk upgrade -a && \
    apk add --no-cache \
    iptables \
    iproute2 \
    curl \
    brotli-libs \
    libstdc++ \
    gcompat \
    dos2unix \
    dumb-init

RUN mkdir -p /app/go2dhcp
WORKDIR /app/go2dhcp

COPY go2dhcp .
RUN chmod +x go2dhcp

EXPOSE 8888

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["./go2dhcp"]
EOF

wget -q https://github.com/Fyne5/go2dhcp/releases/download/$BUILD_NUM/go2dhcp-linux-amd64 -O go2dhcp
docker build -t $BUILD_NUM -f Dockerfile_go2dhcp .
docker tag $BUILD_NUM tquang/go2dhcp:$BUILD_NUM

docker push tquang/go2dhcp:$BUILD_NUM

rm -rf Dockerfile_go2dhcp go2dhcp
