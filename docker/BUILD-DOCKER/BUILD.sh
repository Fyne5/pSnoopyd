#!/bin/bash

BUILD_NUM="0.0.1"

cat << EOF > Dockerfile_psnoopyd
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

RUN mkdir -p /app/psnoopyd
WORKDIR /app/psnoopyd

COPY psnoopyd .
RUN chmod +x psnoopyd

EXPOSE 8888

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["./psnoopyd"]
EOF

wget -q https://github.com/Fyne5/psnoopyd/releases/download/$BUILD_NUM/psnoopyd-linux-amd64 -O psnoopyd
docker build -t $BUILD_NUM -f Dockerfile_psnoopyd .
docker tag $BUILD_NUM tquang/psnoopyd:$BUILD_NUM

docker push tquang/psnoopyd:$BUILD_NUM

rm -rf Dockerfile_psnoopyd psnoopyd
