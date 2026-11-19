#!/bin/bash

wget https://raw.githubusercontent.com/Fyne5/Go2DHCP/refs/heads/main/config.conf

docker compose up -d

docker compose logs -f
