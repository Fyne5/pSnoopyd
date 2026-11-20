#!/bin/bash

wget https://raw.githubusercontent.com/Fyne5/pSnoopyd/refs/heads/main/config.conf

docker compose up -d

docker compose logs -f
