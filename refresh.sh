#!/usr/bin/env bash

docker compose down && \
 git pull && \
 docker compose build && \
 docker compose up -d && \
 docker compose logs -f