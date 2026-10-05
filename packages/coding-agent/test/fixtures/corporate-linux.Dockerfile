# Build/setup network is used before running Pi; model tests use synthetic local endpoints.
FROM node:22.19.0-bookworm@sha256:afff6d8c97964a438d2e6a9c96509367e45d8bf93f790ad561a1eaea926303d9
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap curl openssl gcc libc6-dev python3 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 1001 --create-home --shell /bin/bash pi-test
USER pi-test
WORKDIR /home/pi-test
