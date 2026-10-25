#!/bin/sh
# Build the worker into worker/build/ for `wrangler deploy`.
#
# Cloudflare's build image has no Rust, so a minimal toolchain is installed
# the first time; where Rust is already present this only builds.
# CLD_PHONE_BUILD=--dev gives a quick unoptimized build for checking.
set -eu
cd "$(dirname "$0")"

if ! command -v cargo > /dev/null 2>&1; then
    if [ ! -f "$HOME/.cargo/env" ]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs |
            sh -s -- -y --profile minimal --default-toolchain stable
    fi
    . "$HOME/.cargo/env"
fi
if command -v rustup > /dev/null 2>&1; then
    rustup target add wasm32-unknown-unknown
fi
if ! command -v worker-build > /dev/null 2>&1; then
    cargo install worker-build --version 0.8.7 --locked
fi

cd worker
worker-build "${CLD_PHONE_BUILD:---release}"
