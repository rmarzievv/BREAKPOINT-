#!/usr/bin/env bash
# Cross-compile helper binaries for Windows x64 with zig (pip install ziglang). Prints SHA256 for PREREGISTRATION §7.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
CC="python3 -m ziglang cc -target x86_64-windows-gnu -O2 -s"
$CC enumproc.c -o out/enumproc.exe
$CC netcfg.c -o out/netcfg.exe -liphlpapi -lws2_32
$CC bpsvc.c -o out/bpsvc.exe
cp out/bpsvc.exe out/bpsvc2.exe
cp enumproc.ps1 netcfg.ps1 cleanup_task.ps1 out/
sha256sum out/*
