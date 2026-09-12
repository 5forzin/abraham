#!/usr/bin/env bash
# Builds the Abraham resident kernel payload (ABR-T021) from
# payloads/abraham-km/payload.rs into a driver PE with the Rust
# toolchain alone - no WDK, no MSVC env: the payload is freestanding
# Rust with ZERO imports (kernel functions arrive through the mapper's
# injected function table), linked by rust-lld as a native driver.
set -euo pipefail
cd "$(dirname "$0")/.."

SYSROOT="$(rustc --print sysroot)"
LLD="$SYSROOT/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe"
OUT="payloads/abraham-km/abraham-km.sys"

rustc \
  --edition 2021 \
  --crate-type bin \
  --emit=obj \
  -C opt-level=2 \
  -C panic=abort \
  -C relocation-model=pic \
  -o payloads/abraham-km/payload.obj \
  payloads/abraham-km/payload.rs

"$LLD" -flavor link \
  /MACHINE:X64 \
  /SUBSYSTEM:NATIVE \
  /ENTRY:DriverEntry \
  /DRIVER \
  /DYNAMICBASE \
  /FIXED:NO \
  /NODEFAULTLIB \
  /OUT:"$OUT" \
  payloads/abraham-km/payload.obj

rm -f payloads/abraham-km/payload.obj
echo "built $OUT ($(stat -c%s "$OUT") bytes)"
