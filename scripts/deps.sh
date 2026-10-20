#!/usr/bin/env bash
# Fetch build deps without sudo: unpack Ubuntu debs into ~/fwm-deps/root,
# download Pebble (ACME test CA). In CI, apt-get install is used instead.
set -euo pipefail
ROOT=$HOME/fwm-deps/root
mkdir -p "$ROOT" "$HOME/fwm-deps/dl"
cd "$HOME/fwm-deps/dl"
for p in libssh-dev libclang-rt-20-dev; do
  ls ${p}_*.deb >/dev/null 2>&1 || apt-get download "$p"
done
for d in *.deb; do dpkg-deb -x "$d" "$ROOT"; done
# libssh-dev ships libssh.so -> libssh.so.4; the runtime .so.4 is in /usr/lib already
ln -sf /usr/lib/x86_64-linux-gnu/libssh.so.4 "$ROOT/usr/lib/x86_64-linux-gnu/libssh.so"
PEB=v2.7.0
if [ ! -x "$HOME/fwm-deps/pebble" ]; then
  curl -fsSL -o pebble.tgz "https://github.com/letsencrypt/pebble/releases/download/$PEB/pebble-linux-amd64.tar.gz"
  tar xzf pebble.tgz
  find . -type f -name pebble -exec cp {} "$HOME/fwm-deps/pebble" \;
  chmod +x "$HOME/fwm-deps/pebble"
fi
"$HOME/fwm-deps/pebble" -version 2>&1 | head -1 || true
ls "$ROOT/usr/include/libssh/" | head -3
find "$ROOT" -name 'libclang_rt.fuzzer*.a' | head -2
# libFuzzer runtime next to the clang from ~/llvm20 (unpacked LLVM debs)
RD=$HOME/llvm20/root/usr/lib/llvm-20/lib/clang/20/lib/linux
if [ -d "$HOME/llvm20/root" ]; then mkdir -p "$RD"; cp -n "$ROOT"/usr/lib/llvm-20/lib/clang/20/lib/linux/*.a "$RD"/; fi
