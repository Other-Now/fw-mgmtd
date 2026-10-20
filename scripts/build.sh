#!/usr/bin/env bash
# build.sh [release|asan|fuzz]
set -euo pipefail
. "$(dirname "$0")/env.sh"
kind=${1:-release}
case $kind in
  release) cmake -S "$SRC" -B "$BUILD/release" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFWM_DEPS_ROOT="${FWM_DEPS_ROOT:-}" >/dev/null
           cmake --build "$BUILD/release" ;;
  asan)    cmake -S "$SRC" -B "$BUILD/asan" -G Ninja -DCMAKE_BUILD_TYPE=Debug -DFWM_SANITIZE=ON -DFWM_DEPS_ROOT="${FWM_DEPS_ROOT:-}" >/dev/null
           cmake --build "$BUILD/asan" ;;
  fuzz)    CXX=$CLANGXX cmake -S "$SRC" -B "$BUILD/fuzz" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFWM_FUZZ=ON -DFWM_SANITIZE=ON >/dev/null
           cmake --build "$BUILD/fuzz" ;;
  *) echo "usage: build.sh [release|asan|fuzz]"; exit 2 ;;
esac
