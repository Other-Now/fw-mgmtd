# Sourced by the other scripts. Locally (WSL, no sudo) deps live in ~/fwm-deps;
# in CI they are apt-installed and FWM_DEPS_ROOT stays empty.
export SRC=${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
export BUILD=${BUILD:-$HOME/fwm-build}
if [ -d "$HOME/fwm-deps/root/usr/include/libssh" ]; then
  export FWM_DEPS_ROOT=$HOME/fwm-deps/root
  export PEBBLE=$HOME/fwm-deps/pebble
fi
export PEBBLE=${PEBBLE:-$(command -v pebble || echo pebble)}
# clang 20 from the unpacked LLVM debs (llvm-perf-lab setup) or the system one
if [ -x "$HOME/llvm20/root/usr/lib/llvm-20/bin/clang++" ]; then
  export CLANGXX=$HOME/llvm20/root/usr/lib/llvm-20/bin/clang++
  export LD_LIBRARY_PATH=$HOME/llvm20/root/usr/lib/x86_64-linux-gnu:$HOME/llvm20/root/usr/lib/llvm-20/lib:${LD_LIBRARY_PATH:-}
else
  export CLANGXX=${CLANGXX:-clang++}
fi
