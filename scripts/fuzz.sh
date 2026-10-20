#!/usr/bin/env bash
# fuzz.sh [seconds-per-target]   ASan+UBSan libFuzzer run of every target.
set -uo pipefail
. "$(dirname "$0")/env.sh"
SECS=${1:-60}
bash "$SRC/scripts/build.sh" fuzz
OUT=${OUT:-$SRC/results/fuzz}
mkdir -p "$OUT"
status=0
for t in cli config license http; do
  work=$HOME/fwm-fuzz/$t; mkdir -p "$work"; cp -n "$SRC"/fuzz/corpus/$t/* "$work"/ 2>/dev/null
  (cd "$HOME/fwm-fuzz" && "$BUILD/fuzz/fuzz_$t" "$work" -max_total_time="$SECS" -timeout=5 -rss_limit_mb=1536 \
      -print_final_stats=1 -artifact_prefix="$HOME/fwm-fuzz/crash-$t-" > "$OUT/$t.log" 2>&1)
  rc=$?
  execs=$(grep -o 'stat::number_of_executed_units: [0-9]*' "$OUT/$t.log" | awk '{print $2}')
  cov=$(grep -o 'cov: [0-9]*' "$OUT/$t.log" | tail -1 | awk '{print $2}')
  echo "fuzz_$t: rc=$rc execs=${execs:-?} cov=${cov:-?} secs=$SECS"
  [ $rc -ne 0 ] && status=1 && grep -E "ERROR|SUMMARY|Test unit written|timeout" "$OUT/$t.log" | head -5
done
exit $status
