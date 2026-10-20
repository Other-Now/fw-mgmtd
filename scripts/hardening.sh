#!/usr/bin/env bash
# hardening.sh [binary] : checksec-style report from readelf, no extra tools needed.
set -uo pipefail
. "$(dirname "$0")/env.sh"
B=${1:-$BUILD/release/fw-mgmtd}
FAILS=0
row() { printf "%-34s %s\n" "$1" "$2"; [ "${3:-ok}" = bad ] && FAILS=$((FAILS+1)); return 0; }
hdr=$(readelf -hW "$B"); dyn=$(readelf -dW "$B"); ph=$(readelf -lW "$B"); syms=$(readelf -sW --dyn-syms "$B"); notes=$(readelf -nW "$B")
grep -q 'Type:.*DYN' <<<"$hdr" && row "PIE" "yes" || row "PIE" "NO" bad
grep -q GNU_RELRO <<<"$ph" && grep -q 'BIND_NOW\|FLAGS.*NOW' <<<"$dyn" && row "RELRO" "full (relro + bind_now)" || row "RELRO" "partial/none" bad
grep -A1 GNU_STACK <<<"$ph" | grep -q 'RWE' && row "NX stack" "NO (executable stack)" bad || row "NX stack" "yes"
grep -q __stack_chk_fail <<<"$syms" && row "stack protector" "yes (__stack_chk_fail referenced)" || row "stack protector" "NO" bad
n=$(grep -o '__[a-z_]*_chk' <<<"$syms" | sort -u | wc -l)
[ "$n" -gt 0 ] && row "FORTIFY_SOURCE" "yes ($n fortified libc calls: $(grep -o '__[a-z_]*_chk' <<<"$syms" | sort -u | grep -v stack_chk | head -4 | tr '\n' ' ')...)" || row "FORTIFY_SOURCE" "NO" bad
grep -q 'IBT' <<<"$notes" && grep -q 'SHSTK' <<<"$notes" && row "CET (IBT + SHSTK markers)" "yes" || row "CET (IBT + SHSTK markers)" "no (some linked object lacks the note)" warn
grep -q 'RUNPATH\|RPATH' <<<"$dyn" && row "RPATH/RUNPATH" "present: $(grep -o 'R[UN]*PATH.*' <<<"$dyn")" warn || row "RPATH/RUNPATH" "none"
echo "hardening: $FAILS required checks failed"
exit $FAILS
