#!/usr/bin/env bash
# renewal-only.sh [seconds] : just the HTTPS-under-ACME-renewal part of bench.sh
set -uo pipefail
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPTS/env.sh"
BIN=${BIN:-$BUILD/release}
RUN=${RUN:-$HOME/fwm-run/renewal}
. "$SCRIPTS/lab.sh"
start_daemon || exit 1
ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i admin_key admin@127.0.0.1 'request certificate renew'
"$BIN/fwbench" https-load 8443 trust.pem "${1:-30}" 4 "$ADMIN_TOKEN" 2000
rc=$?
kill $DPID $PEBBLE_PID 2>/dev/null; wait $DPID $PEBBLE_PID 2>/dev/null
exit $rc
