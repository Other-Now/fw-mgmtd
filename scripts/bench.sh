#!/usr/bin/env bash
# bench.sh [label]   -> results/<label>/*.txt
# commit/rollback latency, CLI-over-SSH latency, HTTPS under ACME renewal churn.
set -uo pipefail
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPTS/env.sh"
BIN=${BIN:-$BUILD/release}
LABEL=${1:-local}
OUT=$SRC/results/$LABEL
mkdir -p "$OUT"
RUN=${RUN:-$HOME/fwm-run/bench}
. "$SCRIPTS/lab.sh"

{ echo "## $(date -u +%FT%TZ)  $(uname -sr)  $(nproc) cpus  $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
  echo "## state dir filesystem: $(df -T "$RUN" | tail -1 | awk '{print $2}')"; } > "$OUT/env.txt"

"$BIN/fwbench" commit "$RUN/commitbench" 200 | tee "$OUT/commit.txt"

start_daemon || { echo "daemon failed"; cat "$DOUT"; exit 1; }
SSH="ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -i admin_key admin@127.0.0.1"
$SSH 'request certificate renew' | tee "$OUT/acme-first.txt"     # switch from self-signed to Pebble
"$BIN/fwbench" ssh 2222 admin admin_key 300 | tee "$OUT/ssh.txt"
# 60 s of new-connection load + 2 keep-alive connections; force an ACME renewal every 2 s
"$BIN/fwbench" https-load 8443 trust.pem 60 4 "$ADMIN_TOKEN" 2000 | tee "$OUT/https-renewal.txt"
# automatic renewal: 300 s certs, renew-before 240 s -> the timer renews on its own about once a minute
sleep 70
$SSH 'show certificate' > "$OUT/certificate.txt"
$SSH 'show diagnostics' > "$OUT/diagnostics.txt"
grep -c CERT_RENEWED state/fw-mgmtd.log | sed 's/^/CERT_RENEWED log lines: /' >> "$OUT/certificate.txt"
grep 'CERT_RENEWED' state/fw-mgmtd.log | grep -v manual | head -3 >> "$OUT/certificate.txt"
cat "$OUT/certificate.txt"
kill $DPID $PEBBLE_PID 2>/dev/null; wait $DPID $PEBBLE_PID 2>/dev/null
