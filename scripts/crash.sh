#!/usr/bin/env bash
# crash.sh [kills] : kill -9 the daemon mid-commit-stream, restart, verify.
# Invariants after every restart:
#   1. the store opens (no torn/partial config is ever loaded)
#   2. running commit id >= last commit the client got a 200 for (acked == durable)
#   3. running id <= acked + 1 (at most the one in-flight commit landed)
#   4. hostname matches the commit id (the file content is the commit's, not a mix)
set -uo pipefail
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPTS/env.sh"
BIN=${BIN:-$BUILD/release}
KILLS=${1:-20}
RUN=${RUN:-$HOME/fwm-run/crash}
. "$SCRIPTS/lab.sh"
sed -i '/acme-directory/d' boot.conf   # self-signed is enough here
start_daemon || exit 1
curl -sk https://localhost:8443/api/v1/health >/dev/null
openssl s_client -connect 127.0.0.1:8443 -servername localhost </dev/null 2>/dev/null | openssl x509 > selfsigned.pem
bad=0; total_acked=0
for i in $(seq "$KILLS"); do
  "$BIN/fwbench" api-commit-loop 8443 selfsigned.pem "$ADMIN_TOKEN" > acks.txt 2>/dev/null &
  CL=$!
  sleep "0.$(( (RANDOM % 8) + 2 ))"
  kill -9 $DPID; wait $DPID 2>/dev/null
  wait $CL 2>/dev/null
  acked=$(tail -1 acks.txt | awk '{print $2}'); acked=${acked:-0}
  total_acked=$((total_acked + $(wc -l < acks.txt)))
  start_daemon || { echo "kill $i: daemon did not restart"; cat "$DOUT"; bad=$((bad+1)); break; }
  openssl s_client -connect 127.0.0.1:8443 -servername localhost </dev/null 2>/dev/null | openssl x509 > selfsigned.pem
  j=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:8443/api/v1/config)
  run=$(python3 -c 'import sys,json;print(json.load(sys.stdin)["commit"])' <<<"$j")
  host=$(python3 -c 'import sys,json;print(json.load(sys.stdin)["config"]["system hostname"])' <<<"$j")
  ok=yes
  [ "$run" -ge "$acked" ] || ok="LOST acked commit"
  [ "$run" -le $((acked + 1)) ] || ok="phantom commits"
  [ "$host" = "crash-$run" ] || [ "$run" -le 1 ] || ok="content mismatch ($host)"
  echo "kill $i: acked=$acked running=$run hostname=$host -> $ok"
  [ "$ok" = yes ] || bad=$((bad+1))
done
kill $DPID $PEBBLE_PID 2>/dev/null; wait $DPID $PEBBLE_PID 2>/dev/null
echo "crash: $KILLS kill -9s, $total_acked acknowledged commits, $bad invariant violations"
exit $bad
