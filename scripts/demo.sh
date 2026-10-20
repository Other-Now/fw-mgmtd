#!/usr/bin/env bash
# demo.sh -> docs/demo-session.txt : a real session transcript for the README.
set -uo pipefail
SCRIPTS=$(cd "$(dirname "$0")" && pwd)
. "$SCRIPTS/env.sh"
BIN=${BIN:-$BUILD/release}
RUN=${RUN:-$HOME/fwm-run/demo}
. "$SCRIPTS/lab.sh"
start_daemon || exit 1
SSH="ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
A="$SSH -i admin_key admin@127.0.0.1"
OUTF=$SRC/docs/demo-session.txt
run() { echo "\$ ssh admin@fw '$1'"; $A "$1"; echo; }
{
  run "show configuration"
  run "configure; set firewall rule 20 action drop; set firewall rule 20 source 203.0.113.0/24; set firewall rule 20 protocol tcp; set firewall rule 20 port 23; compare; commit comment \"block telnet from TEST-NET-3\""
  run "configure; set firewall rule 30 source 198.51.100.0/24; commit"
  run "configure; set system services ssh port 0"
  run "configure; set system hostname edge-02; commit confirmed 2"
  sleep 3.5
  run "show commits"
  run "show configuration system hostname"
  run "request certificate renew"
  run "show certificate"
  run "show license"
  echo "\$ ssh bob@fw 'configure'      # bob is a viewer"
  $SSH -i bob_key bob@127.0.0.1 'configure'; echo
  echo "--- interactive shell with a pty: typed 'sh<TAB>co<TAB>', 'n<TAB>', 'fi<TAB>', '?', 'r<TAB>', Enter ---"
  (sleep 0.5; printf 'sh\tco\t'; sleep 0.3; printf 'n\t'; sleep 0.3; printf 'fi\t'; sleep 0.3; printf '?'; sleep 0.3; printf 'r\t\r'; sleep 0.3; printf 'exit\r'; sleep 0.3) \
    | $SSH -tt -i admin_key admin@127.0.0.1 2>/dev/null | tr -d '\r' | sed 's/\x1b\[K//g'
  echo
  echo "--- the same change through the REST API ---"
  base=$(curl -s --cacert trust.pem -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:8443/api/v1/config | python3 -c 'import sys,json;print(json.load(sys.stdin)["commit"])')
  echo "\$ curl -X POST https://fw:8443/api/v1/config -d '{\"base\":$base,\"set\":[\"firewall rule 40 action reject\"]}'"
  curl -s --cacert trust.pem -H "Authorization: Bearer $ADMIN_TOKEN" -d "{\"base\":$base,\"set\":[\"firewall rule 40 action reject\"],\"comment\":\"via api\"}" https://localhost:8443/api/v1/config
  echo "\$ (same request again, stale base)"
  curl -s --cacert trust.pem -H "Authorization: Bearer $ADMIN_TOKEN" -d "{\"base\":$base,\"set\":[\"firewall rule 40 action reject\"]}" https://localhost:8443/api/v1/config
  echo
  echo "--- audit trail (RFC 5424, state/fw-mgmtd.log) ---"
  grep -E "COMMIT|CONFIRM_REVERT|AUTHZ_DENY|CERT_RENEWED" state/fw-mgmtd.log | head -12
} > "$OUTF" 2>&1
kill $DPID $PEBBLE_PID 2>/dev/null; wait $DPID $PEBBLE_PID 2>/dev/null
echo "wrote $OUTF"
