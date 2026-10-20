#!/usr/bin/env bash
# End-to-end: Pebble ACME CA + fw-mgmtd + real OpenSSH client + curl.
# Every check prints PASS/FAIL; exit status is the number of failures.
set -uo pipefail
. "$(dirname "$0")/env.sh"
BIN=${BIN:-$BUILD/release}
RUN=${RUN:-$HOME/fwm-run/e2e}
. "$(dirname "$0")/lab.sh"
FAILS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
has() { grep -q -- "$2" <<<"$1"; }

check "daemon starts" start_daemon
SSH="ssh -q -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
A="$SSH -i admin_key admin@127.0.0.1"
B="$SSH -i bob_key bob@127.0.0.1"
api() { curl -s --cacert trust.pem "$@"; }

# ---------- SSH + RBAC
out=$($A 'show license'); has "$out" "valid" && pass "ssh pubkey login + show license (valid)" || fail "show license: $out"
out=$($SSH -i evil_key admin@127.0.0.1 'show license' 2>&1); [ $? -ne 0 ] && pass "unknown key rejected" || fail "evil key accepted"
out=$($B 'configure'); has "$out" "permission denied" && pass "viewer cannot configure" || fail "viewer configure: $out"
out=$($B 'show configuration system login'); has "$out" "<masked>" && pass "viewer sees secrets masked" || fail "mask: $out"
out=$($A 'configure; set system hostname edge-01; commit comment "via ssh"')
has "$out" "commit complete" && pass "configure/set/commit over ssh exec" || fail "commit: $out"
out=$($A 'configure; set system services ssh port 99999'); has "$out" "out of range" && pass "schema rejects bad port" || fail "range: $out"
out=$($A 'configure; delete system login user admin ssh-key; commit')
has "$out" "lock out" && pass "lockout protection" || fail "lockout: $out"
# interactive shell with a pty: TAB completion and '?' help
out=$( (sleep 0.5; printf 'sh\tconf\tsys\thost\t\r'; sleep 0.5; printf 'show c?'; sleep 0.3; printf '\x15exit\r'; sleep 0.3) | $SSH -tt -i admin_key admin@127.0.0.1 2>/dev/null | tr -d '\r')
has "$out" "hostname edge-01;" && pass "TAB completion: 'sh<TAB>conf<TAB>sys<TAB>host<TAB>' ran" || fail "tab: $out"
has "$out" "commits" && has "$out" "certificate" && pass "'?' lists completions" || fail "help: $out"

# ---------- REST API agrees with the CLI
# the listener still has the self-signed cert until ACME runs, so use -k only for this first call
out=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:8443/api/v1/config)
has "$out" '"system hostname":"edge-01"' && pass "API sees the CLI commit" || fail "api read: $out"
code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost:8443/api/v1/config); [ "$code" = 401 ] && pass "API needs a token" || fail "api 401: $code"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $BOB_TOKEN" -d '{"base":1,"set":["system hostname x"]}' https://localhost:8443/api/v1/config)
[ "$code" = 403 ] && pass "API RBAC: viewer cannot write" || fail "api 403: $code"
base=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://localhost:8443/api/v1/config | python3 -c 'import sys,json;print(json.load(sys.stdin)["commit"])')
out=$(curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" -d "{\"base\":$base,\"set\":[\"firewall rule 20 action drop\"],\"comment\":\"via api\"}" https://localhost:8443/api/v1/config)
has "$out" '"commit"' && pass "API commit" || fail "api commit: $out"
out=$($A 'show configuration firewall | display set'); has "$out" "rule 20 action drop" && pass "CLI sees the API commit" || fail "cli read: $out"
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN_TOKEN" -d "{\"base\":$base,\"set\":[\"system hostname stale\"]}" https://localhost:8443/api/v1/config)
[ "$code" = 409 ] && pass "stale base -> 409" || fail "409: $code"

# ---------- licensing gates config
out=$($A 'configure; set firewall url-filter enable true; commit'); has "$out" "commit complete" && pass "licensed feature configurable" || fail "lic feature: $out"

# ---------- commit confirmed auto-revert
$A 'configure; set firewall rule 99 action drop; commit confirmed 3' | grep -q "rolled back in 3s" && pass "commit confirmed accepted" || fail "commit confirmed"
out=$($A 'show configuration firewall | display set'); has "$out" "rule 99" && pass "rule 99 live during confirm window" || fail "rule99 live"
sleep 4.5
out=$($A 'show configuration firewall | display set'); ! has "$out" "rule 99" && pass "unconfirmed commit auto-reverted" || fail "no revert: $out"
out=$($A 'show log 200'); has "$out" "CONFIRM_REVERT" && pass "revert is in the audit log" || fail "revert log"
$A 'configure; set firewall rule 98 action drop; commit confirmed 3' >/dev/null
$A 'configure; commit' >/dev/null; sleep 4
out=$($A 'show configuration firewall | display set'); has "$out" "rule 98" && pass "confirmed commit kept" || fail "confirm kept"

# ---------- ACME issuance from Pebble + hot reload
out=$($A 'request certificate renew'); has "$out" "renewed" && pass "ACME issuance from Pebble: $out" || fail "acme: $out $(tail -3 pebble.log)"
out=$($A 'show certificate'); has "$out" "Pebble Intermediate" && pass "listener now serves the Pebble-issued cert" || fail "issuer: $out"
code=$(api -o /dev/null -w '%{http_code}' https://localhost:8443/api/v1/health); [ "$code" = 200 ] && pass "curl verifies the chain against Pebble's root" || fail "verify: $code"

# ---------- live port change without restart
out=$($A 'configure; set system services https port 8444; commit'); sleep 0.3
code=$(api -o /dev/null -w '%{http_code}' https://localhost:8444/api/v1/health); [ "$code" = 200 ] && pass "https moved to 8444 without restart" || fail "rebind: $code"
code=$(api -o /dev/null -w '%{http_code}' https://localhost:8443/api/v1/health); [ "$code" = 000 ] && pass "8443 closed" || fail "old port: $code"
$A 'configure; set system services https port 8443; commit' >/dev/null; sleep 0.3

# ---------- remote syslog: audit trail over UDP
python3 -c '
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",5514)); s.settimeout(5)
with open("syslog.rx","w") as f:
  try:
    while True: f.write(s.recv(4096).decode()+"\n"); f.flush()
  except Exception: pass' &
RX=$!; sleep 0.3
$A 'configure; set system syslog server 127.0.0.1; set system syslog port 5514; commit' >/dev/null
$A 'configure; set system hostname edge-02; commit comment "syslog test"' >/dev/null
sleep 0.5; kill $RX 2>/dev/null
grep -q 'audit@32473 user="admin" commit=' syslog.rx && pass "RFC 5424 audit record received over UDP" || fail "syslog rx"
grep -q 'key="system hostname" old="edge-01" new="edge-02"' syslog.rx && pass "audit says who changed what (old/new)" || fail "audit diff"
head -c 300 syslog.rx > syslog-sample.txt

# ---------- diagnostics / tech-support
out=$($A 'show tech-support'); has "$out" "==== show diagnostics" && ! has "$out" "$(sha "$ADMIN_TOKEN")" && pass "tech-support bundles everything, token hash masked" || fail "tech-support"
out=$($B 'show tech-support'); has "$out" "permission denied" && pass "tech-support admin-only" || fail "tech-support rbac"

# ---------- restart keeps everything
kill $DPID; wait $DPID 2>/dev/null
check "daemon restarts" start_daemon
out=$($A 'show configuration system hostname'); has "$out" "edge-02" && pass "running config survives restart" || fail "persist: $out"
out=$($A 'show certificate'); has "$out" "Pebble" && pass "ACME cert survives restart" || fail "cert persist"

kill $DPID 2>/dev/null; wait $DPID 2>/dev/null
kill $PEBBLE_PID 2>/dev/null
cp state/fw-mgmtd.log daemon-syslog.log 2>/dev/null
echo "e2e: $FAILS failures"
exit $FAILS
