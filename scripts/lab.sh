# Shared lab setup: keys, signed license, bootstrap config, Pebble, daemon start.
# Sourced after env.sh with BIN and RUN set; leaves us in $RUN.
rm -rf "$RUN"; mkdir -p "$RUN"; cd "$RUN"
# ---------- keys, license, bootstrap
ssh-keygen -q -t ed25519 -N '' -f admin_key
ssh-keygen -q -t ed25519 -N '' -f bob_key
ssh-keygen -q -t ed25519 -N '' -f evil_key
"$BIN/fw-license" keygen vendor.key vendor.pub
"$BIN/fw-license" issue vendor.key --id L-E2E --customer E2E --device e2e-device --features url-filtering --days 30 --grace 7 > license.lic
ADMIN_TOKEN=$(openssl rand -hex 16); BOB_TOKEN=$(openssl rand -hex 16)
sha() { printf %s "$1" | sha256sum | cut -d' ' -f1; }
cat > boot.conf <<EOF
set system hostname fw-e2e
set system login user admin role admin
set system login user admin ssh-key "$(cut -d' ' -f1,2 admin_key.pub)"
set system login user admin api-token-sha256 $(sha "$ADMIN_TOKEN")
set system login user bob role viewer
set system login user bob ssh-key "$(cut -d' ' -f1,2 bob_key.pub)"
set system login user bob api-token-sha256 $(sha "$BOB_TOKEN")
set system services ssh port 2222
set system services https port 8443
set system certificate common-name localhost
set system certificate acme-directory https://localhost:14000/dir
set system certificate renew-before 240
set system certificate alert-days 1
set firewall rule 10 action accept
EOF

# ---------- Pebble (5-minute certificates so renewal is observable)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 -keyout pebble.key -out pebble.crt 2>/dev/null
cat > pebble.json <<EOF
{"pebble":{"listenAddress":"127.0.0.1:14000","managementListenAddress":"127.0.0.1:15000",
 "certificate":"$RUN/pebble.crt","privateKey":"$RUN/pebble.key","httpPort":5002,"tlsPort":5001,
 "ocspResponderURL":"","externalAccountBindingRequired":false,
 "profiles":{"default":{"description":"short","validityPeriod":300}}}}
EOF
PEBBLE_VA_NOSLEEP=1 "$PEBBLE" -config pebble.json > pebble.log 2>&1 &
PEBBLE_PID=$!
for i in $(seq 50); do curl -s --cacert pebble.crt https://localhost:14000/dir >/dev/null && break; sleep 0.2; done
curl -s --cacert pebble.crt https://localhost:15000/roots/0 > pebble-root.pem
curl -s --cacert pebble.crt https://localhost:15000/intermediates/0 > pebble-int.pem
cat pebble-root.pem > trust.pem

# ---------- daemon
# each start gets its own daemon.N.out so sanitizer reports printed at exit survive restarts
start_daemon() {
  local i
  DSTART=$(( ${DSTART:-0} + 1 )); DOUT=daemon.$DSTART.out
  "$BIN/fw-mgmtd" --state "$RUN/state" --bootstrap boot.conf --license license.lic --vendor-pubkey vendor.pub \
    --acme-ca pebble.crt --device-id e2e-device > "$DOUT" 2>&1 &
  DPID=$!
  for i in $(seq 100); do grep -q ready "$DOUT" && return 0; sleep 0.1; done
  return 1
}
