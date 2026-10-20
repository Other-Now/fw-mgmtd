#!/usr/bin/env bash
# OCSP + CRL checks against a throwaway OpenSSL CA (Pebble has no OCSP responder).
#   good.crt     -> OCSP good,    CRL good
#   revoked.crt  -> OCSP revoked, CRL revoked
#   forged.crt   -> CRL signed by an impostor CA -> rejected (signature)
set -uo pipefail
. "$(dirname "$0")/env.sh"
BIN=${BIN:-$BUILD/release}
RUN=${RUN:-$HOME/fwm-run/revocation}
rm -rf "$RUN"; mkdir -p "$RUN/ca" "$RUN/www"; cd "$RUN"
FAILS=0
expect() { if grep -q -- "$2" <<<"$3"; then echo "PASS  $1"; else echo "FAIL  $1: $3"; FAILS=$((FAILS+1)); fi; }

cat > ca.cnf <<'EOF'
[ca]
default_ca = CA
[CA]
dir = ./ca
database = $dir/index.txt
new_certs_dir = $dir
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 30
default_crl_days = 1
policy = any
copy_extensions = none
[any]
commonName = supplied
[leaf]
basicConstraints = CA:FALSE
authorityInfoAccess = OCSP;URI:http://127.0.0.1:8888
crlDistributionPoints = URI:http://127.0.0.1:8889/ca.crl
[leaf_forged]
basicConstraints = CA:FALSE
crlDistributionPoints = URI:http://127.0.0.1:8889/forged.crl
EOF
touch ca/index.txt; echo 1000 > ca/serial; echo 01 > ca/crlnumber
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=fw-test-ca" -keyout ca.key -out ca.crt 2>/dev/null
for n in good revoked forged; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$n.test" -keyout $n.key -out $n.csr 2>/dev/null
  ext=leaf; [ $n = forged ] && ext=leaf_forged
  openssl ca -batch -config ca.cnf -cert ca.crt -keyfile ca.key -extensions $ext -in $n.csr -out $n.crt 2>/dev/null
done
openssl ca -config ca.cnf -cert ca.crt -keyfile ca.key -revoke revoked.crt -crl_reason keyCompromise 2>/dev/null
openssl ca -config ca.cnf -cert ca.crt -keyfile ca.key -gencrl -out ca.crl.pem 2>/dev/null
openssl crl -in ca.crl.pem -outform DER -out www/ca.crl
# impostor CA with the same subject name signs a CRL claiming nothing is revoked
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=fw-test-ca" -keyout evil.key -out evil.crt 2>/dev/null
mkdir -p evilca; touch evilca/index.txt; echo 01 > evilca/crlnumber
sed 's#dir = ./ca#dir = ./evilca#' ca.cnf > evil.cnf
openssl ca -config evil.cnf -cert evil.crt -keyfile evil.key -gencrl -out forged.crl.pem 2>/dev/null
openssl crl -in forged.crl.pem -outform DER -out www/forged.crl

(cd www && python3 -m http.server 8889 --bind 127.0.0.1 >/dev/null 2>&1) & WWW=$!
openssl ocsp -index ca/index.txt -port 8888 -rsigner ca.crt -rkey ca.key -CA ca.crt -ignore_err >ocsp.log 2>&1 & OCSP=$!
sleep 1

out=$("$BIN/fwbench" revcheck good.crt ca.crt);    echo "$out" > good.txt
expect "good cert: OCSP good" "ocsp: good" "$out"
expect "good cert: CRL good" "crl: good" "$out"
out=$("$BIN/fwbench" revcheck revoked.crt ca.crt); echo "$out" > revoked.txt
expect "revoked cert: OCSP revoked" "ocsp: revoked" "$out"
expect "revoked cert: CRL revoked" "crl: revoked" "$out"
out=$("$BIN/fwbench" revcheck forged.crt ca.crt);  echo "$out" > forged.txt
expect "impostor-signed CRL rejected" "does not verify" "$out"

kill $WWW $OCSP 2>/dev/null
echo "revocation: $FAILS failures"
exit $FAILS
