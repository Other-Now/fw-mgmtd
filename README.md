# fw-mgmtd — a firewall management-plane daemon

One C++20 Linux daemon that does what a firewall's management plane does —
transactional configuration, a CLI over SSH, a REST API, an audit trail,
certificate lifecycle and license enforcement — kept small enough
(~3,700 lines in `src/`) to explain end to end.

```
           ssh (libssh, pubkey)            https (OpenSSL 3, hot-reloadable SSL_CTX)
                 │                                     │
          ┌──────▼──────┐                       ┌──────▼──────┐
          │ line editor │  TAB / ? / history    │  REST API   │  bearer token -> user
          └──────┬──────┘                       └──────┬──────┘
                 └──────────► CliSession / RBAC ◄──────┘   same command table, same roles
                                     │
                       parse_path() — the typed schema (one parser for CLI, API, disk)
                                     │
                 ┌───────────────────▼────────────────────┐
                 │ ConfigStore: candidate -> validate ->   │  commit / rollback N /
                 │ atomic_write(commits/<id>.conf) ->      │  commit confirmed (survives restart)
                 │ notify subscribers                      │  optimistic concurrency (base id)
                 └───┬─────────┬─────────┬─────────┬──────┘
                 syslog     https      ssh      firewall  certificate   <- services apply changes live
                 (UDP)    (rebind)  (rebind)  (recompile)  (ACME)
     RFC 5424 audit log ◄── every commit, every change (old/new), every denied command
     LicenseManager: Ed25519 (EVP_DigestVerify), expiry + grace, device binding, clock-rollback guard
```

## What is in it

| Area | What it does |
|---|---|
| **Config framework** | A typed schema tree (uint ranges, IPv4, CIDR, enums, names) is the single parser for `set`, completion, the API and files on disk. Each session gets a private candidate. `commit` / `commit check` / `commit confirmed <s>` / `rollback N` (50 kept) / `compare` / `update` (rebase). Cross-field validation includes lockout protection: a commit is refused if no admin with an SSH key would remain. Every commit is an immutable file written temp → `fsync` → `rename` → `fsync(dir)`. A pending commit-confirmed is persisted too, so it still reverts after a crash. Services subscribe by path prefix, can veto in `validate()`, and apply live in `apply()`. |
| **CLI over SSH** | Embedded libssh server with public-key auth only, against keys in the running config. It has operational (`>`) and configuration (`#`) modes and a hierarchical `show` (braces, or `\| display set`). Other features: `\| match`, unique-prefix abbreviations (`sh conf`), TAB completion and `?` help driven by the schema and the existing list keys, history, and Ctrl-C/U/D. Exec mode works too (`ssh fw 'configure; set …; commit'`). |
| **RBAC** | Three roles: viewer, operator and admin. Each command declares its minimum role. The role is looked up in the *running* config on every command, so a demotion applies to open sessions immediately. Denials go to the audit log. Secrets are masked for non-admins and in tech-support. |
| **REST API** | HTTPS on the same store: `GET /api/v1/config`, `POST /api/v1/config` (set/delete lists + `base` or `If-Match`; a stale base returns 409), `/confirm`, `/rollback`, `/commits`, and `POST /api/v1/cli`. That last one runs operational commands through the same `CliSession`, so the CLI and the API cannot disagree. Tokens are stored as SHA-256 and compared with `CRYPTO_memcmp`. |
| **Logging / diagnostics** | RFC 5424 to a file, a UDP collector and an in-memory ring. The `[audit@32473 …]` structured data records user, interface, commit id, and each changed key with its old and new value. `show diagnostics` covers RSS, fds, threads, disk, listeners, cert and license. `show tech-support` bundles all of it with secrets masked. |
| **Certificates (OpenSSL 3)** | EC P-256 keygen, CSR with SAN, and an RFC 8555 ACME client: JWS ES256, nonces with badNonce and transport retry, an http-01 responder, polling, finalize and download. Tested against **Pebble**. The new cert is hot-swapped into the listener without a restart, renewed automatically before expiry, and alerts fire once per day-bucket inside `alert-days`. OCSP (nonce, signature, validity window) and CRL (signature, serial, staleness) checks are built on OpenSSL's APIs. |
| **License** | Ed25519-signed key=value file, verified with `EVP_DigestVerify` (no custom crypto). It carries feature flags, expiry plus a grace period, device binding, and a persisted clock high-water mark against clock rollback. An unlicensed feature can't be *configured*, but existing config only warns, so an expired license never blocks unrelated commits. |
| **Security testing** | libFuzzer targets for the CLI, the config parser (round-trip property), the license parser (including a sign-and-verify property) and the HTTP head parser. There are ASan+UBSan builds of the tests and of the daemon under e2e, and a hardened release build verified by `scripts/hardening.sh`. |

## Results

**Local machine:** i5-9300H, WSL2, ext4 virtual disk, 4 vCPU (`results/local/`). The same scripts run in CI on GitHub's ubuntu-24.04 runner (`results/ci/` and the job summary). Latencies are p50 unless noted.

| Measurement | Result |
|---|---|
| Commit, 1 change on a 100 / 1k / 10k-leaf config | **3.6 / 4.4 / 12.0 ms**. `fsync` is 95% of it at 100 leaves; validate+diff is 36 µs / 0.32 ms / 3.5 ms. |
| Rollback 1 (load commit N-1, then commit) | **3.7 / 5.4 / 20.8 ms** |
| CLI over SSH, in an open session | `show …` **0.13–0.14 ms**, `set` **0.12 ms**, `commit` **3.7 ms** (fsync) |
| CLI over SSH, one-shot `ssh fw 'show license'` | **47 ms** (TCP + kex + pubkey auth + exec + close) |
| Certificate renewal under load (60 s, 4 threads, new TLS connection per request, ACME renewal every 2 s) | **0 failed of 77,855** new connections, **0 failed of 50,438** keep-alive requests, **24/24** renewals, 24 distinct server certs observed. Three more 60 s runs: 0 failures in 242k connections. |
| ACME issuance from Pebble (keygen → order → http-01 → finalize → download) | **0.52–0.61 s** per certificate. Via the API under churn it takes 2.5 s, which includes the 2 s activation gate below. |
| Crash test: `kill -9` during a stream of API commits, 20 times | **1,500 acknowledged commits, 0 lost, 0 torn**. In 9/20 kills the in-flight commit landed unacknowledged, which the `base` check makes safe to retry. |
| End-to-end (`scripts/e2e.sh`) | 34/34 checks against real OpenSSH, curl and Pebble; also 34/34 with the daemon built under ASan+UBSan, 0 sanitizer reports |
| OCSP + CRL (`scripts/revocation.sh`) | good → good, revoked → revoked by both methods; a CRL signed by an impostor CA with the same name → rejected |
| Fuzzing (ASan+UBSan) | FUZZ_SUMMARY |
| Unit tests | 30 tests, 245 checks |

## Things the measurements caught

1. **"Zero dropped connections" was false at first: 38–537 handshakes failed per 60 s run.** Diagnostics in the client's verify callback showed `certificate is not yet valid: notBefore=04:20:20 client-now=04:20:19`. Pebble stamps `notBefore = time.Now()` with no backdating, and a cert swapped in the instant it is issued is briefly in the future for clients. The manager now keeps serving the still-valid old cert until `notBefore + 2 s`. Result: 0 failures in 4 × 60 s runs (≈320k connections). Production CAs backdate (Let's Encrypt by 1 h, step-ca by 1 min) for exactly this reason.
2. **Trivial SSH commands took 44 ms.** `set` (prompt only) took 0.3 ms, but `show` (output followed by prompt: two small writes) took 44 ms. That is Nagle holding the second write until the client's delayed ACK. With `TCP_NODELAY` on the accepted socket, `show` dropped from 44.0 ms to **0.14 ms**, commit from 51 ms to 3.7 ms, and one-shot exec from 132 ms to 47 ms.
3. **Validation re-parsed the whole config on every commit.** At 10k leaves, validate+diff was 10.4 ms for a one-leaf change, because every key went through the schema walk twice: once for the schema check and once to find license features. Now only the diff is schema-checked (running config is already valid) and licensed subtrees are precomputed prefixes. 10.4 ms became **3.5 ms**.
4. **The fuzzer found a hang in 1,801 executions.** In `parse_license_body`, a last line with no trailing `\n` made `pos = npos + 1 == 0` and restarted the loop forever (reproducer: the 1-byte input `#`). It was unreachable through the verify path today, which always passes a body ending in `\n`, but it was one refactor away. Fixed, with a regression test and `fuzz/regressions/`.
5. **A malformed ACME response could kill the daemon.** An nlohmann `type_error` from a transport-error body escaped the timer thread, and `std::terminate` raised SIGABRT, which WSL captured. ACME is now wrapped and transport errors retried, the timer loop catches per tick, and both servers `shutdown()` live sockets on stop so no detached thread outlives the objects it uses.

## Run it

```bash
bash scripts/deps.sh        # no-sudo deps: libssh-dev + clang fuzzer runtime (.deb unpack), Pebble v2.7.0
bash scripts/build.sh       # hardened release -> ~/fwm-build/release
~/fwm-build/release/unit_tests
bash scripts/e2e.sh         # Pebble + daemon + OpenSSH + curl, prints PASS/FAIL
bash scripts/revocation.sh  # OCSP responder + CRL against a throwaway OpenSSL CA
bash scripts/crash.sh 20    # kill -9 durability test
bash scripts/bench.sh local # numbers in results/local/
bash scripts/fuzz.sh 600    # libFuzzer, seconds per target
bash scripts/demo.sh        # regenerates docs/demo-session.txt
```

`docs/demo-session.txt` is a real transcript: commit, a failed validation, commit-confirmed reverting by itself, ACME renewal, RBAC denial, TAB/`?` in a pty, the same change via the API and a stale-base 409, and the resulting RFC 5424 audit lines.

## Layout

```
src/schema.*      typed schema tree, parse_path(), completion
src/config.*      flat config map, tokenizer, set-lines / braces rendering, diff
src/store.*       ConfigStore: commit, rollback, commit-confirmed, subscribers, validation
src/cli.*         CliSession: modes, command table + RBAC, pipes, completion; LicenseManager
src/lineedit.*    terminal line editor (TAB, ?, history) — pure, unit-tested
src/ssh_server.*  libssh server: pubkey auth, pty/shell/exec, live port rebind
src/http.*        HTTP/1.1 server (swappable SSL_CTX) + client
src/api.*         REST routes + https/syslog/firewall subscribers
src/certmgr.*     keygen, CSR, ACME, install/hot-reload, renewal, alerts, OCSP, CRL
src/license.*     Ed25519 license verify, policy (grace, device, clock), ClockGuard
src/syslog.*      RFC 5424 formatter + sinks
tools/            fw-license (vendor signing tool), fwbench (every number above)
tests/ fuzz/ scripts/ results/ docs/NOTES.md (design notes / interview walkthrough)
```

## Not built (deliberately, or not yet)

- **Stretch goals not done:** SAML 2.0 SP login, URL categorization over NFQUEUE, and an SNMP AgentX subagent.
- **ACME:** tested against Pebble only, not step-ca. http-01 only (no dns-01 or tls-alpn-01). Pebble has no OCSP responder, so OCSP/CRL are exercised against an `openssl ocsp` responder and a CRL from a throwaway CA.
- **No real dataplane.** The firewall service just counts and "recompiles" rules to show live apply.
- **Single node.** No HA config sync. The REST API is HTTP/1.1, thread-per-connection, with Content-Length bodies only.
- **Fixed roles:** three, not per-path ACLs. Passwords and TACACS/RADIUS are not supported (pubkey and bearer token only).
- **Local numbers are WSL2:** the fsync cost is a virtual disk's. Compare with the CI numbers before quoting.
