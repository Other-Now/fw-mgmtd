# fw-mgmtd: design notes and interview walkthrough

Read this top to bottom once; each section is "what it does → why → what I'd
say if pushed". Numbers are from `results/local/` unless marked CI.

---

## 1. The one-sentence pitch

A firewall management plane in one C++20 daemon: a typed, transactional config
store (commit / rollback / commit-confirmed, crash-safe), served by an SSH CLI
and a REST API that share one parser and one commit path, plus the
certificate (ACME, OCSP/CRL) and license (Ed25519) lifecycles a real
appliance needs — with every claim backed by a script that prints PASS/FAIL or
a number.

## 2. Config model — why a flat map

`Config = std::map<std::string, std::string>`, key = path tokens
(`"firewall rule 10 action"`), value = leaf value.

- **Diff is a sorted merge** — O(N), no tree walking (`config.cpp: diff`).
- **Delete subtree** = erase keys with that prefix *plus a space boundary*
  (`key_in_subtree`): deleting `rule 1` must not delete `rule 10`. There's a
  unit test for exactly that.
- **On-disk format = `set` lines**, i.e. the same text the CLI accepts. The
  loader is `parse_config` → `config_set` → `parse_path`; there's no second
  parser to drift.
- The braces view is just a rendering (`to_hierarchical`), where a list keyword
  absorbs its key (`rule 10 { … }`).

**Schema** (`schema.cpp`): a tree of Container / List / Leaf nodes with types
(UInt with range, IPv4, CIDR, Enum, Name, Hex64, String), `secret` and
`feature` flags. `parse_path(tokens, want_value)` is the only gate, and
`complete_path` walks the same tree for TAB completion. That is why CLI, API
and disk can't disagree: they literally call the same function.

*If asked "why not YANG/protobuf?"* — same idea (schema-driven), but YANG +
libyang would be a week of setup. I'd keep the shape: a schema tree, a
path parser, a flat datastore, and validation in two layers (type/range per leaf
in the schema, cross-field rules at commit).

## 3. Transactions

**Commit pipeline** (`store.cpp: commit_locked`):
1. `base_id != running_id` → refuse (optimistic concurrency). Each session
   edits a *private* candidate copied at `configure`; if someone committed in
   between, you get "changed by another session" and can `update` (re-apply
   your own diff onto the new running config).
2. `diff(running, candidate)`.
3. `validate`: schema check of *changed* keys only, licensing, cross-field rules
   (rule needs action; ssh ≠ https port; **lockout protection**: at least one admin
   with an ssh-key must survive).
4. Subscriber `validate()` for services whose prefix the diff touches. Any of
   them can veto (e.g. SSH probes that the new port is bindable *before* the commit
   is accepted, so a typo can't cut you off).
5. **Durability point:** `atomic_write(commits/<id>.conf)`: write tmp →
   `fsync(tmp)` → `rename` → `fsync(dir)`.
6. Swap `running_` under a `shared_mutex`; persist/clear `confirm-pending`.
7. Subscribers `apply()`, *after* the commit is durable. If we crash between
   5 and 7, startup's `apply_all()` pushes the running config anyway.
8. Prune beyond 50 commits; audit log.

**Why one file per commit instead of `running.conf` + `rollback.N` files?**
Rotating rollback.0→1→2 is a multi-file update with crash windows. Immutable
numbered files make every step a single atomic rename; "rollback N" is "load
`history_[N]`", and startup just picks the highest id that parses. Leftover
`.tmp` files (crash mid-write) are deleted at open; a unit test plants one.

**Why fsync the directory?** `rename` changes the directory entry; without
`fsync(dirfd)` the data can be durable while the name still points at the
old inode after power loss.

**Commit confirmed** (`commit confirmed 60`): commit goes live, a
`confirm-pending` file records `{commit, revert_to, deadline}`. The timer
thread's `tick()` reverts by committing the `revert_to` config as a *new*
commit (history stays append-only, the revert is auditable). A plain `commit`
(even with no changes) confirms. Because the pending state is a file, **a crash
during the window still reverts on restart** — that's the whole point of the
feature (you just locked yourself out; the box must undo it even if it
rebooted). Unit test: `store_pending_confirm_survives_restart`.

**Crash test** (`scripts/crash.sh`): client streams API commits; `kill -9` at a
random time; restart; check (1) store opens, (2) running id ≥ last *acked*
id (acked ⇒ durable), (3) ≤ acked + 1, (4) content matches id. 20 kills,
1,500 acked commits, 0 violations; 9/20 times the in-flight commit landed
without an ack — the classic "maybe committed". The client handles it safely
because its retry carries the old `base` and gets a 409 instead of applying
twice. That's the answer to "what about exactly-once?": the base id is an
idempotency/precondition key (like HTTP `If-Match`).

**Cost model** (`results/local/commit.txt`):

| leaves | total | validate+diff | persist |
|---|---|---|---|
| 100 | 3.6 ms | 36 µs | 3.5 ms |
| 1k | 4.4 ms | 0.32 ms | 4.1 ms |
| 10k | 12.0 ms | 3.5 ms | 8.4 ms |

fsync dominates small configs. At 10k the remaining validate cost is the O(N)
diff and cross-field scan, and persist rewrites 368 KB. Next steps if it mattered: write a
delta/journal instead of the full file, and keep cross-field indexes
incrementally. Rollback at 10k (20.8 ms) is dominated by re-parsing the
old file through the schema.

## 4. CLI over SSH

- **libssh server, message API.** We own the TCP listener and hand each accepted
  fd to `ssh_bind_accept_fd`, which lets us rebind on a port change (subscriber)
  and `shutdown()` live sockets on stop.
- **Auth:** public key only. libssh calls us twice per key: state NONE ("would
  you accept this key?") → `reply_pk_ok`; state VALID (signature verified) →
  success. The key is compared with `ssh_key_cmp` against
  `system login user X ssh-key` **in the running config at login time**.
  6 attempts max; failures are audit-logged with the source IP.
- **Shell vs exec:** a PTY gets the line editor with echo; a non-PTY shell gets
  no echo (the bench uses this); exec runs `;`-separated commands in one
  session and returns exit status 1 if any said `error:`.
- **Line editor** (`lineedit.cpp`) is pure bytes-in/bytes-out: TAB (unique →
  complete + space; ambiguous → extend to the longest common prefix, else list),
  `?` (list with placeholders like `<number>`), history via ESC[A/B, CRLF
  collapsing, Ctrl-C/U/D. Unit-tested without a terminal.
- **Abbreviations** (`sh conf`) are resolved against the command table by unique
  prefix; config paths are *not* abbreviated (ambiguity with list keys).
- **RBAC:** each command carries a minimum role; role = lookup in the running
  config **per command**, so demoting someone affects their open session
  (test: `cli_demotion_takes_effect_immediately`, which kicks them out of
  configure mode). Completion is role-filtered too.

**Finding: TCP_NODELAY.** `show` took 44 ms while `set` took 0.3 ms. The
difference: `show` writes output, then the prompt — two small writes. Nagle
holds the second until the first is ACKed, and the client delays its ACK
(~40 ms). `set` only writes the prompt. After setting TCP_NODELAY on the accepted
socket: 0.14 ms. Interactive protocols (OpenSSH included) set it for this
reason.

## 5. REST API

- Same `ConfigStore::commit`; same `config_set`/`config_delete`; operational
  commands via `POST /api/v1/cli` run through a `CliSession` with the same RBAC.
  e2e checks CLI→API and API→CLI visibility both ways.
- `POST /api/v1/config` *requires* `base` (or `If-Match`), else 428. Stale → 409.
- Tokens: config stores only `sha256(token)`; compare with `CRYPTO_memcmp`
  (constant time) across all users.
- Server hardening: duplicate `Content-Length` rejected and `Transfer-Encoding`
  refused (the request-smuggling ambiguity), 1 MiB body cap, 64 header cap, and
  30 s read timeout. Fuzzed (`fuzz_http`).

## 6. Certificates

- **Key/CSR:** `EVP_PKEY_Q_keygen(EC P-256)`, `X509_REQ` with a SAN extension,
  signed SHA-256. Fresh key per certificate.
- **ACME (RFC 8555)** in ~150 lines (`acme_issue_impl`): directory → newNonce →
  newAccount (JWS with `jwk`) → newOrder (JWS with `kid`) → for each authz,
  serve `token.thumbprint` on `/.well-known/acme-challenge/` (port 5002), POST
  the challenge, poll → finalize with the DER CSR → poll the order → download the chain.
  - ES256 JWS: OpenSSL gives a DER `ECDSA-Sig-Value`; JWS wants raw `r||s`
    (32+32 bytes) → `d2i_ECDSA_SIG` + `BN_bn2binpad`.
  - JWK thumbprint (RFC 7638) needs lexicographic member order and no
    whitespace; nlohmann's `dump()` sorts keys, which is why it works.
  - `badNonce` → retry with the new nonce (Pebble rejects ~5% on purpose);
    transport error → clear the nonce, back off, retry.
- **Hot reload:** `HttpServer` holds a `shared_ptr<SSL_CTX>`. Each accepted
  connection captures the current one; `set_ctx()` swaps it under a mutex.
  `SSL_new` takes its own reference, so in-flight connections are unaffected
  and new handshakes get the new cert. No restart, no listener close.
- **The notBefore finding:** under churn (renew every 2 s, 4 threads making new
  connections), 38–537 handshakes per 60 s run failed with
  `certificate is not yet valid`, notBefore one second after the client's clock.
  Pebble sets `NotBefore: time.Now()` without backdating. Fix: `install()` waits
  until `notBefore + 2 s` before swapping (the old cert is still valid); refuse
  if the CA is > 30 s ahead. After: 0 failures in ≈320k connections over
  4 runs. It's also why Let's Encrypt backdates by an hour.
- **Renewal policy:** timer every 2 s → `left < renew-before` → renew. Bench
  config: 300 s certs, renew-before 240 s, so it auto-renews about once a minute
  (`results/local/certificate.txt` shows timer-triggered renewals).
  A failed renewal keeps the old cert and retries on the next tick.
- **Alerts:** inside `alert-days`, one syslog alert per remaining-days bucket
  (Warning; Crit under 24 h), reset on install.
- **OCSP:** build the request with a **nonce** (`OCSP_request_add1_nonce`), POST
  it, then check the response status, `OCSP_check_nonce` (replay), `OCSP_basic_verify`
  against the issuer, `OCSP_resp_find_status`, and `OCSP_check_validity` with
  300 s skew.
- **CRL:** CDP URIs from the cert, fetch DER or PEM, `X509_CRL_verify` with the
  *issuer's key* (an impostor CA with the same subject name is rejected; the test does exactly
  this), `X509_CRL_get0_by_cert`, and a staleness warning on `nextUpdate`.
- Pebble has no OCSP responder, so `scripts/revocation.sh` builds a CA with
  `openssl ca`, revokes one cert, and runs `openssl ocsp` + a static CRL.

## 7. Licensing

- Format: `key=value` lines, then `signature=<base64 Ed25519>` over **every
  byte before the signature line**. Verify first, then parse (and parse
  strictly: unknown/duplicate fields rejected *even when signed*: a duplicate
  `expires=` must not be resolved "last wins").
- OpenSSL Ed25519 is "pure" EdDSA: `EVP_DigestVerifyInit(..., md=NULL, ...)`
  then one-shot `EVP_DigestVerify` (no streaming update).
- Policy is a **pure function** `evaluate_license(lic, now, device, clock_hwm)`,
  so every case is a unit test with fake clocks: valid → grace (features
  stay on) → expired (off); device mismatch; `*` site license; clock
  rollback; issued-in-the-future.
- **Clock rollback:** `ClockGuard` persists the highest time ever seen
  (`atomic_write`, at most once a minute). If `now + 300 s < hwm` → Invalid.
  While Invalid we don't advance the mark (a rolled-back clock can't lower it).
  Limitation: a device that was off when the clock was moved back, before it ever saw
  the later time, can't tell — you'd need a trusted time source (signed
  NTP/Roughtime) for that.
- Tamper test flips **every byte** of the signed body one at a time: 0 accepted.
- Enforcement: config validation refuses to *add/modify* keys under a licensed
  subtree (`firewall url-filter`) without the feature; existing licensed config
  only warns, so an expired license never blocks an unrelated emergency commit.

## 8. Logging

RFC 5424: `<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD-ID k="v" …] MSG`.
PRI = facility × 8 + severity (local0 = 16 → Notice = `<133>`). SD values
escape `"`, `\` and `]`. Header fields are NILVALUE `-` when empty and limited
to printable ASCII without spaces. One record per line (newlines in messages are flattened). An exact-string unit test covers it.

Audit events: COMMIT (user, via, id, change count, comment), CONFIG_CHANGE
per key (op, key, old, new; secrets masked; capped at 100 per commit),
COMMIT_CONFIRMED, CONFIRM_REVERT, AUTH_OK/AUTH_FAIL (src IP), AUTHZ_DENY
(role vs needed), CMD (every non-show command), CERT_*, LICENSE_STATE.

## 9. Security testing

- **libFuzzer** (`fuzz/`), all ASan+UBSan:
  - `fuzz_config`: parse → serialize → parse must be identity (catches
    quoting bugs, not just crashes).
  - `fuzz_license`: verify path on raw input, **plus** the body parser directly,
    because random bytes never carry a valid signature. Property: whatever the body
    parser accepts, once signed, must verify to the same license.
  - `fuzz_cli`: lines executed in one session (both modes, pipes,
    abbreviations, completion) and raw bytes through the line editor.
    `commit` is skipped to keep the fuzzer out of fsync.
  - `fuzz_http`: request head parser.
  - **Found:** the license body parser hang (`#` with no newline → `npos + 1 == 0`),
    1,801 execs in. Fixed + regression test + `fuzz/regressions/`.
- **Sanitizers:** unit tests, and the *daemon* under the whole e2e, built with
  `-fsanitize=address,undefined -fno-sanitize-recover`; LeakSanitizer at exit;
  0 reports.
- **Hardened build** (`-D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS
  -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -pie
  -z relro -z now -z noexecstack`), verified from the ELF by
  `scripts/hardening.sh`: PIE, full RELRO, NX, canary, fortified calls, CET
  IBT+SHSTK notes.

## 10. Robustness bugs found by running it

- **SIGABRT from the timer thread:** an uncaught `nlohmann::json::type_error` on a
  transport-error body → `std::terminate` (WSL's crash capture logged signal 6). Fix:
  ACME wrapped, transport errors retried, and the timer loop catches per tick. Lesson:
  any exception escaping a `std::thread` function is fatal.
- **Detached threads outliving `main`:** connection threads could still be
  inside the store while `main` destructs it. Both servers track live fds and
  `shutdown(SHUT_RDWR)` them on stop (wakes blocked reads), then wait for
  `active == 0`. The HTTP server also moved `close(fd)` into a single owner
  (a double close can close someone else's reused fd).
- **"Connection closed by remote host"** on every `ssh fw 'cmd'`: we tore down
  TCP right after CHANNEL_CLOSE. sshd waits for the client to hang up; we now
  pump `ssh_event_dopoll` until the client closes (≤ 1 s).

## 11. Likely questions

- *Why threads, not epoll?* A management plane sees tens of sessions; thread-per-
  connection keeps the code linear and debuggable. The dataplane is where you go
  event-driven/DPDK. If it mattered: a libssh `ssh_event` loop plus an epoll HTTP server.
- *How does the dataplane get the config?* Here `FirewallService::apply` stands in. In
  a real box: compile the rule set and push it atomically (generation number, so the
  dataplane swaps whole tables, never half a policy), ack back, and only then
  report the commit done (or roll back on a NACK). `validate()` is where a
  dataplane would reject something it can't program.
- *Two admins editing at once?* Private candidates + optimistic concurrency;
  `update` rebases. Alternative is `configure exclusive` (a lock with timeout).
- *Why is lockout protection a commit rule?* Because the CLI is the only way in;
  commit-confirmed is the second line of defense.
- *What would you add next?* SAML SP (xmlsec1, with signature-wrapping and replay
  tests), journaling instead of full-file commits, per-path RBAC, HA config
  sync (ship commit files + ids to the peer), and dns-01.

## 12. Numbers to remember

- Commit 3.6 ms at 100 leaves (fsync), 12 ms at 10k. Rollback 3.7 / 20.8 ms.
- SSH in-session `show` 0.14 ms (was 44 ms before TCP_NODELAY), commit 3.7 ms,
  one-shot 47 ms.
- Renewal under load: 0 / 77,855 new connections, 0 / 50,438 keep-alive, 24 renewals in
  60 s; ≈320k connections over 4 runs with 0 failures after the notBefore fix.
- ACME issuance from Pebble ≈ 0.5–0.6 s.
- Crash: 20 kill -9s, 1,500 acked, 0 lost/torn.
- Fuzz: see `results/fuzz/`; 1 real bug found (hang).
- e2e 34/34 (also under ASan), unit 30 tests / 245 checks, revocation 5/5.
