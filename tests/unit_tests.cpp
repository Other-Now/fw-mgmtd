// Unit tests. Tiny harness on purpose: no dependency to install.
#include <openssl/x509.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <nlohmann/json.hpp>
#include <thread>

#include "api.hpp"
#include "certmgr.hpp"
#include "cli.hpp"
#include "config.hpp"
#include "http.hpp"
#include "license.hpp"
#include "lineedit.hpp"
#include "schema.hpp"
#include "store.hpp"
#include "syslog.hpp"
#include "util.hpp"

using namespace fw;
using json = nlohmann::json;

namespace fw {
static std::ostream& operator<<(std::ostream& o, LicState s) { return o << lic_state_name(s); }
}  // namespace fw

static int g_fail = 0, g_checks = 0;
#define CHECK(c)                                                                \
  do {                                                                          \
    ++g_checks;                                                                 \
    if (!(c)) {                                                                 \
      ++g_fail;                                                                 \
      std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__ << ": " #c "\n";    \
    }                                                                           \
  } while (0)
#define CHECK_EQ(a, b)                                                                                     \
  do {                                                                                                     \
    ++g_checks;                                                                                            \
    auto _a = (a);                                                                                         \
    auto _b = (b);                                                                                         \
    if (!(_a == _b)) {                                                                                     \
      ++g_fail;                                                                                            \
      std::cerr << "  FAIL " << __FILE__ << ":" << __LINE__ << ": " #a " == " #b "\n    got: " << _a     \
                << "\n    want: " << _b << "\n";                                                           \
    }                                                                                                      \
  } while (0)

static std::vector<std::pair<const char*, std::function<void()>>>& tests() {
  static std::vector<std::pair<const char*, std::function<void()>>> t;
  return t;
}
struct Reg {
  Reg(const char* n, std::function<void()> f) { tests().push_back({n, std::move(f)}); }
};
#define TEST(name)                       \
  static void name();                    \
  static Reg reg_##name(#name, name);    \
  static void name()

static std::string tmpdir() {
  char t[] = "/tmp/fwm-test-XXXXXX";
  return mkdtemp(t);
}

static std::vector<std::string> T(const std::string& s) { return *tokenize(s); }

static const char* ADMIN_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

static Config base_config() {
  Config c;
  config_set(c, T("system hostname fw1"));
  config_set(c, T("system login user admin role admin"));
  config_set(c, T(std::string("system login user admin ssh-key \"") + ADMIN_KEY + "\""));
  config_set(c, T("system login user admin api-token-sha256 " + sha256_hex("admintoken")));
  config_set(c, T("system login user bob role viewer"));
  config_set(c, T("system login user bob api-token-sha256 " + sha256_hex("bobtoken")));
  config_set(c, T("firewall rule 10 action accept"));
  config_set(c, T("firewall rule 10 source 10.0.0.0/8"));
  return c;
}

// ---------------------------------------------------------------- schema / config

TEST(schema_accepts_and_rejects) {
  Config c;
  CHECK_EQ(config_set(c, T("system hostname fw-1")), "");
  CHECK_EQ(config_set(c, T("interfaces interface eth0 address 192.0.2.1/24")), "");
  CHECK_EQ(config_set(c, T("firewall rule 10 action drop")), "");
  CHECK(!config_set(c, T("system services ssh port 70000")).empty());
  CHECK(!config_set(c, T("interfaces interface eth0 address 192.0.2.1")).empty());
  CHECK(!config_set(c, T("interfaces interface eth0 address 300.0.2.1/24")).empty());
  CHECK(!config_set(c, T("firewall rule 10 action maybe")).empty());
  CHECK(!config_set(c, T("firewall rule 0 action drop")).empty());   // key range 1..65535
  CHECK(!config_set(c, T("firewall rule abc action drop")).empty());
  CHECK(!config_set(c, T("system nosuch 1")).empty());
  CHECK(!config_set(c, T("system hostname")).empty());                // missing value
  CHECK(!config_set(c, T("system hostname a b")).empty());            // extra token
  CHECK(!config_set(c, T("system hostname \"bad name\"")).empty());
  CHECK_EQ(c.size(), 3u);
}

TEST(tokenize_quotes_and_roundtrip) {
  auto t = tokenize("set interfaces interface eth0 description \"uplink \\\"A\\\" \\\\ x\"");
  CHECK(t && t->size() == 6);
  CHECK_EQ((*t)[5], std::string("uplink \"A\" \\ x"));
  CHECK(!tokenize("set a \"unterminated"));
  Config c = base_config();
  config_set(c, T("interfaces interface eth0 description \"has # and ; and \\\"quotes\\\"\""));
  std::string err;
  auto back = parse_config(to_set_lines(c), &err);
  CHECK(back.has_value());
  CHECK(back && *back == c);
}

TEST(delete_subtree_is_exact) {
  Config c = base_config();
  config_set(c, T("firewall rule 1 action drop"));
  config_set(c, T("firewall rule 100 action drop"));
  CHECK_EQ(config_delete(c, T("firewall rule 1")), "");
  CHECK(c.count("firewall rule 10 action") == 1);
  CHECK(c.count("firewall rule 100 action") == 1);
  CHECK(c.count("firewall rule 1 action") == 0);
  CHECK(!config_delete(c, T("firewall rule 5")).empty());
}

TEST(hierarchical_view_and_masking) {
  Config c = base_config();
  auto h = to_hierarchical(c, "firewall");
  CHECK_EQ(h, std::string("firewall {\n    rule 10 {\n        action accept;\n        source 10.0.0.0/8;\n    }\n}\n"));
  auto masked = to_set_lines(c, true);
  CHECK(masked.find(sha256_hex("admintoken")) == std::string::npos);
  CHECK(masked.find("<masked>") != std::string::npos);
}

TEST(diff_kinds) {
  Config a = base_config(), b = a;
  b["system hostname"] = "fw2";
  b.erase("firewall rule 10 source");
  b["firewall rule 20 action"] = "drop";
  auto d = diff(a, b);
  CHECK_EQ(d.size(), 3u);
  int add = 0, del = 0, mod = 0;
  for (auto& x : d) (x.kind == Change::Add ? add : x.kind == Change::Delete ? del : mod)++;
  CHECK(add == 1 && del == 1 && mod == 1);
}

// ---------------------------------------------------------------- store

TEST(store_commit_rollback_persist) {
  auto dir = tmpdir();
  Config boot = base_config();
  {
    ConfigStore s(dir, nullptr);
    s.open(boot);
    CHECK_EQ(s.running_id(), 1u);
    auto [c, id] = s.snapshot();
    c["system hostname"] = "fw2";
    auto r = s.commit(c, id, {"admin", "test"}, "rename");
    CHECK(r.ok);
    CHECK_EQ(r.id, 2u);
    auto old = s.rollback_config(1);
    CHECK(old && *old == boot);
    auto r2 = s.commit(*old, 2, {"admin", "test"}, "rollback 1");
    CHECK(r2.ok && r2.id == 3);
    CHECK(s.snapshot().first == boot);
  }
  ConfigStore s2(dir, nullptr);  // "restart"
  s2.open({});
  CHECK_EQ(s2.running_id(), 3u);
  CHECK(s2.snapshot().first == boot);
  CHECK_EQ(s2.history().size(), 3u);
  CHECK_EQ(s2.history()[1].comment, std::string("rename"));
}

TEST(store_optimistic_concurrency) {
  ConfigStore s(tmpdir(), nullptr);
  s.open(base_config());
  auto [c1, b1] = s.snapshot();
  auto [c2, b2] = s.snapshot();
  c1["system hostname"] = "one";
  c2["system hostname"] = "two";
  CHECK(s.commit(c1, b1, {"a", "test"}, "").ok);
  auto r = s.commit(c2, b2, {"b", "test"}, "");
  CHECK(!r.ok);
  CHECK(r.error.find("changed by another session") != std::string::npos);
  CHECK_EQ(s.snapshot().first.at("system hostname"), std::string("one"));
}

TEST(store_semantic_validation) {
  ConfigStore s(tmpdir(), nullptr);
  s.open(base_config());
  auto [c, id] = s.snapshot();
  auto bad = c;
  bad["firewall rule 20 source"] = "10.1.0.0/16";  // no action
  CHECK(s.commit(bad, id, {"a", "test"}, "").error.find("'action' is mandatory") != std::string::npos);
  bad = c;
  bad.erase("system login user admin ssh-key");  // lockout protection
  CHECK(s.commit(bad, id, {"a", "test"}, "").error.find("lock out") != std::string::npos);
  bad = c;
  bad["system services ssh port"] = "9000";
  bad["system services https port"] = "9000";
  CHECK(!s.commit(bad, id, {"a", "test"}, "").ok);
  CHECK_EQ(s.running_id(), id);
}

TEST(store_commit_confirmed_reverts) {
  auto dir = tmpdir();
  ConfigStore s(dir, nullptr);
  s.open(base_config());
  auto [c, id] = s.snapshot();
  auto risky = c;
  risky["firewall rule 5 action"] = "drop";
  auto r = s.commit(risky, id, {"admin", "test"}, "risky", 1);
  CHECK(r.ok);
  CHECK(s.pending().has_value());
  s.tick();
  CHECK_EQ(s.running_id(), 2u);  // not yet
  usleep(1100 * 1000);
  s.tick();
  CHECK_EQ(s.running_id(), 3u);  // revert is a new commit
  CHECK(s.snapshot().first == c);
  CHECK(!s.pending().has_value());
  CHECK_EQ(s.history()[0].user, std::string("system"));
}

TEST(store_commit_confirmed_confirm_keeps) {
  ConfigStore s(tmpdir(), nullptr);
  s.open(base_config());
  auto [c, id] = s.snapshot();
  c["firewall rule 5 action"] = "drop";
  CHECK(s.commit(c, id, {"admin", "test"}, "", 1).ok);
  auto r = s.commit(c, 2, {"admin", "test"}, "");  // plain commit, no changes -> confirms
  CHECK(r.ok);
  CHECK(!s.pending().has_value());
  usleep(1100 * 1000);
  s.tick();
  CHECK_EQ(s.running_id(), 2u);
}

TEST(store_pending_confirm_survives_restart) {
  auto dir = tmpdir();
  Config boot = base_config();
  {
    ConfigStore s(dir, nullptr);
    s.open(boot);
    auto [c, id] = s.snapshot();
    c["firewall rule 5 action"] = "drop";
    CHECK(s.commit(c, id, {"admin", "test"}, "", 1).ok);
  }  // "crash" with the confirm still pending
  usleep(1100 * 1000);
  ConfigStore s2(dir, nullptr);
  s2.open({});
  CHECK(s2.pending().has_value());
  s2.tick();
  CHECK(s2.snapshot().first == boot);
}

TEST(store_ignores_torn_tmp_and_retains_50) {
  auto dir = tmpdir();
  {
    ConfigStore s(dir, nullptr);
    s.open(base_config());
    for (int i = 0; i < 60; ++i) {
      auto [c, id] = s.snapshot();
      c["system hostname"] = "h" + std::to_string(i);
      CHECK(s.commit(c, id, {"a", "test"}, "").ok);
    }
    CHECK_EQ(s.history().size(), ConfigStore::kRetain);
    CHECK(!s.rollback_config(50));
    CHECK(s.rollback_config(49).has_value());
  }
  // a crash between write() and rename() leaves only a .tmp; it must be ignored
  FILE* f = fopen((dir + "/commits/0000000099.conf.tmp").c_str(), "w");
  fputs("#@ {\"id\":99,\"ts\":0,\"user\":\"x\",\"via\":\"x\",\"comment\":\"\",\"changes\":0}\nset system hostn", f);
  fclose(f);
  ConfigStore s2(dir, nullptr);
  s2.open({});
  CHECK_EQ(s2.running_id(), 61u);
  CHECK(!file_exists(dir + "/commits/0000000099.conf.tmp"));
}

struct VetoSub : Subscriber {
  int applied = 0;
  std::string name() const override { return "veto"; }
  std::vector<std::string> prefixes() const override { return {"interfaces"}; }
  std::string validate(const Config& c, const std::vector<Change>&) override {
    return c.count("interfaces interface bad0 mtu") ? "driver refuses bad0" : "";
  }
  void apply(const Config&, const std::vector<Change>&) override { ++applied; }
};

TEST(store_subscriber_veto_and_apply) {
  ConfigStore s(tmpdir(), nullptr);
  VetoSub v;
  s.subscribe(&v);
  s.open(base_config());
  auto [c, id] = s.snapshot();
  auto bad = c;
  bad["interfaces interface bad0 mtu"] = "1500";
  auto r = s.commit(bad, id, {"a", "test"}, "");
  CHECK(!r.ok && r.error.find("driver refuses") != std::string::npos);
  CHECK_EQ(v.applied, 0);
  c["system hostname"] = "x";  // outside the subscriber's prefix
  CHECK(s.commit(c, id, {"a", "test"}, "").ok);
  CHECK_EQ(v.applied, 0);
  c["interfaces interface eth1 mtu"] = "9000";
  CHECK(s.commit(c, id + 1, {"a", "test"}, "").ok);
  CHECK_EQ(v.applied, 1);
}

TEST(store_license_gating) {
  bool licensed = false;
  ConfigStore s(tmpdir(), nullptr, [&](const std::string& f) { return licensed && f == "url-filtering"; });
  s.open(base_config());
  auto [c, id] = s.snapshot();
  c["firewall url-filter enable"] = "true";
  auto r = s.commit(c, id, {"a", "test"}, "");
  CHECK(!r.ok && r.error.find("not licensed") != std::string::npos);
  licensed = true;
  CHECK(s.commit(c, id, {"a", "test"}, "").ok);
  licensed = false;  // license expired later: unrelated commits still work, with a warning
  c["system hostname"] = "after-expiry";
  auto r2 = s.commit(c, id + 1, {"a", "test"}, "");
  CHECK(r2.ok);
  CHECK(!r2.warnings.empty());
}

// ---------------------------------------------------------------- license

struct Keys {
  std::string priv, pub;
  Keys() { ed25519_keygen(&priv, &pub); }
};
static std::string make_lic(const Keys& k, const std::string& dev, int64_t issued, int64_t expires, int grace = 7) {
  std::string body = "customer=Acme\nlicense-id=L-1\ndevice-id=" + dev + "\nfeatures=url-filtering,api\nissued=" +
                     std::to_string(issued) + "\nexpires=" + std::to_string(expires) + "\ngrace-days=" + std::to_string(grace) + "\n";
  return body + "signature=" + ed25519_sign_b64(k.priv, body) + "\n";
}

TEST(license_valid_and_tamper) {
  Keys k;
  int64_t now = 1'800'000'000;
  auto lic = make_lic(k, "dev1", now - 100, now + 86400 * 30);
  std::string err;
  auto l = parse_and_verify_license(lic, k.pub, &err);
  CHECK(l.has_value());
  CHECK(l && l->features.count("api"));
  CHECK_EQ(evaluate_license(l, now, "dev1", 0).state, LicState::Valid);
  // flip each byte of the signed body: every single one must break verification
  size_t body_len = lic.find("signature=");
  int accepted = 0;
  for (size_t i = 0; i < body_len; ++i) {
    std::string t = lic;
    t[i] ^= 0x01;
    if (parse_and_verify_license(t, k.pub, &err)) ++accepted;
  }
  CHECK_EQ(accepted, 0);
  // extend expiry by editing the text -> rejected
  std::string t = lic;
  auto p = t.find("expires=");
  t.replace(p + 8, 1, "9");
  CHECK(!parse_and_verify_license(t, k.pub, &err));
  CHECK_EQ(err, std::string("signature verification failed"));
  // signature from another vendor key
  Keys other;
  CHECK(!parse_and_verify_license(make_lic(other, "dev1", now, now + 1000), k.pub, &err));
  // garbage / truncated signature
  CHECK(!parse_and_verify_license(lic.substr(0, lic.size() - 10), k.pub, &err));
  CHECK(!parse_and_verify_license("customer=x\n", k.pub, &err));
}

TEST(license_strict_fields_even_when_signed) {
  Keys k;
  std::string body = "license-id=L\ndevice-id=*\nissued=1\nexpires=2\nexpires=999999999999\n";
  std::string err;
  CHECK(!parse_and_verify_license(body + "signature=" + ed25519_sign_b64(k.priv, body) + "\n", k.pub, &err));
  CHECK(err.find("duplicate") != std::string::npos);
  body = "license-id=L\ndevice-id=*\nissued=1\nexpires=2\nadmin=true\n";
  CHECK(!parse_and_verify_license(body + "signature=" + ed25519_sign_b64(k.priv, body) + "\n", k.pub, &err));
}

TEST(license_body_without_trailing_newline_terminates) {
  // regression: fuzz_license found that "#" (no newline) looped forever
  std::string err;
  CHECK(!parse_license_body("#", &err));
  CHECK(!parse_license_body("license-id=L", &err));
  auto l = parse_license_body("license-id=L\ndevice-id=*\nissued=1\nexpires=2", &err);
  CHECK(l.has_value());
}

TEST(license_expiry_grace_device_clock) {
  Keys k;
  int64_t t0 = 1'800'000'000, exp = t0 + 86400;
  std::string err;
  auto l = parse_and_verify_license(make_lic(k, "dev1", t0, exp, 7), k.pub, &err);
  CHECK(l.has_value());
  CHECK_EQ(evaluate_license(l, exp - 1, "dev1", 0).state, LicState::Valid);
  auto g = evaluate_license(l, exp + 3600, "dev1", 0);
  CHECK_EQ(g.state, LicState::Grace);
  CHECK(g.feature("url-filtering"));  // grace keeps features on
  auto e = evaluate_license(l, exp + 8 * 86400, "dev1", 0);
  CHECK_EQ(e.state, LicState::Expired);
  CHECK(!e.feature("url-filtering"));
  CHECK_EQ(evaluate_license(l, t0 + 10, "dev2", 0).state, LicState::Invalid);  // device binding
  // clock rollback: device has already seen exp+8d; clock now says t0+10
  auto rb = evaluate_license(l, t0 + 10, "dev1", exp + 8 * 86400);
  CHECK_EQ(rb.state, LicState::Invalid);
  CHECK(rb.reason.find("backwards") != std::string::npos);
  // small NTP-style skew under the tolerance is fine
  CHECK_EQ(evaluate_license(l, t0 + 1000, "dev1", t0 + 1000 + 60).state, LicState::Valid);
  // clock before the issue date
  CHECK_EQ(evaluate_license(l, t0 - 86400, "dev1", 0).state, LicState::Invalid);
  auto site = parse_and_verify_license(make_lic(k, "*", t0, exp), k.pub, &err);
  CHECK_EQ(evaluate_license(site, t0 + 5, "anything", 0).state, LicState::Valid);
}

TEST(clock_guard_persists) {
  auto p = tmpdir() + "/hwm";
  {
    ClockGuard g(p);
    g.observe(1000);
    g.observe(500);  // going backwards never lowers the mark
    CHECK_EQ(g.hwm(), 1000);
  }
  ClockGuard g2(p);
  CHECK_EQ(g2.hwm(), 1000);
}

// ---------------------------------------------------------------- syslog

TEST(rfc5424_format_exact) {
  auto s = rfc5424_format(16, Sev::Notice, "2026-10-20T10:00:00.000001Z", "fw1", "fw-mgmtd", 42, "COMMIT",
                          {{"audit@32473", {{"user", "alice"}, {"comment", "a \"q\" ] \\"}}}}, "commit 7\nby alice");
  CHECK_EQ(s, std::string("<133>1 2026-10-20T10:00:00.000001Z fw1 fw-mgmtd 42 COMMIT [audit@32473 user=\"alice\" comment=\"a \\\"q\\\" \\] \\\\\"] commit 7 by alice"));
  CHECK_EQ(rfc5424_format(1, Sev::Err, "T", "", "a p", 1, "", {}, ""), std::string("<11>1 T - ap 1 - -"));
}

// ---------------------------------------------------------------- CLI

struct CliFixture {
  std::string dir = tmpdir();
  Syslog log{dir + "/log"};
  ConfigStore store{dir + "/cfg", &log};
  Engine eng;
  CliFixture() {
    store.open(base_config());
    eng.store = &store;
    eng.log = &log;
  }
};

TEST(cli_rbac) {
  CliFixture f;
  CliSession bob(f.eng, "bob", "test");
  auto o = bob.exec("configure");
  CHECK(o.text.find("permission denied") != std::string::npos);
  CHECK(!bob.in_config());
  o = bob.exec("show configuration system login");
  CHECK(o.text.find("<masked>") != std::string::npos);
  CHECK(o.text.find(sha256_hex("bobtoken")) == std::string::npos);
  CHECK(bob.exec("show log").text.find("permission denied") != std::string::npos);  // operator+
  bool logged = false;
  for (auto& l : f.log.recent(50))
    if (l.find("AUTHZ_DENY") != std::string::npos && l.find("user=\"bob\"") != std::string::npos) logged = true;
  CHECK(logged);
  CliSession nobody(f.eng, "mallory", "test");
  CHECK(nobody.exec("show configuration").exit);
}

TEST(cli_configure_commit_rollback) {
  CliFixture f;
  CliSession a(f.eng, "admin", "test");
  CHECK(a.exec("conf").text.find("Entering") != std::string::npos);  // abbreviation
  CHECK_EQ(a.exec("set system hostname edge-7").text, std::string(""));
  CHECK(a.exec("set system services ssh port 99999").text.find("error") != std::string::npos);
  CHECK(a.exec("compare").text.find("+ set system hostname edge-7") != std::string::npos);
  CHECK(a.exec("exit").text.find("uncommitted") != std::string::npos);
  CHECK(a.exec("commit check").text.find("succeeds") != std::string::npos);
  CHECK_EQ(f.store.running_id(), 1u);
  CHECK(a.exec("commit comment \"rename box\"").text.find("commit complete") != std::string::npos);
  CHECK_EQ(f.store.snapshot().first.at("system hostname"), std::string("edge-7"));
  CHECK(a.exec("rollback 1").text.find("load complete") != std::string::npos);
  CHECK(a.exec("commit").text.find("commit complete") != std::string::npos);
  CHECK_EQ(f.store.snapshot().first.at("system hostname"), std::string("fw1"));
  CHECK(a.exec("exit").text.find("Exiting") != std::string::npos);
  auto h = a.exec("show commits").text;
  CHECK(h.find("rename box") != std::string::npos);
  CHECK(a.exec("show configuration firewall | display set").text.find("set firewall rule 10 action accept") != std::string::npos);
  CHECK(a.exec("show configuration | match hostname").text.find("hostname fw1;") != std::string::npos);
}

TEST(cli_two_sessions_conflict_then_update) {
  CliFixture f;
  CliSession a(f.eng, "admin", "test"), b(f.eng, "admin", "test");
  a.exec("configure");
  b.exec("configure");
  a.exec("set firewall rule 20 action drop");
  b.exec("set firewall rule 30 action reject");
  CHECK(b.exec("commit").text.find("commit complete") != std::string::npos);
  CHECK(a.exec("commit").text.find("changed by another session") != std::string::npos);
  CHECK(a.exec("update").text.find("1 of your changes") != std::string::npos);
  CHECK(a.exec("commit").text.find("commit complete") != std::string::npos);
  auto c = f.store.snapshot().first;
  CHECK(c.count("firewall rule 20 action") && c.count("firewall rule 30 action"));
}

TEST(cli_demotion_takes_effect_immediately) {
  CliFixture f;
  CliSession a(f.eng, "admin", "test");
  // make a second admin so that demoting "admin" passes lockout protection
  a.exec("configure");
  a.exec("set system login user root2 role admin");
  a.exec(std::string("set system login user root2 ssh-key \"") + ADMIN_KEY + "\"");
  a.exec("set system login user admin role viewer");
  CHECK(a.exec("commit").text.find("commit complete") != std::string::npos);
  CHECK(a.exec("set system hostname x").text.find("permission denied") != std::string::npos);
  CHECK(!a.in_config());
}

TEST(cli_completion) {
  CliFixture f;
  CliSession a(f.eng, "admin", "test");
  auto c = a.complete("sh");
  CHECK(c.size() == 1 && c[0] == "show");
  c = a.complete("show c");
  CHECK_EQ(c.size(), 3u);  // certificate commits configuration
  c = a.complete("show configuration fire");
  CHECK(c.size() == 1 && c[0] == "firewall");
  CliSession bob(f.eng, "bob", "test");
  c = bob.complete("");
  CHECK(std::find(c.begin(), c.end(), "configure") == c.end());  // role-filtered
  a.exec("configure");
  c = a.complete("set firewall rule ");
  CHECK(std::find(c.begin(), c.end(), "10") != c.end());
  CHECK(std::find(c.begin(), c.end(), "<number>") != c.end());
  c = a.complete("set firewall rule 10 action ");
  CHECK_EQ(c.size(), 3u);
  c = a.complete("set firewall rule 10 action d");
  CHECK(c.size() == 1 && c[0] == "drop");
  c = a.complete("commit ");
  CHECK_EQ(c.size(), 3u);
}

TEST(line_editor) {
  std::vector<std::string> words = {"show", "set"};
  LineEditor ed([&](const std::string& l) {
    std::vector<std::string> o;
    std::string w = l.substr(l.rfind(' ') == std::string::npos ? 0 : l.rfind(' ') + 1);
    for (auto& x : words) if (x.rfind(w, 0) == 0) o.push_back(x);
    return o;
  }, true);
  std::vector<LineEditor::Event> ev;
  ed.feed("sh\t", ev, "> ");
  CHECK_EQ(ed.buffer(), std::string("show "));
  ed.feed("abc\x7f\r\n", ev, "> ");
  CHECK(ev.size() == 1 && ev[0].line == "show ab");
  ev.clear();
  ed.feed("s\t", ev, "> ");  // ambiguous: buffer unchanged, list shown
  CHECK_EQ(ed.buffer(), std::string("s"));
  ed.feed("\x03", ev, "> ");
  CHECK(ev.size() == 1 && ev[0].kind == LineEditor::Event::Interrupt);
  ev.clear();
  ed.feed("\x1b[A\r", ev, "> ");  // history: up arrow recalls the last line
  CHECK(ev.size() == 1 && ev[0].line == "show ab");
}

// ---------------------------------------------------------------- HTTP / API

TEST(http_request_parser) {
  HttpRequest r;
  size_t cl;
  std::string err;
  CHECK(parse_request_head("GET /api/v1/config?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n", r, &cl, &err));
  CHECK(r.path == "/api/v1/config" && r.query == "x=1" && cl == 5);
  HttpRequest r2;
  CHECK(!parse_request_head("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", r2, &cl, &err));
  HttpRequest r3;
  CHECK(!parse_request_head("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", r3, &cl, &err));
  HttpRequest r4;
  CHECK(!parse_request_head("GET / HTTP/2\r\n\r\n", r4, &cl, &err));
  HttpRequest r5;
  CHECK(!parse_request_head("POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n", r5, &cl, &err));
}

static HttpRequest req(const std::string& m, const std::string& path, const std::string& tok, const std::string& body = "") {
  HttpRequest r;
  r.method = m;
  r.path = r.target = path;
  if (!tok.empty()) r.headers["authorization"] = "Bearer " + tok;
  r.body = body;
  return r;
}

TEST(api_auth_rbac_and_cli_agreement) {
  CliFixture f;
  CHECK_EQ(api_handle(f.eng, req("GET", "/api/v1/config", "")).status, 401);
  CHECK_EQ(api_handle(f.eng, req("GET", "/api/v1/config", "wrong")).status, 401);
  auto g = api_handle(f.eng, req("GET", "/api/v1/config", "bobtoken"));
  CHECK_EQ(g.status, 200);
  CHECK(g.body.find("<masked>") != std::string::npos);
  CHECK_EQ(api_handle(f.eng, req("POST", "/api/v1/config", "bobtoken", R"({"base":1,"set":["system hostname x"]})")).status, 403);
  CHECK_EQ(api_handle(f.eng, req("POST", "/api/v1/config", "admintoken", R"({"set":["system hostname x"]})")).status, 428);
  CHECK_EQ(api_handle(f.eng, req("POST", "/api/v1/config", "admintoken", R"({"base":1,"set":["system services ssh port 0"]})")).status, 422);
  // API write -> CLI read
  auto w = api_handle(f.eng, req("POST", "/api/v1/config", "admintoken", R"({"base":1,"set":["system hostname via-api"],"comment":"api"})"));
  CHECK_EQ(w.status, 200);
  CliSession a(f.eng, "admin", "test");
  CHECK(a.exec("show configuration system hostname").text.find("via-api") != std::string::npos);
  // stale base -> 409
  CHECK_EQ(api_handle(f.eng, req("POST", "/api/v1/config", "admintoken", R"({"base":1,"set":["system hostname y"]})")).status, 409);
  // CLI write -> API read
  a.exec("configure");
  a.exec("set system hostname via-cli");
  a.exec("commit");
  auto j = json::parse(api_handle(f.eng, req("GET", "/api/v1/config", "admintoken")).body);
  CHECK_EQ(j["config"]["system hostname"].get<std::string>(), std::string("via-cli"));
  CHECK_EQ(j["commit"].get<int>(), 3);
  // operational commands through the same CLI engine, same RBAC
  auto c = api_handle(f.eng, req("POST", "/api/v1/cli", "bobtoken", R"({"command":"show log"})"));
  CHECK(c.body.find("permission denied") != std::string::npos);
  auto rb = api_handle(f.eng, req("POST", "/api/v1/config/rollback", "admintoken", R"({"n":1})"));
  CHECK_EQ(rb.status, 200);
  CHECK_EQ(f.store.snapshot().first.at("system hostname"), std::string("via-api"));
}

// ---------------------------------------------------------------- certificates

TEST(cert_keygen_csr_selfsigned) {
  auto key = gen_ec_key_pem();
  auto der = make_csr_der(key, "fw1.example.test");
  const unsigned char* p = reinterpret_cast<const unsigned char*>(der.data());
  X509_REQ* rq = d2i_X509_REQ(nullptr, &p, static_cast<long>(der.size()));
  CHECK(rq != nullptr);
  CHECK(rq && X509_REQ_verify(rq, X509_REQ_get0_pubkey(rq)) == 1);  // self-signature of the CSR
  X509_REQ_free(rq);
  auto pem = self_signed_pem(key, "fw1.example.test", 30);
  auto ci = cert_info(pem);
  CHECK(ci.ok);
  CHECK_EQ(ci.sans, std::string("fw1.example.test"));
  CHECK(ci.not_after - ci.not_before > 29 * 86400);
  std::string err;
  CHECK(make_server_ctx(pem, key, &err) != nullptr);
  CHECK(make_server_ctx(pem, gen_ec_key_pem(), &err) == nullptr);  // mismatched key
}

TEST(https_server_hot_swap) {
  auto dir = tmpdir();
  auto k1 = gen_ec_key_pem(), c1 = self_signed_pem(k1, "localhost", 1);
  auto k2 = gen_ec_key_pem(), c2 = self_signed_pem(k2, "localhost", 1);
  atomic_write(dir + "/c1.pem", c1);
  atomic_write(dir + "/c2.pem", c2);
  HttpServer srv([](const HttpRequest&) { return HttpResponse{200, "text/plain", "ok"}; });
  std::string err;
  srv.set_ctx(make_server_ctx(c1, k1, &err));
  CHECK(srv.listen("127.0.0.1", 0, &err));
  srv.start();
  std::string url = "https://localhost:" + std::to_string(srv.port()) + "/";
  CHECK_EQ(http_fetch("GET", url, "", {}, dir + "/c1.pem").status, 200);
  CHECK_EQ(http_fetch("GET", url, "", {}, dir + "/c2.pem").status, 0);  // not trusted yet
  srv.set_ctx(make_server_ctx(c2, k2, &err));
  CHECK_EQ(http_fetch("GET", url, "", {}, dir + "/c2.pem").status, 200);
  CHECK_EQ(srv.handshake_failures.load(), 1u);
  srv.stop();
}

int main(int argc, char** argv) {
  std::string only = argc > 1 ? argv[1] : "";
  int ran = 0;
  for (auto& [name, fn] : tests()) {
    if (!only.empty() && std::string(name).find(only) == std::string::npos) continue;
    int before = g_fail;
    fn();
    ++ran;
    std::cout << (g_fail == before ? "ok   " : "FAIL ") << name << "\n";
  }
  std::cout << ran << " tests, " << g_checks << " checks, " << g_fail << " failures\n";
  return g_fail ? 1 : 0;
}
