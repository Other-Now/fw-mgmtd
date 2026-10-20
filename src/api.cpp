#include "api.hpp"

#include <openssl/crypto.h>

#include <nlohmann/json.hpp>

#include "cli.hpp"
#include "syslog.hpp"
#include "util.hpp"

namespace fw {

using json = nlohmann::json;

static HttpResponse J(int status, const json& j) { return {status, "application/json", j.dump() + "\n"}; }
static HttpResponse err(int status, const std::string& m) { return J(status, {{"error", m}}); }

// Bearer token -> user, by comparing SHA-256(token) with each user's
// api-token-sha256 in constant time. Tokens themselves are never stored.
static std::string auth_user(Engine& e, const HttpRequest& req) {
  auto it = req.headers.find("authorization");
  if (it == req.headers.end() || !starts_with(it->second, "Bearer ")) return "";
  std::string h = sha256_hex(it->second.substr(7));
  auto [cfg, id] = e.store->snapshot();
  const std::string pre = "system login user ";
  std::string found;
  for (auto i = cfg.lower_bound(pre); i != cfg.end() && starts_with(i->first, pre); ++i) {
    if (i->first.size() < 17 || i->first.compare(i->first.size() - 17, 17, " api-token-sha256") != 0) continue;
    if (i->second.size() == h.size() && CRYPTO_memcmp(i->second.data(), h.data(), h.size()) == 0)
      found = i->first.substr(pre.size(), i->first.size() - pre.size() - 17);
  }
  return found;
}

static json commit_json(const CommitResult& r) {
  json w = r.warnings;
  auto us = [](double v) { return static_cast<int64_t>(v + 0.5); };
  return {{"commit", r.id}, {"changes", r.diff.size()}, {"warnings", w},
          {"us", {{"validate", us(r.us_validate)}, {"persist", us(r.us_persist)}, {"apply", us(r.us_apply)}, {"total", us(r.us_total)}}}};
}

HttpResponse api_handle(Engine& e, const HttpRequest& req) {
  if (req.path == "/api/v1/health") return J(200, {{"status", "ok"}, {"commit", e.store->running_id()}});
  std::string user = auth_user(e, req);
  if (user.empty()) {
    if (e.log)
      e.log->log(Sev::Warning, "AUTH_FAIL", "api authentication failed from " + req.peer,
                 {{"audit@32473", {{"src", req.peer}, {"via", "api"}, {"path", req.path}}}});
    return {401, "application/json", "{\"error\":\"unauthorized\"}\n", {{"WWW-Authenticate", "Bearer"}}};
  }
  Role role = e.role_of(user);
  auto need = [&](Role r) { return static_cast<int>(role) >= static_cast<int>(r); };
  auto deny = [&](const char* what) {
    if (e.log)
      e.log->log(Sev::Warning, "AUTHZ_DENY", user + " denied: " + what,
                 {{"audit@32473", {{"user", user}, {"via", "api"}, {"role", role_name(role)}, {"cmd", what}}}});
    return err(403, std::string("permission denied: ") + what + " requires admin");
  };

  if (req.method == "GET" && req.path == "/api/v1/config") {
    auto [cfg, id] = e.store->snapshot();
    json c = json::object();
    for (auto& [k, v] : cfg) c[k] = (role != Role::Admin && key_is_secret(k)) ? "<masked>" : v;
    auto r = J(200, {{"commit", id}, {"config", c}});
    r.headers.push_back({"ETag", "\"" + std::to_string(id) + "\""});
    return r;
  }
  if (req.method == "GET" && req.path == "/api/v1/commits") {
    json a = json::array();
    for (auto& h : e.store->history())
      a.push_back({{"commit", h.id}, {"ts", h.ts}, {"user", h.user}, {"via", h.via}, {"comment", h.comment}, {"changes", h.changes}});
    json out = {{"commits", a}};
    if (auto p = e.store->pending()) out["pending_confirm"] = {{"commit", p->commit_id}, {"revert_to", p->revert_to}, {"deadline", p->deadline}};
    return J(200, out);
  }
  if (req.method == "POST" && req.path == "/api/v1/cli") {
    json b = json::parse(req.body, nullptr, false);
    if (b.is_discarded() || !b.contains("command") || !b["command"].is_string()) return err(400, "body must be {\"command\": \"...\"}");
    std::string cmd = b["command"];
    if (starts_with(trim(cmd), "conf")) return err(400, "configuration mode is not available here; use POST /api/v1/config");
    CliSession s(e, user, "api");
    auto o = s.exec(cmd);
    return J(o.text.rfind("error:", 0) == 0 ? 400 : 200, {{"output", o.text}});
  }
  if (req.method == "POST" && req.path == "/api/v1/config") {
    if (!need(Role::Admin)) return deny("configuration change");
    json b = json::parse(req.body, nullptr, false);
    if (b.is_discarded() || !b.is_object()) return err(400, "invalid JSON");
    auto [cfg, id] = e.store->snapshot();
    // base: from body or If-Match; required so that a stale client cannot
    // blindly overwrite a newer commit
    uint64_t base = 0;
    if (b.contains("base") && b["base"].is_number_unsigned()) base = b["base"];
    else if (auto im = req.headers.find("if-match"); im != req.headers.end()) base = std::strtoull(im->second.c_str() + (im->second[0] == '"'), nullptr, 10);
    else return err(428, "need \"base\" (commit id) or If-Match");
    if (base != id) return J(409, {{"error", "running configuration changed"}, {"base", base}, {"running", id}});
    Config cand = cfg;
    auto apply_list = [&](const char* field, bool is_set) -> std::string {
      if (!b.contains(field)) return "";
      if (!b[field].is_array()) return std::string(field) + " must be an array of strings";
      for (auto& s : b[field]) {
        if (!s.is_string()) return std::string(field) + " must be an array of strings";
        std::string terr;
        auto toks = tokenize(s.get<std::string>(), &terr);
        if (!toks) return terr;
        auto er = is_set ? config_set(cand, *toks) : config_delete(cand, *toks);
        if (!er.empty()) return std::string(is_set ? "set " : "delete ") + s.get<std::string>() + ": " + er;
      }
      return "";
    };
    if (auto er = apply_list("delete", false); !er.empty()) return err(422, er);
    if (auto er = apply_list("set", true); !er.empty()) return err(422, er);
    int confirm = b.value("confirmed", 0);
    if (confirm < 0 || confirm > 86400) return err(422, "confirmed must be 0..86400 seconds");
    auto r = e.store->commit(cand, base, {user, "api"}, b.value("comment", std::string()), confirm, b.value("check", false));
    if (!r.ok) return J(r.error.find("changed by another session") != std::string::npos ? 409 : 422, {{"error", r.error}});
    return J(200, commit_json(r));
  }
  if (req.method == "POST" && req.path == "/api/v1/config/confirm") {
    if (!need(Role::Admin)) return deny("commit confirm");
    auto r = e.store->confirm({user, "api"});
    return r.ok ? J(200, {{"confirmed", r.id}}) : err(409, r.error);
  }
  if (req.method == "POST" && req.path == "/api/v1/config/rollback") {
    if (!need(Role::Admin)) return deny("rollback");
    json b = json::parse(req.body, nullptr, false);
    if (b.is_discarded() || !b.contains("n") || !b["n"].is_number_unsigned()) return err(400, "body must be {\"n\": N}");
    auto old = e.store->rollback_config(b["n"].get<size_t>());
    if (!old) return err(404, "no such rollback");
    auto r = e.store->commit(*old, e.store->running_id(), {user, "api"}, b.value("comment", "rollback " + std::to_string(b["n"].get<size_t>())));
    return r.ok ? J(200, commit_json(r)) : err(422, r.error);
  }
  return err(404, "no such endpoint");
}

void HttpsService::apply(const Config& c, const std::vector<Change>&) {
  auto it = c.find("system services https port");
  int want = it == c.end() ? 8443 : std::stoi(it->second);
  if (want == srv_.port()) return;
  std::string e;
  if (!srv_.listen(addr_, want, &e)) {
    if (log_) log_->log(Sev::Err, "HTTPS_REBIND", e);
  } else if (log_) {
    log_->log(Sev::Notice, "HTTPS_REBIND", "https now listening on port " + std::to_string(want));
  }
}

void SyslogService::apply(const Config& c, const std::vector<Change>&) {
  auto get = [&](const char* k) { auto it = c.find(k); return it == c.end() ? std::string() : it->second; };
  log_->set_hostname(get("system hostname"));
  std::string port = get("system syslog port"), fac = get("system syslog facility");
  log_->set_remote(get("system syslog server"), port.empty() ? 514 : std::stoi(port));
  log_->set_facility(fac.empty() ? 16 : std::stoi(fac));
}

void FirewallService::apply(const Config& c, const std::vector<Change>& d) {
  size_t n = 0;
  for (auto it = c.lower_bound("firewall rule "); it != c.end() && starts_with(it->first, "firewall rule "); ++it)
    if (it->first.size() > 7 && it->first.compare(it->first.size() - 7, 7, " action") == 0) ++n;
  rules_ = n;
  ++applies_;
  if (log_ && !d.empty())
    log_->log(Sev::Info, "FW_APPLY", "rule set recompiled: " + std::to_string(n) + " rules (" + std::to_string(d.size()) + " changes, no restart)");
}

}  // namespace fw
