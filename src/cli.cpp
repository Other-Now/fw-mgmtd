#include "cli.hpp"

#include <algorithm>
#include <cstdio>

#include "certmgr.hpp"
#include "schema.hpp"
#include "store.hpp"
#include "syslog.hpp"
#include "util.hpp"

namespace fw {

const char* role_name(Role r) {
  switch (r) {
    case Role::Viewer: return "viewer";
    case Role::Operator: return "operator";
    case Role::Admin: return "admin";
    default: return "none";
  }
}

Role role_from(const std::string& s) {
  if (s == "admin") return Role::Admin;
  if (s == "operator") return Role::Operator;
  if (s == "viewer") return Role::Viewer;
  return Role::None;
}

Role Engine::role_of(const std::string& user) const {
  auto [c, id] = store->snapshot();
  auto it = c.find("system login user " + user + " role");
  return it == c.end() ? Role::None : role_from(it->second);
}

// ------------------------------------------------------------------ license manager

LicenseManager::LicenseManager(std::string license_path, std::string pubkey_path, std::string clock_path,
                               std::string device_id, Syslog* log)
    : lic_path_(std::move(license_path)), pub_path_(std::move(pubkey_path)), device_id_(std::move(device_id)),
      clock_(std::move(clock_path)), log_(log) {
  reload();
}

void LicenseManager::reload() {
  std::lock_guard lk(mu_);
  lic_.reset();
  load_error_.clear();
  auto text = read_file(lic_path_);
  auto pub = read_file(pub_path_);
  if (!text) {
    load_error_ = "no license file at " + lic_path_;
    return;
  }
  if (!pub) {
    load_error_ = "no vendor public key at " + pub_path_;
    return;
  }
  std::string err;
  lic_ = parse_and_verify_license(*text, *pub, &err);
  if (!lic_) {
    load_error_ = err;
    if (log_) log_->log(Sev::Err, "LICENSE_INVALID", "license rejected: " + err);
  }
}

LicenseStatus LicenseManager::status() {
  std::lock_guard lk(mu_);
  auto st = evaluate_license(lic_, unix_now(), device_id_, clock_.hwm());
  if (!lic_ && !load_error_.empty()) st.reason = load_error_;
  return st;
}

void LicenseManager::tick() {
  LicState now_state;
  std::string reason;
  {
    std::lock_guard lk(mu_);
    int64_t now = unix_now();
    auto st = evaluate_license(lic_, now, device_id_, clock_.hwm());
    // never let a rolled-back clock lower the high-water mark
    if (st.state != LicState::Invalid) clock_.observe(now);
    now_state = st.state;
    reason = st.reason;
  }
  if (now_state != last_state_) {
    if (log_)
      log_->log(now_state == LicState::Valid ? Sev::Notice : Sev::Warning, "LICENSE_STATE",
                std::string("license state ") + lic_state_name(last_state_) + " -> " + lic_state_name(now_state) + ": " + reason);
    last_state_ = now_state;
  }
}

std::string LicenseManager::show() {
  auto st = status();
  std::string s = "State:      " + std::string(lic_state_name(st.state)) + " (" + st.reason + ")\n";
  s += "Device id:  " + device_id_ + "\n";
  if (st.lic) {
    s += "License:    " + st.lic->license_id + "  customer " + st.lic->customer + "\n";
    s += "Bound to:   " + st.lic->device_id + "\n";
    s += "Issued:     " + rfc3339(Clock::from_time_t(st.lic->issued), false) + "\n";
    s += "Expires:    " + rfc3339(Clock::from_time_t(st.lic->expires), false) + "  (+" + std::to_string(st.lic->grace_days) + " days grace)\n";
    std::string f;
    for (auto& x : st.lic->features) f += (f.empty() ? "" : ", ") + x;
    bool active = st.state == LicState::Valid || st.state == LicState::Grace;
    s += "Features:   " + f + (active ? "  [active]" : "  [inactive]") + "\n";
  }
  return s;
}

// ------------------------------------------------------------------ command table

namespace {
struct Cmd {
  std::vector<std::string> words;
  Role role;
  const char* help;
};

const std::vector<Cmd>& op_cmds() {
  static const std::vector<Cmd> v = {
      {{"show", "configuration"}, Role::Viewer, "Running configuration"},
      {{"show", "commits"}, Role::Viewer, "Commit history (rollback numbers)"},
      {{"show", "certificate"}, Role::Viewer, "HTTPS certificate status"},
      {{"show", "license"}, Role::Viewer, "License state and features"},
      {{"show", "users"}, Role::Viewer, "Logged-in sessions"},
      {{"show", "log"}, Role::Operator, "Recent syslog/audit messages"},
      {{"show", "diagnostics"}, Role::Operator, "Process and service health"},
      {{"show", "tech-support"}, Role::Admin, "Everything support needs, secrets masked"},
      {{"request", "certificate", "renew"}, Role::Operator, "Renew the HTTPS certificate now"},
      {{"request", "certificate", "check-revocation"}, Role::Operator, "OCSP + CRL check of the current certificate"},
      {{"request", "license", "reload"}, Role::Admin, "Re-read the license file"},
      {{"configure"}, Role::Admin, "Enter configuration mode"},
      {{"exit"}, Role::Viewer, "Log out"},
      {{"help"}, Role::Viewer, "List commands"},
  };
  return v;
}

const std::vector<Cmd>& cfg_cmds() {
  static const std::vector<Cmd> v = {
      {{"set"}, Role::Admin, "Set a configuration value"},
      {{"delete"}, Role::Admin, "Delete a statement or subtree"},
      {{"show"}, Role::Admin, "Show the candidate configuration"},
      {{"compare"}, Role::Admin, "Diff candidate against running (or 'compare rollback N')"},
      {{"commit"}, Role::Admin, "commit [check] [confirmed <seconds>] [comment \"text\"]"},
      {{"rollback"}, Role::Admin, "Load commit N back into the candidate"},
      {{"discard"}, Role::Admin, "Throw away candidate changes"},
      {{"update"}, Role::Admin, "Rebase your changes on the latest running configuration"},
      {{"run"}, Role::Admin, "Run an operational command"},
      {{"exit"}, Role::Admin, "Leave configuration mode"},
      {{"help"}, Role::Admin, "List commands"},
  };
  return v;
}

// Resolves abbreviations ("sh conf" -> "show configuration") against the
// table. Returns the matched command index and how many words it consumed.
std::optional<std::pair<size_t, size_t>> resolve(const std::vector<Cmd>& tbl, std::vector<std::string>& t,
                                                 std::string* err) {
  std::vector<size_t> cand(tbl.size());
  for (size_t i = 0; i < tbl.size(); ++i) cand[i] = i;
  size_t w = 0;
  for (; w < t.size(); ++w) {
    std::vector<size_t> next;
    std::string exact;
    for (auto i : cand) {
      if (tbl[i].words.size() <= w) continue;
      if (starts_with(tbl[i].words[w], t[w])) {
        next.push_back(i);
        if (tbl[i].words[w] == t[w]) exact = t[w];
      }
    }
    if (next.empty()) break;
    std::string word = tbl[next[0]].words[w];
    bool same = std::all_of(next.begin(), next.end(), [&](size_t i) { return tbl[i].words[w] == word; });
    if (!same && exact.empty()) {
      *err = "'" + t[w] + "' is ambiguous";
      return std::nullopt;
    }
    if (!exact.empty()) {
      next.erase(std::remove_if(next.begin(), next.end(), [&](size_t i) { return tbl[i].words[w] != exact; }), next.end());
      word = exact;
    }
    t[w] = word;
    cand = next;
    // a full command matched: stop consuming
    for (auto i : cand)
      if (tbl[i].words.size() == w + 1) return std::make_pair(i, w + 1);
  }
  *err = w < t.size() ? "syntax error at '" + t[w] + "'" : "incomplete command";
  return std::nullopt;
}

std::string fmt_time(int64_t t) { return rfc3339(Clock::from_time_t(t), false); }
}  // namespace

std::string apply_pipes(const std::string& out, const std::vector<std::vector<std::string>>& pipes) {
  std::string cur = out;
  for (auto& p : pipes) {
    if (p.size() == 2 && p[0] == "match") {
      std::string o;
      size_t pos = 0;
      while (pos < cur.size()) {
        size_t nl = cur.find('\n', pos);
        if (nl == std::string::npos) nl = cur.size();
        auto line = cur.substr(pos, nl - pos);
        if (line.find(p[1]) != std::string::npos) o += line + "\n";
        pos = nl + 1;
      }
      cur = o;
    } else if (p.size() == 1 && p[0] == "count") {
      cur = "Count: " + std::to_string(std::count(cur.begin(), cur.end(), '\n')) + " lines\n";
    }
  }
  return cur;
}

// ------------------------------------------------------------------ session

CliSession::CliSession(Engine& e, std::string user, std::string via)
    : e_(e), user_(std::move(user)), via_(std::move(via)), id_(e.next_id++) {
  std::lock_guard lk(e_.mu);
  e_.sessions[id_] = user_ + " via " + via_ + " since " + fmt_time(unix_now());
}

CliSession::~CliSession() {
  std::lock_guard lk(e_.mu);
  e_.sessions.erase(id_);
}

std::string CliSession::prompt() const {
  return user_ + "@fw" + (config_mode_ ? "# " : "> ");
}

bool CliSession::allowed(Role have, Role need, const std::string& cmd) {
  if (static_cast<int>(have) >= static_cast<int>(need)) return true;
  if (e_.log)
    e_.log->log(Sev::Warning, "AUTHZ_DENY", user_ + " denied: " + cmd,
                {{"audit@32473", {{"user", user_}, {"via", via_}, {"role", role_name(have)}, {"need", role_name(need)}, {"cmd", cmd}}}});
  return false;
}

std::string CliSession::show_config(const Config& c, std::vector<std::string> t, bool mask) {
  bool as_set = false;
  // `| display set` is a renderer switch, not a text filter
  if (t.size() >= 3 && t[t.size() - 3] == "|" && t[t.size() - 2] == "display" && t.back() == "set") {
    as_set = true;
    t.resize(t.size() - 3);
  }
  std::string sub;
  if (!t.empty()) {
    auto p = parse_path(t, false);
    if (!p.error.empty()) return "error: " + p.error + "\n";
    sub = join(p.key, " ");
  }
  if (as_set) {
    Config part;
    for (auto& [k, v] : c)
      if (key_in_subtree(k, sub)) part[k] = v;
    return to_set_lines(part, mask);
  }
  return to_hierarchical(c, sub, mask);
}

CliSession::Out CliSession::exec(const std::string& raw) {
  std::string terr;
  auto toks = tokenize(raw, &terr);
  if (!toks) return {"error: " + terr + "\n"};
  if (toks->empty()) return {""};
  Role r = e_.role_of(user_);
  if (r == Role::None) return {"error: user " + user_ + " is no longer authorized\n", true};
  // split off output pipes, keeping "| display set" with the command
  std::vector<std::string> t;
  std::vector<std::vector<std::string>> pipes;
  for (size_t i = 0; i < toks->size(); ++i) {
    if ((*toks)[i] == "|" && !(i + 1 < toks->size() && (*toks)[i + 1] == "display")) {
      pipes.emplace_back();
      for (++i; i < toks->size() && (*toks)[i] != "|"; ++i) pipes.back().push_back((*toks)[i]);
      --i;
    } else {
      t.push_back((*toks)[i]);
    }
  }
  if (e_.log && t[0] != "show" && t[0] != "help" && t[0] != "compare")
    e_.log->log(Sev::Info, "CMD", raw, {{"audit@32473", {{"user", user_}, {"via", via_}, {"mode", config_mode_ ? "config" : "op"}}}});
  Out o = config_mode_ ? cfg_command(t, r) : op_command(t, r);
  if (!pipes.empty()) o.text = apply_pipes(o.text, pipes);
  return o;
}

CliSession::Out CliSession::op_command(const std::vector<std::string>& in, Role r) {
  auto t = in;
  std::string err;
  auto m = resolve(op_cmds(), t, &err);
  if (!m) return {"error: " + err + "\n"};
  const Cmd& c = op_cmds()[m->first];
  std::vector<std::string> args(t.begin() + static_cast<long>(m->second), t.end());
  std::string cmd = join(c.words, " ");
  if (!allowed(r, c.role, cmd)) return {"error: permission denied: '" + cmd + "' requires role " + role_name(c.role) + "\n"};

  if (cmd == "exit") return {"", true};
  if (cmd == "help") {
    std::string s;
    for (auto& x : op_cmds())
      if (static_cast<int>(r) >= static_cast<int>(x.role)) {
        auto w = join(x.words, " ");
        s += "  " + w + std::string(w.size() < 34 ? 34 - w.size() : 1, ' ') + x.help + "\n";
      }
    return {s};
  }
  if (cmd == "configure") {
    config_mode_ = true;
    auto [cfg, id] = e_.store->snapshot();
    cand_ = base_cfg_ = cfg;
    base_id_ = id;
    std::string s = "Entering configuration mode (private candidate, base commit " + std::to_string(id) + ")\n";
    if (auto p = e_.store->pending())
      s += "WARNING: commit " + std::to_string(p->commit_id) + " is a commit-confirmed; it rolls back in " +
           std::to_string(p->deadline - unix_now()) + "s unless you 'commit'\n";
    return {s};
  }
  if (cmd == "show configuration") {
    auto [cfg, id] = e_.store->snapshot();
    return {"## commit " + std::to_string(id) + "\n" + show_config(cfg, args, r != Role::Admin)};
  }
  if (cmd == "show commits") {
    std::string s = "  #  commit  time                  user         via            changes  comment\n";
    auto h = e_.store->history();
    char b[512];
    for (size_t i = 0; i < h.size(); ++i) {
      snprintf(b, sizeof b, "%3zu  %6llu  %s  %-12s %-14s %7zu  %s\n", i, static_cast<unsigned long long>(h[i].id),
               fmt_time(h[i].ts).c_str(), h[i].user.c_str(), h[i].via.c_str(), h[i].changes, h[i].comment.c_str());
      s += b;
    }
    if (auto p = e_.store->pending())
      s += "commit " + std::to_string(p->commit_id) + " is pending confirmation; reverts to " + std::to_string(p->revert_to) +
           " in " + std::to_string(p->deadline - unix_now()) + "s\n";
    return {s};
  }
  if (cmd == "show certificate") return {e_.cert ? e_.cert->show() : "certificate manager disabled\n"};
  if (cmd == "show license") return {e_.lic ? e_.lic->show() : "license manager disabled\n"};
  if (cmd == "show users") {
    std::lock_guard lk(e_.mu);
    std::string s;
    for (auto& [id, d] : e_.sessions) s += std::to_string(id) + "  " + d + (id == id_ ? "  (you)" : "") + "\n";
    return {s};
  }
  if (cmd == "show log") {
    size_t n = args.empty() ? 20 : std::strtoul(args[0].c_str(), nullptr, 10);
    std::string s;
    if (e_.log)
      for (auto& l : e_.log->recent(std::min<size_t>(n, 500))) s += l + "\n";
    return {s};
  }
  if (cmd == "show diagnostics") return {e_.diagnostics ? e_.diagnostics() : "\n"};
  if (cmd == "show tech-support") {
    auto [cfg, id] = e_.store->snapshot();
    std::string s = "==== version\n" + e_.version + "\n";
    s += "==== show diagnostics\n" + (e_.diagnostics ? e_.diagnostics() : std::string()) + "\n";
    s += "==== show configuration | display set   (secrets masked)\n" + to_set_lines(cfg, true) + "\n";
    s += "==== show commits\n" + op_command({"show", "commits"}, r).text + "\n";
    s += "==== show certificate\n" + (e_.cert ? e_.cert->show() : std::string()) + "\n";
    s += "==== show license\n" + (e_.lic ? e_.lic->show() : std::string()) + "\n";
    s += "==== show log 100\n";
    if (e_.log)
      for (auto& l : e_.log->recent(100)) s += l + "\n";
    return {s};
  }
  if (cmd == "request certificate renew") {
    if (!e_.cert) return {"certificate manager disabled\n"};
    auto res = e_.cert->renew("manual by " + user_);
    return {res.ok ? "certificate renewed in " + std::to_string(static_cast<int>(res.ms)) + " ms\n" : "error: " + res.error + "\n"};
  }
  if (cmd == "request certificate check-revocation") {
    if (!e_.cert) return {"certificate manager disabled\n"};
    std::string s;
    for (auto& rr : e_.cert->check_revocation_now()) s += rr.method + ": " + rr.status + "  " + rr.detail + "\n";
    return {s};
  }
  if (cmd == "request license reload") {
    if (!e_.lic) return {"license manager disabled\n"};
    e_.lic->reload();
    return {e_.lic->show()};
  }
  return {"error: unhandled\n"};
}

CliSession::Out CliSession::do_commit(const std::vector<std::string>& t) {
  bool check = false;
  int confirm = 0;
  std::string comment;
  for (size_t i = 1; i < t.size(); ++i) {
    if (t[i] == "check") check = true;
    else if (t[i] == "confirmed" && i + 1 < t.size()) {
      confirm = std::atoi(t[++i].c_str());
      if (confirm < 1 || confirm > 86400) return {"error: confirmed <seconds> must be 1..86400\n"};
    } else if (t[i] == "comment" && i + 1 < t.size()) comment = t[++i];
    else return {"error: syntax: commit [check] [confirmed <seconds>] [comment \"text\"]\n"};
  }
  auto r = e_.store->commit(cand_, base_id_, {user_, via_}, comment, confirm, check);
  std::string s;
  for (auto& w : r.warnings) s += "warning: " + w + "\n";
  if (!r.ok) return {s + "error: commit failed: " + r.error + "\n"};
  if (check) return {s + "configuration check succeeds\n"};
  base_id_ = r.id;
  base_cfg_ = cand_;
  if (confirm) s += "commit confirmed will be automatically rolled back in " + std::to_string(confirm) + "s unless confirmed\n";
  char b[160];
  snprintf(b, sizeof b, "commit complete (commit %llu, %zu changes, %.0f us)\n", static_cast<unsigned long long>(r.id),
           r.diff.size(), r.us_total);
  return {s + b};
}

CliSession::Out CliSession::cfg_command(const std::vector<std::string>& in, Role r) {
  auto t = in;
  std::string err;
  auto m = resolve(cfg_cmds(), t, &err);
  if (!m) return {"error: " + err + "\n"};
  const Cmd& c = cfg_cmds()[m->first];
  std::vector<std::string> args(t.begin() + 1, t.end());
  const std::string& cmd = c.words[0];
  if (!allowed(r, c.role, cmd)) {
    config_mode_ = false;  // demoted while in configure mode
    return {"error: permission denied; leaving configuration mode\n"};
  }
  if (cmd == "set") {
    auto e = config_set(cand_, args);
    return {e.empty() ? "" : "error: " + e + "\n"};
  }
  if (cmd == "delete") {
    auto e = config_delete(cand_, args);
    return {e.empty() ? "" : "warning: " + e + "\n"};
  }
  if (cmd == "show") return {show_config(cand_, args, false)};
  if (cmd == "compare") {
    if (args.size() == 2 && args[0] == "rollback") {
      auto old = e_.store->rollback_config(std::strtoul(args[1].c_str(), nullptr, 10));
      if (!old) return {"error: no such rollback\n"};
      return {render_diff(diff(*old, cand_))};
    }
    auto [run, id] = e_.store->snapshot();
    auto d = render_diff(diff(run, cand_));
    return {d.empty() ? "no differences\n" : d};
  }
  if (cmd == "commit") return do_commit(t);
  if (cmd == "rollback") {
    size_t n = args.empty() ? 0 : std::strtoul(args[0].c_str(), nullptr, 10);
    auto old = e_.store->rollback_config(n);
    if (!old) return {"error: rollback " + std::to_string(n) + " does not exist\n"};
    cand_ = *old;
    return {"load complete (rollback " + std::to_string(n) + " in candidate; 'commit' to activate)\n"};
  }
  if (cmd == "discard") {
    cand_ = base_cfg_;
    return {"candidate discarded\n"};
  }
  if (cmd == "update") {
    auto mine = diff(base_cfg_, cand_);
    auto [run, id] = e_.store->snapshot();
    Config next = run;
    for (auto& ch : mine) {
      if (ch.kind == Change::Delete) next.erase(ch.key);
      else next[ch.key] = ch.new_value;
    }
    cand_ = next;
    base_cfg_ = run;
    base_id_ = id;
    return {"candidate rebased on commit " + std::to_string(id) + " (" + std::to_string(mine.size()) + " of your changes re-applied)\n"};
  }
  if (cmd == "run") {
    auto o = op_command(args, r);
    o.exit = false;
    return o;
  }
  if (cmd == "exit") {
    if (!diff(base_cfg_, cand_).empty() && !(args.size() == 1 && args[0] == "discard"))
      return {"error: uncommitted changes; 'commit', or 'exit discard' to drop them\n"};
    config_mode_ = false;
    return {"Exiting configuration mode\n"};
  }
  if (cmd == "help") {
    std::string s;
    for (auto& x : cfg_cmds()) s += "  " + x.words[0] + std::string(12 - x.words[0].size(), ' ') + x.help + "\n";
    return {s};
  }
  return {"error: unhandled\n"};
}

std::vector<std::string> CliSession::complete(const std::string& line) const {
  std::string terr;
  auto tk = tokenize(line, &terr);
  if (!tk) return {};
  std::vector<std::string> t = *tk;
  std::string partial;
  if (!line.empty() && line.back() != ' ' && !t.empty()) {
    partial = t.back();
    t.pop_back();
  }
  Role r = e_.role_of(user_);
  std::vector<std::string> cands;
  auto from_table = [&](const std::vector<Cmd>& tbl, const std::vector<std::string>& words) {
    for (auto& c : tbl) {
      if (static_cast<int>(r) < static_cast<int>(c.role) || c.words.size() <= words.size()) continue;
      bool ok = true;
      for (size_t i = 0; i < words.size() && ok; ++i) ok = c.words[i] == words[i];
      if (ok && std::find(cands.begin(), cands.end(), c.words[words.size()]) == cands.end())
        cands.push_back(c.words[words.size()]);
    }
  };
  auto op_complete = [&](const std::vector<std::string>& w) {
    if (w.size() >= 2 && w[0] == "show" && w[1] == "configuration") {
      auto [run, id] = e_.store->snapshot();
      cands = complete_path({w.begin() + 2, w.end()}, run);
    } else {
      from_table(op_cmds(), w);
    }
  };
  if (config_mode_) {
    if (t.empty()) from_table(cfg_cmds(), t);
    else if (t[0] == "set" || t[0] == "delete" || t[0] == "show") cands = complete_path({t.begin() + 1, t.end()}, cand_);
    else if (t[0] == "run") op_complete({t.begin() + 1, t.end()});
    else if (t[0] == "commit") cands = {"check", "confirmed", "comment"};
  } else {
    op_complete(t);
  }
  std::vector<std::string> out;
  for (auto& c : cands) {
    if (c.empty()) continue;
    if (c[0] == '<') {
      if (partial.empty()) out.push_back(c);  // placeholder: help only
    } else if (starts_with(c, partial)) {
      out.push_back(c);
    }
  }
  return out;
}

}  // namespace fw
