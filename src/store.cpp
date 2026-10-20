#include "store.hpp"

#include <dirent.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>

#include "schema.hpp"
#include "syslog.hpp"
#include "util.hpp"

namespace fw {

using json = nlohmann::json;

// {"firewall url-filter", "url-filtering"}, ... computed once from the schema.
// (Features are attached to containers, so a prefix is enough.)
static const std::vector<std::pair<std::string, std::string>>& licensed_prefixes() {
  static const auto v = [] {
    std::vector<std::pair<std::string, std::string>> out;
    std::function<void(const Node&, const std::string&)> walk = [&](const Node& n, const std::string& path) {
      for (auto& ch : n.children) {
        if (ch.kind == Node::Leaf) continue;
        std::string p = path.empty() ? ch.name : path + " " + ch.name;
        if (!ch.feature.empty()) out.emplace_back(p, ch.feature);
        else if (ch.kind == Node::Container) walk(ch, p);
      }
    };
    walk(schema_root(), "");
    return out;
  }();
  return v;
}

ConfigStore::ConfigStore(std::string dir, Syslog* log, FeatureCheck fc)
    : dir_(std::move(dir)), log_(log), features_(std::move(fc)) {
  mkdirs(dir_ + "/commits");
}

std::string ConfigStore::path_for(uint64_t id) const {
  char b[32];
  snprintf(b, sizeof b, "%010llu", static_cast<unsigned long long>(id));
  return dir_ + "/commits/" + b + ".conf";
}

static std::string serialize_commit(const CommitInfo& ci, const Config& c) {
  json meta = {{"id", ci.id}, {"ts", ci.ts}, {"user", ci.user}, {"via", ci.via},
               {"comment", ci.comment}, {"changes", ci.changes}};
  return "#@ " + meta.dump() + "\n" + to_set_lines(c);
}

static std::optional<std::pair<CommitInfo, Config>> load_commit(const std::string& path) {
  auto text = read_file(path);
  if (!text || !starts_with(*text, "#@ ")) return std::nullopt;
  auto nl = text->find('\n');
  CommitInfo ci;
  try {
    auto m = json::parse(text->substr(3, nl - 3));
    ci.id = m["id"];
    ci.ts = m["ts"];
    ci.user = m["user"];
    ci.via = m["via"];
    ci.comment = m["comment"];
    ci.changes = m["changes"];
  } catch (...) {
    return std::nullopt;
  }
  std::string err;
  auto c = parse_config(text->substr(nl + 1), &err);
  if (!c) return std::nullopt;
  return std::make_pair(ci, std::move(*c));
}

void ConfigStore::scan_history_locked() {
  history_.clear();
  DIR* d = opendir((dir_ + "/commits").c_str());
  if (!d) return;
  std::vector<uint64_t> ids;
  while (auto* e = readdir(d)) {
    std::string n = e->d_name;
    if (n.size() == 15 && n.compare(10, 5, ".conf") == 0) ids.push_back(std::stoull(n.substr(0, 10)));
    else if (n.size() > 4 && n.compare(n.size() - 4, 4, ".tmp") == 0)
      ::unlink((dir_ + "/commits/" + n).c_str());  // leftover of a crash mid-write
  }
  closedir(d);
  std::sort(ids.rbegin(), ids.rend());
  for (auto id : ids)
    if (auto lc = load_commit(path_for(id))) history_.push_back(lc->first);
}

void ConfigStore::open(const Config& bootstrap) {
  std::lock_guard lk(commit_mu_);
  scan_history_locked();
  if (history_.empty()) {
    CommitInfo ci{1, unix_now(), "system", "bootstrap", "initial configuration", bootstrap.size()};
    atomic_write(path_for(1), serialize_commit(ci, bootstrap));
    history_.push_back(ci);
  }
  auto lc = load_commit(path_for(history_.front().id));
  if (!lc) throw std::runtime_error("cannot load newest commit");
  {
    std::unique_lock w(run_mu_);
    running_ = std::move(lc->second);
    running_id_ = lc->first.id;
  }
  // a commit-confirmed that never got confirmed survives a crash/restart
  if (auto p = read_file(dir_ + "/confirm-pending")) {
    PendingConfirm pc;
    if (sscanf(p->c_str(), "%lu %lu %ld", &pc.commit_id, &pc.revert_to, &pc.deadline) == 3 &&
        pc.commit_id == running_id_) {
      pending_ = pc;
      if (log_) log_->log(Sev::Warning, "CONFIRM_PENDING", "commit confirmed pending across restart, revert at deadline");
    } else {
      ::unlink((dir_ + "/confirm-pending").c_str());
    }
  }
}

std::pair<Config, uint64_t> ConfigStore::snapshot() const {
  std::shared_lock r(run_mu_);
  return {running_, running_id_};
}

uint64_t ConfigStore::running_id() const {
  std::shared_lock r(run_mu_);
  return running_id_;
}

std::string ConfigStore::validate(const Config& c, const std::vector<Change>& d,
                                  std::vector<std::string>* warnings) const {
  // 1. schema: only what changed. The rest is the running config, which was
  //    validated when it was committed; re-parsing all N keys made validation
  //    O(N) parse_path calls (10 ms at 10k leaves) for a one-leaf change.
  for (auto& ch : d) {
    if (ch.kind == Change::Delete) continue;
    auto toks = split_ws(ch.key);
    toks.push_back(ch.new_value);
    auto p = parse_path(toks, true);
    if (!p.error.empty()) return "invalid statement '" + ch.key + "': " + p.error;
  }
  // 2. licensing: changing a licensed subtree needs the feature; existing
  //    licensed config only warns (an expired license must not block every commit)
  for (auto& [prefix, feat] : licensed_prefixes()) {
    if (features_ && features_(feat)) continue;
    for (auto& ch : d)
      if (ch.kind != Change::Delete && key_in_subtree(ch.key, prefix))
        return "feature '" + feat + "' is not licensed; cannot configure '" + ch.key + "'";
    auto it = c.lower_bound(prefix);
    if (warnings && it != c.end() && key_in_subtree(it->first, prefix))
      warnings->push_back("feature '" + feat + "' is not licensed; existing configuration is inactive");
  }
  // 3. cross-field rules
  std::set<std::string> rules, rules_with_action, users, cats, cats_with_action;
  bool admin_with_key = false;
  std::map<std::string, std::pair<bool, bool>> userinfo;  // role==admin, has key
  for (auto& [k, v] : c) {
    auto t = split_ws(k);
    if (t.size() == 4 && t[0] == "firewall" && t[1] == "rule") {
      rules.insert(t[2]);
      if (t[3] == "action") rules_with_action.insert(t[2]);
    }
    if (t.size() == 5 && t[0] == "firewall" && t[2] == "category") {
      cats.insert(t[3]);
      if (t[4] == "action") cats_with_action.insert(t[3]);
    }
    if (t.size() == 5 && t[0] == "system" && t[1] == "login" && t[2] == "user") {
      users.insert(t[3]);
      if (t[4] == "role" && v == "admin") userinfo[t[3]].first = true;
      if (t[4] == "role") userinfo[t[3]];
      if (t[4] == "ssh-key") userinfo[t[3]].second = true;
    }
  }
  for (auto& r : rules)
    if (!rules_with_action.count(r)) return "firewall rule " + r + ": 'action' is mandatory";
  for (auto& cname : cats)
    if (!cats_with_action.count(cname)) return "url-filter category " + cname + ": 'action' is mandatory";
  for (auto& u : users) {
    auto it = userinfo.find(u);
    if (it == userinfo.end()) return "user " + u + ": 'role' is mandatory";
    if (it->second.first && it->second.second) admin_with_key = true;
  }
  if (!admin_with_key) return "commit would lock out all administrators: need at least one admin user with an ssh-key";
  if (c.count("system syslog port") && !c.count("system syslog server")) return "system syslog port requires system syslog server";
  auto sp = c.find("system services ssh port"), hp = c.find("system services https port");
  if (sp != c.end() && hp != c.end() && sp->second == hp->second) return "ssh and https cannot share a port";
  return "";
}

CommitResult ConfigStore::commit(const Config& cand, uint64_t base_id, const Who& who, const std::string& comment,
                                 int confirm_seconds, bool check_only) {
  std::lock_guard lk(commit_mu_);
  if (base_id != running_id_) {
    CommitResult r;
    r.error = "configuration changed by another session since you started editing (base " + std::to_string(base_id) +
              ", running " + std::to_string(running_id_) + "); re-apply your changes on top of the new running config";
    return r;
  }
  return commit_locked(cand, who, comment, confirm_seconds, check_only);
}

CommitResult ConfigStore::commit_locked(const Config& cand, const Who& who, const std::string& comment,
                                        int confirm_seconds, bool check_only) {
  CommitResult r;
  double t0 = mono_us();
  r.diff = diff(running_, cand);
  if (auto e = validate(cand, r.diff, &r.warnings); !e.empty()) {
    r.error = e;
    return r;
  }
  for (auto* s : subs_) {
    bool hit = std::any_of(r.diff.begin(), r.diff.end(), [&](const Change& ch) {
      for (auto& p : s->prefixes())
        if (key_in_subtree(ch.key, p)) return true;
      return false;
    });
    if (!hit) continue;
    if (auto e = s->validate(cand, r.diff); !e.empty()) {
      r.error = s->name() + ": " + e;
      return r;
    }
  }
  double t1 = mono_us();
  r.us_validate = t1 - t0;
  if (check_only) {
    r.ok = true;
    r.us_total = t1 - t0;
    return r;
  }
  // a normal commit while a commit-confirmed is pending confirms it (Junos semantics)
  bool was_pending = pending_.has_value();
  if (r.diff.empty() && confirm_seconds == 0) {
    r.ok = true;
    r.id = running_id_;
    if (was_pending) {
      pending_.reset();
      persist_pending_locked();
      r.warnings.push_back("commit confirmed: will not be rolled back");
      if (log_)
        log_->log(Sev::Notice, "COMMIT_CONFIRMED", "commit " + std::to_string(running_id_) + " confirmed by " + who.user,
                  {{"audit@32473", {{"user", who.user}, {"via", who.via}, {"commit", std::to_string(running_id_)}}}});
    } else {
      r.warnings.push_back("no changes to commit");
    }
    r.us_total = mono_us() - t0;
    return r;
  }
  CommitInfo ci{running_id_ + 1, unix_now(), who.user, who.via, comment, r.diff.size()};
  for (auto& ch : ci.comment)
    if (ch == '\n' || ch == '\r') ch = ' ';
  atomic_write(path_for(ci.id), serialize_commit(ci, cand));  // <- the durability point
  uint64_t prev = running_id_;
  {
    std::unique_lock w(run_mu_);
    running_ = cand;
    running_id_ = ci.id;
  }
  history_.insert(history_.begin(), ci);
  if (confirm_seconds > 0) {
    // keep the original revert target if a confirmed commit is stacked on a pending one
    uint64_t revert_to = was_pending ? pending_->revert_to : prev;
    pending_ = PendingConfirm{ci.id, revert_to, unix_now() + confirm_seconds};
  } else {
    pending_.reset();
  }
  persist_pending_locked();
  double t2 = mono_us();
  r.us_persist = t2 - t1;
  for (auto* s : subs_) {
    bool hit = std::any_of(r.diff.begin(), r.diff.end(), [&](const Change& ch) {
      for (auto& p : s->prefixes())
        if (key_in_subtree(ch.key, p)) return true;
      return false;
    });
    if (hit) s->apply(running_, r.diff);
  }
  r.us_apply = mono_us() - t2;
  // prune beyond the retention window; harmless if we crash halfway
  while (history_.size() > kRetain) {
    ::unlink(path_for(history_.back().id).c_str());
    history_.pop_back();
  }
  if (log_) {
    log_->log(Sev::Notice, "COMMIT",
              "commit " + std::to_string(ci.id) + " by " + who.user + (confirm_seconds ? " (confirmed, pending)" : ""),
              {{"audit@32473",
                {{"user", who.user}, {"via", who.via}, {"commit", std::to_string(ci.id)},
                 {"changes", std::to_string(r.diff.size())}, {"comment", ci.comment}}}});
    size_t n = 0;
    for (auto& ch : r.diff) {
      if (++n > 100) {
        log_->log(Sev::Info, "CONFIG_CHANGE", std::to_string(r.diff.size() - 100) + " more changes not logged individually");
        break;
      }
      bool sec = key_is_secret(ch.key);
      const char* op = ch.kind == Change::Add ? "add" : ch.kind == Change::Delete ? "delete" : "modify";
      log_->log(Sev::Info, "CONFIG_CHANGE", std::string(op) + " " + ch.key,
                {{"audit@32473",
                  {{"user", who.user}, {"commit", std::to_string(ci.id)}, {"op", op}, {"key", ch.key},
                   {"old", sec ? "<masked>" : ch.old_value}, {"new", sec ? "<masked>" : ch.new_value}}}});
    }
  }
  r.ok = true;
  r.id = ci.id;
  r.us_total = mono_us() - t0;
  return r;
}

CommitResult ConfigStore::confirm(const Who& who) {
  std::lock_guard lk(commit_mu_);
  CommitResult r;
  if (!pending_) {
    r.error = "no commit confirmed is pending";
    return r;
  }
  pending_.reset();
  persist_pending_locked();
  if (log_)
    log_->log(Sev::Notice, "COMMIT_CONFIRMED", "commit " + std::to_string(running_id_) + " confirmed by " + who.user,
              {{"audit@32473", {{"user", who.user}, {"via", who.via}, {"commit", std::to_string(running_id_)}}}});
  r.ok = true;
  r.id = running_id_;
  return r;
}

void ConfigStore::persist_pending_locked() {
  std::string p = dir_ + "/confirm-pending";
  if (pending_) {
    char b[96];
    snprintf(b, sizeof b, "%lu %lu %ld\n", pending_->commit_id, pending_->revert_to, pending_->deadline);
    atomic_write(p, b);
  } else {
    ::unlink(p.c_str());
  }
}

void ConfigStore::revert_locked(const char* why) {
  auto target = pending_->revert_to;
  auto lc = load_commit(path_for(target));
  pending_.reset();
  persist_pending_locked();
  if (!lc) {
    if (log_) log_->log(Sev::Err, "CONFIRM_REVERT", "revert target missing");
    return;
  }
  auto r = commit_locked(lc->second, {"system", "confirm-timer"}, std::string(why) + ": rolled back to commit " + std::to_string(target), 0, false);
  if (log_)
    log_->log(r.ok ? Sev::Warning : Sev::Err, "CONFIRM_REVERT",
              r.ok ? "commit confirmed not confirmed in time; reverted to commit " + std::to_string(target) : "revert failed: " + r.error);
}

void ConfigStore::tick() {
  std::lock_guard lk(commit_mu_);
  if (pending_ && unix_now() >= pending_->deadline) revert_locked("commit confirmed timeout");
}

std::optional<Config> ConfigStore::rollback_config(size_t n) const {
  std::lock_guard lk(commit_mu_);
  if (n >= history_.size()) return std::nullopt;
  auto lc = load_commit(path_for(history_[n].id));
  if (!lc) return std::nullopt;
  return std::move(lc->second);
}

std::vector<CommitInfo> ConfigStore::history() const {
  std::lock_guard lk(commit_mu_);
  return history_;
}

std::optional<PendingConfirm> ConfigStore::pending() const {
  std::lock_guard lk(commit_mu_);
  return pending_;
}

void ConfigStore::subscribe(Subscriber* s) {
  std::lock_guard lk(commit_mu_);
  subs_.push_back(s);
}

void ConfigStore::apply_all() {
  std::lock_guard lk(commit_mu_);
  auto d = diff({}, running_);
  for (auto* s : subs_) s->apply(running_, d);
}

}  // namespace fw
