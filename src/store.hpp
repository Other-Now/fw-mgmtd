// Transactional configuration store: candidate -> validate -> durable commit ->
// notify subscribers. Every commit is a separate immutable file
// commits/<id>.conf written with atomic_write(), so "rollback N" is just
// "load the file N commits back", and a crash can never leave a torn running
// config.
#pragma once
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "config.hpp"

namespace fw {

class Syslog;

struct Who {
  std::string user, via;  // via: "ssh", "api", "system", "test"
};

struct CommitInfo {
  uint64_t id = 0;
  int64_t ts = 0;
  std::string user, via, comment;
  size_t changes = 0;
};

struct CommitResult {
  bool ok = false;
  std::string error;
  std::vector<std::string> warnings;
  uint64_t id = 0;
  std::vector<Change> diff;
  double us_validate = 0, us_persist = 0, us_apply = 0, us_total = 0;
};

struct PendingConfirm {
  uint64_t commit_id = 0, revert_to = 0;
  int64_t deadline = 0;  // unix seconds
};

// Services implement this to take config changes live, without a restart.
// validate() runs before anything is written and may veto the commit;
// apply() runs after the commit is durable.
class Subscriber {
 public:
  virtual ~Subscriber() = default;
  virtual std::string name() const = 0;
  virtual std::vector<std::string> prefixes() const = 0;
  virtual std::string validate(const Config&, const std::vector<Change>&) { return ""; }
  virtual void apply(const Config&, const std::vector<Change>&) = 0;
};

class ConfigStore {
 public:
  using FeatureCheck = std::function<bool(const std::string& feature)>;
  static constexpr size_t kRetain = 50;  // rollback 0..49

  ConfigStore(std::string dir, Syslog* log, FeatureCheck fc = nullptr);

  // Loads the newest commit from disk, or writes `bootstrap` as commit 1.
  // Also honours a commit-confirmed that was pending when we crashed.
  void open(const Config& bootstrap);

  std::pair<Config, uint64_t> snapshot() const;
  uint64_t running_id() const;

  // Schema is already enforced by parse_path; this is cross-field + licensing.
  std::string validate(const Config& c, const std::vector<Change>& d, std::vector<std::string>* warnings) const;

  // base_id: the running id the candidate was derived from. If running moved
  // on since then, the commit is refused (optimistic concurrency) -- two
  // sessions can never silently overwrite each other.
  CommitResult commit(const Config& cand, uint64_t base_id, const Who& who, const std::string& comment,
                      int confirm_seconds = 0, bool check_only = false);
  CommitResult confirm(const Who& who);

  std::optional<Config> rollback_config(size_t n) const;
  std::vector<CommitInfo> history() const;
  std::optional<PendingConfirm> pending() const;

  void tick();  // reverts an expired commit-confirmed
  void subscribe(Subscriber* s);
  void apply_all();  // push the full running config to every subscriber (startup)
  void set_feature_check(FeatureCheck fc) { features_ = std::move(fc); }

 private:
  std::string path_for(uint64_t id) const;
  CommitResult commit_locked(const Config& cand, const Who& who, const std::string& comment, int confirm_seconds,
                             bool check_only);
  void persist_pending_locked();
  void scan_history_locked();
  void revert_locked(const char* why);

  std::string dir_;
  Syslog* log_;
  FeatureCheck features_;
  mutable std::mutex commit_mu_;      // serializes commits
  mutable std::shared_mutex run_mu_;  // guards running_/running_id_
  Config running_;
  uint64_t running_id_ = 0;
  std::vector<CommitInfo> history_;   // newest first
  std::optional<PendingConfirm> pending_;
  std::vector<Subscriber*> subs_;
};

}  // namespace fw
