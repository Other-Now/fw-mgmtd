// Hierarchical CLI (operational ">" and configuration "#" modes), RBAC, and
// completion. Pure logic: no sockets here, so the same engine is driven by the
// SSH server, the REST API's /cli endpoint, the tests and the fuzzer.
#pragma once
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "config.hpp"
#include "license.hpp"

namespace fw {

class ConfigStore;
class Syslog;
class CertManager;

enum class Role { None = -1, Viewer = 0, Operator = 1, Admin = 2 };
const char* role_name(Role r);
Role role_from(const std::string& s);

class LicenseManager {
 public:
  LicenseManager(std::string license_path, std::string pubkey_path, std::string clock_path, std::string device_id,
                 Syslog* log);
  void reload();
  LicenseStatus status();
  bool feature(const std::string& f) { return status().feature(f); }
  void tick();  // clock high-water mark + state-change alerts
  std::string show();

 private:
  std::mutex mu_;
  std::string lic_path_, pub_path_, device_id_, load_error_;
  ClockGuard clock_;
  Syslog* log_;
  std::optional<License> lic_;
  LicState last_state_ = LicState::None;
};

struct Engine {
  ConfigStore* store = nullptr;
  Syslog* log = nullptr;
  CertManager* cert = nullptr;
  LicenseManager* lic = nullptr;
  std::function<std::string()> diagnostics;  // filled in by the daemon
  std::string version = "fw-mgmtd 1.0";

  // live sessions for `show users`
  std::mutex mu;
  std::map<int, std::string> sessions;
  std::atomic<int> next_id{1};

  Role role_of(const std::string& user) const;  // looked up in the running config each time
};

class CliSession {
 public:
  CliSession(Engine& e, std::string user, std::string via);
  ~CliSession();

  struct Out {
    std::string text;
    bool exit = false;
  };
  Out exec(const std::string& line);
  std::string prompt() const;
  // Completion candidates for the word under the cursor (the last token of
  // `line`, or a new empty word if `line` ends with a space).
  std::vector<std::string> complete(const std::string& line) const;
  bool in_config() const { return config_mode_; }

 private:
  Out op_command(const std::vector<std::string>& t, Role r);
  Out cfg_command(const std::vector<std::string>& t, Role r);
  Out do_commit(const std::vector<std::string>& t);
  std::string show_config(const Config& c, std::vector<std::string> t, bool mask);
  bool allowed(Role have, Role need, const std::string& cmd);

  Engine& e_;
  std::string user_, via_;
  int id_;
  bool config_mode_ = false;
  Config cand_, base_cfg_;
  uint64_t base_id_ = 0;
};

// Applies `| match X` / `| count` / `| display set` style output filters.
std::string apply_pipes(const std::string& out, const std::vector<std::vector<std::string>>& pipes);

}  // namespace fw
