// Embedded libssh server: public-key auth against the keys in the running
// config (system login user X ssh-key), then either an interactive shell
// (line editor + CliSession) or a one-shot exec ("ssh fw 'show license'").
#pragma once
#include <atomic>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "store.hpp"

namespace fw {

struct Engine;

class SshServer : public Subscriber {
 public:
  SshServer(Engine& e, std::string hostkey_path, std::string addr);
  ~SshServer() override;
  bool listen(int port, std::string* err);
  void start();
  void stop();
  int port() const { return port_; }

  std::string name() const override { return "ssh"; }
  std::vector<std::string> prefixes() const override { return {"system services ssh"}; }
  std::string validate(const Config& c, const std::vector<Change>&) override;
  void apply(const Config& c, const std::vector<Change>&) override;

  std::atomic<uint64_t> auth_ok{0}, auth_fail{0}, sessions_total{0};
  std::atomic<int> active{0};

 private:
  void accept_loop();
  void handle(int fd, std::string peer);

  Engine& e_;
  std::string hostkey_, addr_;
  std::atomic<int> listen_fd_{-1}, port_{0}, idle_timeout_{900};
  std::atomic<bool> running_{false};
  std::mutex fds_mu_;
  std::set<int> fds_;
  std::thread th_;
};

}  // namespace fw
