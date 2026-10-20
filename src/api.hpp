// REST API over HTTPS. Every write goes through the same ConfigStore::commit()
// and the same schema parser as the CLI; /api/v1/cli runs operational
// commands through a CliSession -- so the CLI and the API cannot disagree.
#pragma once
#include "http.hpp"
#include "store.hpp"

namespace fw {

struct Engine;

HttpResponse api_handle(Engine& e, const HttpRequest& req);

// Subscriber that moves the HTTPS listener when its port changes.
class HttpsService : public Subscriber {
 public:
  HttpsService(HttpServer& s, Syslog* log, std::string addr) : srv_(s), log_(log), addr_(std::move(addr)) {}
  std::string name() const override { return "https"; }
  std::vector<std::string> prefixes() const override { return {"system services https"}; }
  void apply(const Config& c, const std::vector<Change>&) override;

 private:
  HttpServer& srv_;
  Syslog* log_;
  std::string addr_;
};

// Subscriber that re-points the syslog sinks.
class SyslogService : public Subscriber {
 public:
  explicit SyslogService(Syslog* log) : log_(log) {}
  std::string name() const override { return "syslog"; }
  std::vector<std::string> prefixes() const override { return {"system syslog", "system hostname"}; }
  void apply(const Config& c, const std::vector<Change>&) override;

 private:
  Syslog* log_;
};

// Stand-in for the dataplane: compiles the rule list and reports what changed.
class FirewallService : public Subscriber {
 public:
  explicit FirewallService(Syslog* log) : log_(log) {}
  std::string name() const override { return "firewall"; }
  std::vector<std::string> prefixes() const override { return {"firewall"}; }
  void apply(const Config& c, const std::vector<Change>& d) override;
  size_t rules() const { return rules_; }
  uint64_t applies() const { return applies_; }

 private:
  Syslog* log_;
  std::atomic<size_t> rules_{0};
  std::atomic<uint64_t> applies_{0};
};

}  // namespace fw
