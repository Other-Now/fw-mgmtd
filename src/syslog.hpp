// RFC 5424 syslog: formatter + sinks (local file, UDP collector, in-memory ring
// for `show log`). Audit events are ordinary messages with an [audit@32473 ...]
// structured-data element, so a SIEM can filter on it.
#pragma once
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace fw {

enum class Sev { Emerg = 0, Alert, Crit, Err, Warning, Notice, Info, Debug };

struct SdElement {
  std::string id;  // e.g. "audit@32473" (32473 is the IANA example enterprise number)
  std::vector<std::pair<std::string, std::string>> params;
};

std::string rfc5424_format(int facility, Sev sev, const std::string& timestamp, const std::string& host,
                           const std::string& app, int pid, const std::string& msgid,
                           const std::vector<SdElement>& sd, const std::string& msg);
std::string sd_escape(const std::string& v);

class Syslog {
 public:
  explicit Syslog(std::string local_path);
  ~Syslog();
  void log(Sev sev, const std::string& msgid, const std::string& msg, const std::vector<SdElement>& sd = {});
  // Called by the config subscriber; empty server disables the UDP sink.
  void set_remote(const std::string& server, int port);
  void set_hostname(const std::string& h);
  void set_facility(int f);
  std::vector<std::string> recent(size_t n) const;
  uint64_t sent_udp() const { return sent_udp_; }

 private:
  mutable std::mutex mu_;
  std::string path_, host_ = "fw-mgmtd";
  int facility_ = 16;  // local0
  int fd_file_ = -1, fd_udp_ = -1;
  std::string remote_;
  int remote_port_ = 514;
  std::deque<std::string> ring_;
  uint64_t sent_udp_ = 0;
};

}  // namespace fw
