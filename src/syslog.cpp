#include "syslog.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util.hpp"

namespace fw {

std::string sd_escape(const std::string& v) {
  // RFC 5424 6.3.3: '"', '\' and ']' MUST be escaped inside PARAM-VALUE
  std::string o;
  for (char c : v) {
    if (c == '"' || c == '\\' || c == ']') o += '\\';
    o += c;
  }
  return o;
}

static std::string nil_or(const std::string& s, size_t maxlen) {
  // header fields are PRINTUSASCII, no spaces; "-" is NILVALUE
  if (s.empty()) return "-";
  std::string o;
  for (char c : s)
    if (c > 32 && c < 127) o += c;
  if (o.size() > maxlen) o.resize(maxlen);
  return o.empty() ? "-" : o;
}

std::string rfc5424_format(int facility, Sev sev, const std::string& ts, const std::string& host,
                           const std::string& app, int pid, const std::string& msgid,
                           const std::vector<SdElement>& sd, const std::string& msg) {
  std::string out = "<" + std::to_string(facility * 8 + static_cast<int>(sev)) + ">1 ";
  out += ts + " " + nil_or(host, 255) + " " + nil_or(app, 48) + " " + std::to_string(pid) + " " +
         nil_or(msgid, 32) + " ";
  if (sd.empty()) {
    out += "-";
  } else {
    for (auto& e : sd) {
      out += "[" + e.id;
      for (auto& [k, v] : e.params) out += " " + k + "=\"" + sd_escape(v) + "\"";
      out += "]";
    }
  }
  if (!msg.empty()) {
    out += " ";
    for (char c : msg) out += (c == '\n' || c == '\r') ? ' ' : c;  // keep one record per line
  }
  return out;
}

Syslog::Syslog(std::string local_path) : path_(std::move(local_path)) {
  if (!path_.empty()) fd_file_ = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
  fd_udp_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
}

Syslog::~Syslog() {
  if (fd_file_ >= 0) ::close(fd_file_);
  if (fd_udp_ >= 0) ::close(fd_udp_);
}

void Syslog::log(Sev sev, const std::string& msgid, const std::string& msg, const std::vector<SdElement>& sd) {
  std::lock_guard lk(mu_);
  std::string line = rfc5424_format(facility_, sev, rfc3339(Clock::now()), host_, "fw-mgmtd", getpid(), msgid, sd, msg);
  if (fd_file_ >= 0) {
    std::string l = line + "\n";
    (void)!::write(fd_file_, l.data(), l.size());
  }
  if (!remote_.empty() && fd_udp_ >= 0) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(static_cast<uint16_t>(remote_port_));
    inet_pton(AF_INET, remote_.c_str(), &sa.sin_addr);
    if (::sendto(fd_udp_, line.data(), line.size(), 0, reinterpret_cast<sockaddr*>(&sa), sizeof sa) > 0) ++sent_udp_;
  }
  ring_.push_back(std::move(line));
  if (ring_.size() > 500) ring_.pop_front();
}

void Syslog::set_remote(const std::string& server, int port) {
  std::lock_guard lk(mu_);
  remote_ = server;
  remote_port_ = port ? port : 514;
}
void Syslog::set_hostname(const std::string& h) {
  std::lock_guard lk(mu_);
  host_ = h.empty() ? "fw-mgmtd" : h;
}
void Syslog::set_facility(int f) {
  std::lock_guard lk(mu_);
  facility_ = f;
}

std::vector<std::string> Syslog::recent(size_t n) const {
  std::lock_guard lk(mu_);
  size_t start = ring_.size() > n ? ring_.size() - n : 0;
  return {ring_.begin() + static_cast<long>(start), ring_.end()};
}

}  // namespace fw
