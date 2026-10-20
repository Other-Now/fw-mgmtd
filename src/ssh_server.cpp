#include "ssh_server.hpp"

#include <arpa/inet.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "cli.hpp"
#include "lineedit.hpp"
#include "syslog.hpp"
#include "util.hpp"

namespace fw {

SshServer::SshServer(Engine& e, std::string hostkey_path, std::string addr)
    : e_(e), hostkey_(std::move(hostkey_path)), addr_(std::move(addr)) {
  ssh_init();
  if (!file_exists(hostkey_)) {
    ssh_key k = nullptr;
    if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &k) == SSH_OK) {
      ssh_pki_export_privkey_file(k, nullptr, nullptr, nullptr, hostkey_.c_str());
      ssh_key_free(k);
    }
  }
}

SshServer::~SshServer() { stop(); }

bool SshServer::listen(int port, std::string* err) {
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  inet_pton(AF_INET, addr_.c_str(), &sa.sin_addr);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0 || ::listen(fd, 128) != 0) {
    if (err) *err = std::string("ssh bind: ") + strerror(errno);
    ::close(fd);
    return false;
  }
  socklen_t sl = sizeof sa;
  getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
  int old = listen_fd_.exchange(fd);
  port_ = ntohs(sa.sin_port);
  if (old >= 0) ::close(old);
  return true;
}

void SshServer::start() {
  running_ = true;
  th_ = std::thread([this] { accept_loop(); });
}

void SshServer::stop() {
  if (!running_.exchange(false)) return;
  if (th_.joinable()) th_.join();
  int fd = listen_fd_.exchange(-1);
  if (fd >= 0) ::close(fd);
  {
    std::lock_guard lk(fds_mu_);
    for (int c : fds_) ::shutdown(c, SHUT_RDWR);  // libssh owns the fd; just wake its reads
  }
  for (int i = 0; i < 500 && active > 0; ++i) usleep(10000);
}

std::string SshServer::validate(const Config& c, const std::vector<Change>&) {
  auto it = c.find("system services ssh port");
  int want = it == c.end() ? 2222 : std::stoi(it->second);
  if (want == port_) return "";
  // probe the port before the commit is accepted, so a typo can't cut off SSH
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(want));
  inet_pton(AF_INET, addr_.c_str(), &sa.sin_addr);
  bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
  ::close(fd);
  return ok ? "" : "port " + std::to_string(want) + " is not available";
}

void SshServer::apply(const Config& c, const std::vector<Change>&) {
  auto it = c.find("system services ssh idle-timeout");
  idle_timeout_ = it == c.end() ? 900 : std::stoi(it->second);
  it = c.find("system services ssh port");
  int want = it == c.end() ? 2222 : std::stoi(it->second);
  if (want != port_) {
    std::string err;
    if (!listen(want, &err) && e_.log) e_.log->log(Sev::Err, "SSH_REBIND", err);
    else if (e_.log) e_.log->log(Sev::Notice, "SSH_REBIND", "ssh now listening on port " + std::to_string(want));
  }
}

void SshServer::accept_loop() {
  while (running_) {
    int lfd = listen_fd_.load();
    if (lfd < 0) { usleep(50000); continue; }
    pollfd p{lfd, POLLIN, 0};
    if (poll(&p, 1, 100) <= 0 || !(p.revents & POLLIN)) continue;
    sockaddr_in peer{};
    socklen_t sl = sizeof peer;
    int fd = ::accept4(lfd, reinterpret_cast<sockaddr*>(&peer), &sl, SOCK_CLOEXEC);
    if (fd < 0) continue;
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
    // CLI output and the next prompt are separate small writes; with Nagle on,
    // the prompt waits for the client's delayed ACK (~40 ms per command)
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    ++active;
    {
      std::lock_guard lk(fds_mu_);
      fds_.insert(fd);
    }
    std::thread([this, fd, s = std::string(ip)] {
      handle(fd, s);
      {
        std::lock_guard lk(fds_mu_);
        fds_.erase(fd);
      }
      --active;
    }).detach();
  }
}

namespace {
std::string crlf(const std::string& s) {
  std::string o;
  o.reserve(s.size() + 16);
  for (char c : s) {
    if (c == '\n') o += '\r';
    o += c;
  }
  return o;
}
bool chan_write(ssh_channel ch, const std::string& s) {
  return s.empty() || ssh_channel_write(ch, s.data(), static_cast<uint32_t>(s.size())) == static_cast<int>(s.size());
}
}  // namespace

void SshServer::handle(int fd, std::string peer) {
  ++sessions_total;
  ssh_bind bind = ssh_bind_new();
  ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, hostkey_.c_str());
  ssh_session s = ssh_new();
  long auth_timeout = 30;
  ssh_options_set(s, SSH_OPTIONS_TIMEOUT, &auth_timeout);
  if (ssh_bind_accept_fd(bind, s, fd) != SSH_OK || ssh_handle_key_exchange(s) != SSH_OK) {
    ssh_free(s);
    ssh_bind_free(bind);
    return;
  }
  std::string user;
  bool authed = false;
  int attempts = 0;
  ssh_channel chan = nullptr;
  // ---- authentication: public key only, keys come from the running config
  while (!authed && attempts < 6) {
    ssh_message m = ssh_message_get(s);
    if (!m) break;
    if (ssh_message_type(m) == SSH_REQUEST_AUTH && ssh_message_subtype(m) == SSH_AUTH_METHOD_PUBLICKEY) {
      user = ssh_message_auth_user(m);
      ssh_key offered = ssh_message_auth_pubkey(m);
      auto [cfg, id] = e_.store->snapshot();
      auto it = cfg.find("system login user " + user + " ssh-key");
      bool match = false;
      if (it != cfg.end() && cfg.count("system login user " + user + " role")) {
        auto parts = split_ws(it->second);
        ssh_key want = nullptr;
        if (parts.size() >= 2 && ssh_pki_import_pubkey_base64(parts[1].c_str(), ssh_key_type_from_name(parts[0].c_str()), &want) == SSH_OK) {
          match = ssh_key_cmp(want, offered, SSH_KEY_CMP_PUBLIC) == 0;
          ssh_key_free(want);
        }
      }
      auto state = ssh_message_auth_publickey_state(m);
      if (match && state == SSH_PUBLICKEY_STATE_NONE) {
        ssh_message_auth_reply_pk_ok_simple(m);  // "this key would be accepted, now sign"
      } else if (match && state == SSH_PUBLICKEY_STATE_VALID) {
        ssh_message_auth_reply_success(m, 0);  // libssh verified the signature
        authed = true;
      } else {
        ++attempts;
        ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PUBLICKEY);
        ssh_message_reply_default(m);
      }
    } else {
      if (ssh_message_type(m) == SSH_REQUEST_AUTH) ++attempts;
      ssh_message_auth_set_methods(m, SSH_AUTH_METHOD_PUBLICKEY);
      ssh_message_reply_default(m);
    }
    ssh_message_free(m);
  }
  if (!authed) {
    ++auth_fail;
    if (e_.log)
      e_.log->log(Sev::Warning, "AUTH_FAIL", "ssh authentication failed for '" + user + "' from " + peer,
                  {{"audit@32473", {{"user", user}, {"src", peer}, {"via", "ssh"}}}});
    ssh_disconnect(s);
    ssh_free(s);
    ssh_bind_free(bind);
    return;
  }
  ++auth_ok;
  if (e_.log)
    e_.log->log(Sev::Notice, "AUTH_OK", "ssh login " + user + " from " + peer,
                {{"audit@32473", {{"user", user}, {"src", peer}, {"via", "ssh"}, {"role", role_name(e_.role_of(user))}}}});

  // ---- channel + pty/shell/exec requests
  bool pty = false, shell = false;
  std::string exec_cmd;
  while (!shell && exec_cmd.empty()) {
    ssh_message m = ssh_message_get(s);
    if (!m) break;
    int type = ssh_message_type(m), sub = ssh_message_subtype(m);
    if (type == SSH_REQUEST_CHANNEL_OPEN && sub == SSH_CHANNEL_SESSION && !chan) {
      chan = ssh_message_channel_request_open_reply_accept(m);
    } else if (type == SSH_REQUEST_CHANNEL && chan) {
      if (sub == SSH_CHANNEL_REQUEST_PTY) { pty = true; ssh_message_channel_request_reply_success(m); }
      else if (sub == SSH_CHANNEL_REQUEST_SHELL) { shell = true; ssh_message_channel_request_reply_success(m); }
      else if (sub == SSH_CHANNEL_REQUEST_EXEC) {
        const char* c = ssh_message_channel_request_command(m);
        exec_cmd = c && *c ? c : " ";
        ssh_message_channel_request_reply_success(m);
      } else if (sub == SSH_CHANNEL_REQUEST_ENV || sub == SSH_CHANNEL_REQUEST_WINDOW_CHANGE) {
        ssh_message_channel_request_reply_success(m);
      } else {
        ssh_message_reply_default(m);
      }
    } else {
      ssh_message_reply_default(m);
    }
    ssh_message_free(m);
  }
  if (chan) {
    CliSession cli(e_, user, "ssh");
    if (!exec_cmd.empty()) {
      // one-shot: commands separated by ';' run in one session ("configure; set ...; commit")
      std::string cur;
      std::vector<std::string> cmds;
      bool q = false;
      for (char c : exec_cmd) {
        if (c == '"') q = !q;
        if (c == ';' && !q) { cmds.push_back(cur); cur.clear(); }
        else cur += c;
      }
      cmds.push_back(cur);
      int status = 0;
      for (auto& c : cmds) {
        auto o = cli.exec(trim(c));
        if (o.text.find("error:") != std::string::npos) status = 1;
        chan_write(chan, o.text);
        if (o.exit) break;
      }
      ssh_channel_request_send_exit_status(chan, status);
    } else {
      LineEditor ed([&](const std::string& l) { return cli.complete(l); }, pty);
      auto out = [&](const std::string& t) { return chan_write(chan, pty ? crlf(t) : t); };
      out("fw-mgmtd management CLI. Type 'help' or press '?'. TAB completes.\n");
      chan_write(chan, cli.prompt());
      char buf[4096];
      bool done = false;
      while (!done && ssh_channel_is_open(chan) && running_) {
        int idle = idle_timeout_.load();
        int n = ssh_channel_read_timeout(chan, buf, sizeof buf, 0, idle > 0 ? idle * 1000 : -1);
        if (n == 0 && !ssh_channel_is_eof(chan)) {
          out("\nidle timeout\n");
          break;
        }
        if (n <= 0) break;
        std::vector<LineEditor::Event> ev;
        std::string echo = ed.feed(std::string(buf, static_cast<size_t>(n)), ev, cli.prompt());
        chan_write(chan, echo);
        for (auto& e : ev) {
          if (e.kind == LineEditor::Event::Eof) { done = true; break; }
          if (e.kind == LineEditor::Event::Line) {
            auto o = cli.exec(e.line);
            out(o.text);
            if (o.exit) { done = true; break; }
          }
          chan_write(chan, cli.prompt());
        }
      }
    }
    ssh_channel_send_eof(chan);
    ssh_channel_close(chan);
    // like sshd, let the client hang up first (up to 1 s): if we drop TCP while
    // it is still processing CHANNEL_CLOSE, OpenSSH reports "closed by remote host"
    ssh_event ev = ssh_event_new();
    ssh_event_add_session(ev, s);
    for (int i = 0; i < 40 && (ssh_get_status(s) & (SSH_CLOSED | SSH_CLOSED_ERROR)) == 0; ++i)
      if (ssh_event_dopoll(ev, 25) == SSH_ERROR) break;
    ssh_event_remove_session(ev, s);
    ssh_event_free(ev);
    ssh_channel_free(chan);
  }
  ssh_disconnect(s);
  ssh_free(s);
  ssh_bind_free(bind);
}

}  // namespace fw
