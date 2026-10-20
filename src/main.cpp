// fw-mgmtd: firewall management-plane daemon.
//   transactional config store  <- CLI over SSH (libssh) and REST over HTTPS
//   services subscribe to config changes (syslog, https, ssh, firewall, certs)
//   certificate lifecycle (ACME), license enforcement, RFC 5424 audit log
#include <dirent.h>
#include <signal.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <thread>

#include "api.hpp"
#include "certmgr.hpp"
#include "cli.hpp"
#include "http.hpp"
#include "ssh_server.hpp"
#include "store.hpp"
#include "syslog.hpp"
#include "util.hpp"

using namespace fw;

static std::string proc_status(const char* key) {
  auto s = read_file("/proc/self/status").value_or("");
  auto p = s.find(key);
  if (p == std::string::npos) return "?";
  auto e = s.find('\n', p);
  return trim(s.substr(p + strlen(key), e - p - strlen(key)));
}

static int count_fds() {
  int n = 0;
  if (DIR* d = opendir("/proc/self/fd")) {
    while (readdir(d)) ++n;
    closedir(d);
  }
  return n - 3;  // ., .., and the DIR fd itself
}

int main(int argc, char** argv) {
  std::map<std::string, std::string> opt = {
      {"state", "./state"},       {"bootstrap", ""},       {"license", ""},          {"vendor-pubkey", ""},
      {"acme-ca", ""},            {"device-id", ""},       {"listen", "127.0.0.1"}, {"challenge-port", "5002"},
  };
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if (a.rfind("--", 0) == 0 && i + 1 < argc && opt.count(a.substr(2))) opt[a.substr(2)] = argv[++i];
    else {
      std::cerr << "usage: fw-mgmtd [--state DIR] [--bootstrap FILE] [--license FILE] [--vendor-pubkey FILE]\n"
                   "                [--acme-ca PEM] [--device-id ID] [--listen ADDR] [--challenge-port N]\n";
      return 2;
    }
  }
  const std::string st = opt["state"];
  mkdirs(st);
  signal(SIGPIPE, SIG_IGN);
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  sigaddset(&sigs, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &sigs, nullptr);  // threads inherit the mask; main sigwait()s

  Syslog log(st + "/fw-mgmtd.log");
  log.log(Sev::Notice, "START", "fw-mgmtd starting, pid " + std::to_string(getpid()));
  std::string dev = opt["device-id"].empty() ? local_device_id() : opt["device-id"];
  LicenseManager lic(opt["license"].empty() ? st + "/license.lic" : opt["license"], opt["vendor-pubkey"],
                     st + "/clock-hwm", dev, &log);
  lic.tick();

  ConfigStore store(st + "/config", &log, [&](const std::string& f) { return lic.feature(f); });
  Config boot;
  if (!opt["bootstrap"].empty()) {
    std::string err;
    auto text = read_file(opt["bootstrap"]);
    auto c = text ? parse_config(*text, &err) : std::nullopt;
    if (!c) {
      std::cerr << "bootstrap config: " << (text ? err : "cannot read") << "\n";
      return 1;
    }
    boot = *c;
  }
  try {
    store.open(boot);
  } catch (const std::exception& e) {
    std::cerr << "config store: " << e.what() << "\n";
    return 1;
  }

  Engine eng;
  eng.store = &store;
  eng.log = &log;
  eng.lic = &lic;
  auto t_start = Clock::now();

  HttpServer https([&](const HttpRequest& r) { return api_handle(eng, r); });
  CertManager cert(st + "/cert", &log, [&](SslCtxPtr c) { https.set_ctx(std::move(c)); }, opt["acme-ca"],
                   std::stoi(opt["challenge-port"]));
  eng.cert = &cert;
  SshServer ssh(eng, st + "/ssh_host_ed25519_key", opt["listen"]);
  SyslogService syslog_svc(&log);
  HttpsService https_svc(https, &log, opt["listen"]);
  FirewallService fw_svc(&log);
  for (Subscriber* s : std::initializer_list<Subscriber*>{&syslog_svc, &cert, &https_svc, &ssh, &fw_svc}) store.subscribe(s);
  store.apply_all();  // binds listeners on the configured ports
  if (ssh.port() == 0) {
    std::string e;
    if (!ssh.listen(2222, &e)) { std::cerr << e << "\n"; return 1; }
  }
  if (https.port() == 0) {
    std::string e;
    if (!https.listen(opt["listen"], 8443, &e)) { std::cerr << e << "\n"; return 1; }
  }
  cert.start_with_existing_or_selfsigned();

  eng.diagnostics = [&] {
    auto [cfg, id] = store.snapshot();
    struct statvfs vfs {};
    statvfs(st.c_str(), &vfs);
    auto up = std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - t_start).count();
    std::string s;
    char b[256];
    snprintf(b, sizeof b, "Uptime:            %llds\nPID:               %d\n", static_cast<long long>(up), getpid());
    s += b;
    s += "RSS:               " + proc_status("VmRSS:") + "\nThreads:           " + proc_status("Threads:") + "\n";
    s += "Open fds:          " + std::to_string(count_fds()) + "\n";
    snprintf(b, sizeof b, "State dir free:    %.1f MiB (%s)\n", vfs.f_bavail * static_cast<double>(vfs.f_frsize) / (1 << 20), st.c_str());
    s += b;
    s += "Running commit:    " + std::to_string(id) + " (" + std::to_string(cfg.size()) + " statements)\n";
    if (auto p = store.pending()) s += "Commit confirmed:  commit " + std::to_string(p->commit_id) + " reverts in " + std::to_string(p->deadline - unix_now()) + "s\n";
    s += "SSH:               port " + std::to_string(ssh.port()) + ", " + std::to_string(ssh.active.load()) + " active, " +
         std::to_string(ssh.auth_ok.load()) + " logins, " + std::to_string(ssh.auth_fail.load()) + " auth failures\n";
    s += "HTTPS:             port " + std::to_string(https.port()) + ", " + std::to_string(https.connections.load()) + " connections, " +
         std::to_string(https.requests.load()) + " requests, " + std::to_string(https.handshake_failures.load()) + " handshake failures, " +
         std::to_string(https.ctx_swaps.load()) + " cert reloads\n";
    s += "Certificate:       " + std::to_string(cert.seconds_left()) + "s left\n";
    auto ls = lic.status();
    s += "License:           " + std::string(lic_state_name(ls.state)) + " (" + ls.reason + ")\n";
    s += "Firewall:          " + std::to_string(fw_svc.rules()) + " rules, recompiled " + std::to_string(fw_svc.applies()) + " times\n";
    s += "Syslog UDP sent:   " + std::to_string(log.sent_udp()) + "\n";
    return s;
  };

  https.start();
  ssh.start();
  log.log(Sev::Notice, "READY", "ssh on " + std::to_string(ssh.port()) + ", https on " + std::to_string(https.port()));
  std::cout << "fw-mgmtd ready: ssh " << ssh.port() << " https " << https.port() << std::endl;

  std::atomic<bool> stop{false};
  std::thread timer([&] {
    int n = 0;
    while (!stop) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
      // an exception escaping a std::thread is std::terminate(); one bad tick
      // must cost one tick, not the management plane
      try {
        store.tick();  // commit-confirmed deadline
        if (++n % 4 == 0) lic.tick();
        if (n % 8 == 0) cert.tick();
      } catch (const std::exception& e) {
        log.log(Sev::Err, "TIMER", std::string("timer tick failed: ") + e.what());
      }
    }
  });

  int sig = 0;
  sigwait(&sigs, &sig);
  log.log(Sev::Notice, "STOP", std::string("signal ") + strsignal(sig) + ", shutting down");
  stop = true;
  timer.join();
  ssh.stop();
  https.stop();
  return 0;
}
