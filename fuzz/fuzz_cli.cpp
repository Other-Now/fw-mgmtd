// CLI fuzzer: each input is split into lines and executed in one session
// (operational + configuration mode, pipes, abbreviations, completion), and
// the raw bytes are also pushed through the terminal line editor.
// `commit` is skipped so the fuzzer does not spend its time in fsync.
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <string>

#include "cli.hpp"
#include "lineedit.hpp"
#include "store.hpp"
#include "util.hpp"

using namespace fw;

static Engine* engine() {
  static Engine e;
  static ConfigStore* store = nullptr;
  if (!store) {
    char t[] = "/tmp/fwm-fuzz-XXXXXX";
    store = new ConfigStore(std::string(mkdtemp(t)) + "/cfg", nullptr);
    Config c;
    config_set(c, *tokenize("system login user admin role admin"));
    config_set(c, *tokenize("system login user admin ssh-key \"ssh-ed25519 AAAA\""));
    config_set(c, *tokenize("firewall rule 10 action accept"));
    store->open(c);
    e.store = store;
  }
  return &e;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 4096) return 0;
  std::string in(reinterpret_cast<const char*>(data), size);
  Engine* e = engine();
  CliSession s(*e, "admin", "fuzz");
  size_t pos = 0;
  while (pos <= in.size()) {
    size_t nl = in.find('\n', pos);
    if (nl == std::string::npos) nl = in.size();
    std::string line = in.substr(pos, nl - pos);
    pos = nl + 1;
    auto t = split_ws(line);
    if (!t.empty() && starts_with("commit", t[0]) && t[0].size() >= 2) continue;
    if (!t.empty() && t[0] == "run") continue;  // run -> request certificate renew etc. need services
    (void)s.complete(line);
    (void)s.exec(line);
  }
  LineEditor ed([&](const std::string& l) { return s.complete(l); }, true);
  std::vector<LineEditor::Event> ev;
  (void)ed.feed(in, ev, s.prompt());
  return 0;
}
