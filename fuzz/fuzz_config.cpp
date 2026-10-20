// Config file parser fuzzer. Property: parse -> serialize -> parse is the
// identity (catches quoting/escaping bugs, not just crashes), and every
// renderer survives whatever the parser accepted.
#include <cstdint>
#include <cstdlib>
#include <string>

#include "config.hpp"

using namespace fw;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 16384) return 0;
  std::string in(reinterpret_cast<const char*>(data), size);
  std::string err;
  auto c = parse_config(in, &err);
  if (!c) return 0;
  std::string text = to_set_lines(*c);
  auto back = parse_config(text, &err);
  if (!back || *back != *c) abort();
  (void)to_hierarchical(*c);
  (void)to_set_lines(*c, true);
  (void)render_diff(diff({}, *c));
  return 0;
}
