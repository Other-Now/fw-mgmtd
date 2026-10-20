// License parser fuzzer. Two surfaces:
//  1. parse_and_verify_license on raw input (what an attacker can actually hand us)
//  2. parse_license_body directly -- random bytes never carry a valid Ed25519
//     signature, so without this the field parser would be unreachable.
// Property: anything the body parser accepts, once signed, must verify and
// parse to the same License.
#include <cstdint>
#include <cstdlib>
#include <string>

#include "license.hpp"

using namespace fw;

static std::string g_priv, g_pub;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (g_pub.empty()) ed25519_keygen(&g_priv, &g_pub);
  std::string in(reinterpret_cast<const char*>(data), size);
  std::string err;
  (void)parse_and_verify_license(in, g_pub, &err);
  auto l = parse_license_body(in, &err);
  if (l && !in.empty() && in.back() == '\n') {
    std::string signed_text = in + "signature=" + ed25519_sign_b64(g_priv, in) + "\n";
    auto v = parse_and_verify_license(signed_text, g_pub, &err);
    if (!v || v->license_id != l->license_id || v->expires != l->expires || v->features != l->features) abort();
    (void)evaluate_license(v, 1'800'000'000, "dev", 1'799'000'000);
  }
  return 0;
}
