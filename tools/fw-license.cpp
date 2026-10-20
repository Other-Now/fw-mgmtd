// Vendor-side license tool (would live on the vendor's signing host, not the device).
//   fw-license keygen PRIV.pem PUB.pem
//   fw-license device-id
//   fw-license issue PRIV.pem --id L-1 --customer Acme --device ID|* --features a,b --days 365 --grace 14 [--issued UNIX]
//   fw-license verify PUB.pem LICENSE [--device ID]
#include <iostream>
#include <map>

#include "license.hpp"
#include "util.hpp"

using namespace fw;

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: fw-license keygen|device-id|issue|verify ...\n";
    return 2;
  }
  std::string cmd = argv[1];
  try {
    if (cmd == "keygen" && argc == 4) {
      std::string priv, pub;
      ed25519_keygen(&priv, &pub);
      atomic_write(argv[2], priv);
      atomic_write(argv[3], pub);
      return 0;
    }
    if (cmd == "device-id") {
      std::cout << local_device_id() << "\n";
      return 0;
    }
    std::map<std::string, std::string> o;
    for (int i = 4; i + 1 < argc; i += 2) o[std::string(argv[i]).substr(2)] = argv[i + 1];
    if (cmd == "issue" && argc >= 3) {
      for (int i = 3; i + 1 < argc; i += 2) o[std::string(argv[i]).substr(2)] = argv[i + 1];
      auto priv = read_file(argv[2]);
      if (!priv) throw std::runtime_error("cannot read private key");
      int64_t issued = o.count("issued") ? std::stoll(o["issued"]) : unix_now();
      int64_t days = std::stoll(o.count("days") ? o["days"] : "365");
      std::string body = "# fw-mgmtd license\n";
      body += "customer=" + (o.count("customer") ? o["customer"] : "Example Customer") + "\n";
      body += "license-id=" + (o.count("id") ? o["id"] : "L-0001") + "\n";
      body += "device-id=" + (o.count("device") ? o["device"] : local_device_id()) + "\n";
      body += "features=" + (o.count("features") ? o["features"] : "url-filtering") + "\n";
      body += "issued=" + std::to_string(issued) + "\n";
      body += "expires=" + std::to_string(issued + days * 86400) + "\n";
      body += "grace-days=" + (o.count("grace") ? o["grace"] : "14") + "\n";
      std::cout << body << "signature=" << ed25519_sign_b64(*priv, body) << "\n";
      return 0;
    }
    if (cmd == "verify" && argc >= 4) {
      auto pub = read_file(argv[2]);
      auto lic = read_file(argv[3]);
      if (!pub || !lic) throw std::runtime_error("cannot read inputs");
      std::string err;
      auto l = parse_and_verify_license(*lic, *pub, &err);
      if (!l) {
        std::cout << "INVALID: " << err << "\n";
        return 1;
      }
      auto st = evaluate_license(l, unix_now(), o.count("device") ? o["device"] : local_device_id(), 0);
      std::cout << lic_state_name(st.state) << ": " << st.reason << "\n";
      return st.state == LicState::Valid || st.state == LicState::Grace ? 0 : 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  std::cerr << "bad arguments\n";
  return 2;
}
