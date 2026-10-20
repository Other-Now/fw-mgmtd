// HTTP request-head parser fuzzer (the REST API's first contact with the network).
#include <cstdint>
#include <string>

#include "http.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string in(reinterpret_cast<const char*>(data), size);
  fw::HttpRequest r;
  size_t cl = 0;
  std::string err;
  (void)fw::parse_request_head(in, r, &cl, &err);
  return 0;
}
