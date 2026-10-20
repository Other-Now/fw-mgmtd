#include "util.hpp"

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fw {

static void throw_errno(const std::string& what) {
  throw std::runtime_error(what + ": " + std::strerror(errno));
}

void atomic_write(const std::string& path, std::string_view data) {
  std::string tmp = path + ".tmp";
  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) throw_errno("open " + tmp);
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      throw_errno("write " + tmp);
    }
    off += static_cast<size_t>(n);
  }
  if (::fsync(fd) != 0) { ::close(fd); throw_errno("fsync " + tmp); }
  ::close(fd);
  if (::rename(tmp.c_str(), path.c_str()) != 0) throw_errno("rename " + tmp);
  // the rename itself lives in the directory; without this fsync a crash can
  // leave the directory entry pointing at the old inode
  auto slash = path.rfind('/');
  std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
  int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
}

std::optional<std::string> read_file(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return std::nullopt;
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

bool file_exists(const std::string& path) {
  struct stat st;
  return ::stat(path.c_str(), &st) == 0;
}

void mkdirs(const std::string& path) {
  std::string cur;
  for (size_t i = 0; i <= path.size(); ++i) {
    if (i == path.size() || path[i] == '/') {
      if (!cur.empty()) ::mkdir(cur.c_str(), 0700);
    }
    if (i < path.size()) cur += path[i];
  }
}

std::vector<std::string> split_ws(std::string_view s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    size_t j = i;
    while (j < s.size() && s[j] != ' ' && s[j] != '\t') ++j;
    if (j > i) out.emplace_back(s.substr(i, j - i));
    i = j;
  }
  return out;
}

std::string join(const std::vector<std::string>& v, std::string_view sep) {
  std::string out;
  for (size_t i = 0; i < v.size(); ++i) {
    if (i) out += sep;
    out += v[i];
  }
  return out;
}

std::string trim(std::string_view s) {
  size_t a = 0, b = s.size();
  while (a < b && isspace(static_cast<unsigned char>(s[a]))) ++a;
  while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) --b;
  return std::string(s.substr(a, b - a));
}

bool starts_with(std::string_view s, std::string_view p) {
  return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}

static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64encode(std::string_view in, bool url) {
  const char* t = url ? B64U : B64;
  std::string out;
  size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8) | uint8_t(in[i + 2]);
    out += t[v >> 18]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63]; out += t[v & 63];
  }
  if (i + 1 == in.size()) {
    uint32_t v = uint8_t(in[i]) << 16;
    out += t[v >> 18]; out += t[(v >> 12) & 63];
    if (!url) out += "==";
  } else if (i + 2 == in.size()) {
    uint32_t v = (uint8_t(in[i]) << 16) | (uint8_t(in[i + 1]) << 8);
    out += t[v >> 18]; out += t[(v >> 12) & 63]; out += t[(v >> 6) & 63];
    if (!url) out += '=';
  }
  return out;
}

std::optional<std::string> b64decode(std::string_view in, bool url) {
  auto val = [url](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == (url ? '-' : '+')) return 62;
    if (c == (url ? '_' : '/')) return 63;
    return -1;
  };
  while (!in.empty() && in.back() == '=') in.remove_suffix(1);
  if (in.size() % 4 == 1) return std::nullopt;
  std::string out;
  uint32_t acc = 0;
  int bits = 0;
  for (char c : in) {
    int v = val(c);
    if (v < 0) return std::nullopt;
    acc = (acc << 6) | uint32_t(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += char((acc >> bits) & 0xff);
    }
  }
  return out;
}

std::string to_hex(std::string_view in) {
  static const char* h = "0123456789abcdef";
  std::string out;
  for (unsigned char c : in) { out += h[c >> 4]; out += h[c & 15]; }
  return out;
}

std::string sha256_hex(std::string_view in) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int n = 0;
  EVP_Digest(in.data(), in.size(), md, &n, EVP_sha256(), nullptr);
  return to_hex(std::string_view(reinterpret_cast<char*>(md), n));
}

std::string rfc3339(Clock::time_point t, bool micros) {
  auto us = std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
  time_t secs = static_cast<time_t>(us / 1000000);
  struct tm tm;
  gmtime_r(&secs, &tm);
  char buf[64];
  size_t n = strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%S", &tm);
  if (micros) n += snprintf(buf + n, sizeof buf - n, ".%06lld", static_cast<long long>(us % 1000000));
  snprintf(buf + n, sizeof buf - n, "Z");
  return buf;
}

int64_t unix_now() {
  return std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
}

double mono_us() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

}  // namespace fw
