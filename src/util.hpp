// Small helpers shared by every module: crash-safe file writes, strings, time.
#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fw {

// write tmp -> fsync(tmp) -> rename(tmp, path) -> fsync(dir).
// After this returns, `path` holds either the old or the new bytes, never a mix,
// even across power loss. Throws std::runtime_error on failure.
void atomic_write(const std::string& path, std::string_view data);

std::optional<std::string> read_file(const std::string& path);
bool file_exists(const std::string& path);
void mkdirs(const std::string& path);

std::vector<std::string> split_ws(std::string_view s);
std::string join(const std::vector<std::string>& v, std::string_view sep);
std::string trim(std::string_view s);
bool starts_with(std::string_view s, std::string_view p);

std::string b64encode(std::string_view in, bool url = false);
std::optional<std::string> b64decode(std::string_view in, bool url = false);
std::string sha256_hex(std::string_view in);
std::string to_hex(std::string_view in);

using Clock = std::chrono::system_clock;
std::string rfc3339(Clock::time_point t, bool micros = true);
int64_t unix_now();
double mono_us();  // monotonic microseconds, for latency measurement

}  // namespace fw
