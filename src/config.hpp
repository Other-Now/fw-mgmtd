// A configuration is a flat sorted map  "firewall rule 10 action" -> "accept".
// Flat keys make diff, delete-subtree and serialization trivial; the
// hierarchical view is only a rendering.
#pragma once
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fw {

using Config = std::map<std::string, std::string>;

// Splits a command line into words. Double quotes group words; inside quotes
// \" and \\ are escapes. Returns nullopt (with err) on an unterminated quote.
std::optional<std::vector<std::string>> tokenize(const std::string& line, std::string* err = nullptr);
std::string quote_if_needed(const std::string& v);

// Applies one "set <path> <value>" (tokens after "set"). Returns error or "".
std::string config_set(Config& c, const std::vector<std::string>& toks);
// Deletes the subtree named by tokens. Returns error or "" (deleting nothing is an error).
std::string config_delete(Config& c, const std::vector<std::string>& toks);

// "set ..." lines; the on-disk format and `show | display set`.
std::string to_set_lines(const Config& c, bool mask_secrets = false);
// Parses set-lines (comments start with '#'). Every line is schema-checked.
// On error returns nullopt and a "line N: ..." message.
std::optional<Config> parse_config(const std::string& text, std::string* err);

// Junos-style braces view, optionally restricted to a subtree.
std::string to_hierarchical(const Config& c, const std::string& subtree = "", bool mask_secrets = false);

struct Change {
  enum Kind { Add, Modify, Delete } kind;
  std::string key, old_value, new_value;
};
std::vector<Change> diff(const Config& a, const Config& b);
std::string render_diff(const std::vector<Change>& d);

bool key_is_secret(const std::string& key);
bool key_in_subtree(const std::string& key, const std::string& prefix);

}  // namespace fw
