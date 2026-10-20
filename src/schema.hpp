// Typed configuration schema. The tree below is the single source of truth for
// what `set` accepts, what tab completion offers, and what a config file may
// contain -- the CLI, the REST API and the on-disk loader all go through
// parse_path(), so they cannot disagree about what is valid.
#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fw {

enum class VType { String, UInt, IPv4, Cidr, Bool, Enum, Name, Hex64 };

struct Node {
  enum Kind { Container, List, Leaf } kind;
  std::string name;
  std::string help;
  // List: type of the key; Leaf: type of the value
  VType type = VType::String;
  uint64_t min = 0, max = UINT64_MAX;
  std::vector<std::string> enums;
  bool secret = false;            // masked in show output for non-admins and tech-support
  std::string feature;            // license feature needed to configure anything below
  std::vector<Node> children;

  const Node* child(const std::string& n) const;
};

const Node& schema_root();

// Validate one value against a node's type. Returns an error string or nullopt.
std::optional<std::string> check_value(const Node& n, const std::string& v);

// Result of walking tokens like {"firewall","rule","10","action","accept"}.
struct PathParse {
  std::string error;              // empty == ok
  size_t error_at = 0;            // index of the offending token
  std::vector<std::string> key;   // canonical path tokens (without the value)
  const Node* leaf = nullptr;     // set when the path reached a leaf
  std::optional<std::string> value;
  std::string feature;            // strictest license feature on the path
  bool secret = false;
  const Node* last = nullptr;     // deepest node reached (for completion / delete)
};

// want_value: true for `set` (a leaf + value is required); false for `delete`
// and `show` (any prefix that names a container, list entry or leaf is fine).
PathParse parse_path(const std::vector<std::string>& toks, bool want_value);

// Candidate next words after `toks` (a complete prefix). Placeholders such as
// "<name>" are returned for free-form values; existing list keys from `cfg`
// are offered too.
std::vector<std::string> complete_path(const std::vector<std::string>& toks,
                                       const std::map<std::string, std::string>& cfg);

const char* vtype_name(VType t);

}  // namespace fw
