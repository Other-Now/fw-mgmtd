#include "schema.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>

namespace fw {

const Node* Node::child(const std::string& n) const {
  for (auto& c : children)
    if (c.name == n) return &c;
  return nullptr;
}

static Node C(std::string name, std::string help, std::vector<Node> kids, std::string feature = "") {
  Node n{Node::Container, std::move(name), std::move(help)};
  n.children = std::move(kids);
  n.feature = std::move(feature);
  return n;
}
static Node L(std::string name, std::string help, VType key, std::vector<Node> kids,
              uint64_t mn = 0, uint64_t mx = UINT64_MAX) {
  Node n{Node::List, std::move(name), std::move(help), key, mn, mx};
  n.children = std::move(kids);
  return n;
}
static Node V(std::string name, std::string help, VType t, uint64_t mn = 0, uint64_t mx = UINT64_MAX) {
  return Node{Node::Leaf, std::move(name), std::move(help), t, mn, mx};
}
static Node E(std::string name, std::string help, std::vector<std::string> vals) {
  Node n{Node::Leaf, std::move(name), std::move(help), VType::Enum};
  n.enums = std::move(vals);
  return n;
}
static Node S(Node n) { n.secret = true; return n; }

const Node& schema_root() {
  static const Node root = C("", "", {
    C("system", "System parameters", {
      V("hostname", "Device host name", VType::Name),
      C("login", "Administrator accounts", {
        L("user", "Local user", VType::Name, {
          E("role", "Role for command authorization", {"admin", "operator", "viewer"}),
          V("ssh-key", "Public key, OpenSSH format (\"ssh-ed25519 AAAA...\")", VType::String),
          S(V("api-token-sha256", "SHA-256 of the REST API bearer token", VType::Hex64)),
        }),
      }),
      C("syslog", "Remote syslog (RFC 5424 over UDP)", {
        V("server", "Collector address", VType::IPv4),
        V("port", "Collector UDP port", VType::UInt, 1, 65535),
        V("facility", "Syslog facility number", VType::UInt, 0, 23),
      }),
      C("services", "Management services", {
        C("ssh", "CLI over SSH", {V("port", "Listen port", VType::UInt, 1, 65535),
                                  V("idle-timeout", "Seconds before idle sessions close", VType::UInt, 0, 86400)}),
        C("https", "REST API over HTTPS", {V("port", "Listen port", VType::UInt, 1, 65535)}),
      }),
      C("certificate", "HTTPS server certificate lifecycle", {
        V("common-name", "Subject CN / SAN dNSName", VType::Name),
        V("acme-directory", "ACME directory URL", VType::String),
        V("renew-before", "Renew when fewer than this many seconds remain", VType::UInt, 60, 400000000),
        V("alert-days", "Alert when the certificate expires within N days", VType::UInt, 1, 365),
      }),
    }),
    C("interfaces", "Network interfaces", {
      L("interface", "Interface", VType::Name, {
        V("address", "IPv4 address/prefix", VType::Cidr),
        V("description", "Free text", VType::String),
        V("mtu", "MTU", VType::UInt, 68, 9216),
        V("disable", "Administratively down", VType::Bool),
      }),
    }),
    C("firewall", "Packet filter", {
      L("rule", "Rule, evaluated in ascending order", VType::UInt, {
        E("action", "Verdict", {"accept", "drop", "reject"}),
        V("source", "Source prefix", VType::Cidr),
        V("destination", "Destination prefix", VType::Cidr),
        E("protocol", "IP protocol", {"any", "tcp", "udp", "icmp"}),
        V("port", "Destination port", VType::UInt, 1, 65535),
        V("log", "Log matches", VType::Bool),
      }, 1, 65535),
      C("url-filter", "URL categorization (licensed)", {
        V("enable", "Enable URL filtering", VType::Bool),
        L("category", "Category policy", VType::Name, {E("action", "Verdict", {"allow", "block"})}),
      }, "url-filtering"),
    }),
  });
  return root;
}

const char* vtype_name(VType t) {
  switch (t) {
    case VType::String: return "<string>";
    case VType::UInt: return "<number>";
    case VType::IPv4: return "<a.b.c.d>";
    case VType::Cidr: return "<a.b.c.d/len>";
    case VType::Bool: return "<true|false>";
    case VType::Enum: return "<enum>";
    case VType::Name: return "<name>";
    case VType::Hex64: return "<sha256-hex>";
  }
  return "?";
}

static bool parse_u64(const std::string& s, uint64_t& out) {
  if (s.empty() || s.size() > 20) return false;
  auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
  return ec == std::errc() && p == s.data() + s.size();
}

std::optional<std::string> check_value(const Node& n, const std::string& v) {
  switch (n.type) {
    case VType::String:
      if (v.size() > 1024) return "string longer than 1024 bytes";
      for (unsigned char c : v)
        if (c < 0x20 || c == 0x7f) return "control characters are not allowed";
      return std::nullopt;
    case VType::Name:
      if (v.empty() || v.size() > 63) return "name must be 1-63 characters";
      for (unsigned char c : v)
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.' || c == '/'))
          return "name may contain only [A-Za-z0-9._/-]";
      return std::nullopt;
    case VType::UInt: {
      uint64_t x;
      if (!parse_u64(v, x)) return "expected a number";
      if (x < n.min || x > n.max)
        return "value out of range " + std::to_string(n.min) + ".." + std::to_string(n.max);
      return std::nullopt;
    }
    case VType::Bool:
      if (v == "true" || v == "false") return std::nullopt;
      return "expected true or false";
    case VType::Enum:
      if (std::find(n.enums.begin(), n.enums.end(), v) != n.enums.end()) return std::nullopt;
      return "expected one of: " + [&] { std::string s; for (auto& e : n.enums) s += (s.empty() ? "" : ", ") + e; return s; }();
    case VType::IPv4: {
      in_addr a;
      if (inet_pton(AF_INET, v.c_str(), &a) == 1) return std::nullopt;
      return "expected an IPv4 address";
    }
    case VType::Cidr: {
      auto slash = v.find('/');
      if (slash == std::string::npos) return "expected a.b.c.d/len";
      in_addr a;
      uint64_t len;
      if (inet_pton(AF_INET, v.substr(0, slash).c_str(), &a) != 1 || !parse_u64(v.substr(slash + 1), len) || len > 32)
        return "expected a.b.c.d/len";
      return std::nullopt;
    }
    case VType::Hex64:
      if (v.size() != 64) return "expected 64 hex characters";
      for (char c : v)
        if (!isxdigit(static_cast<unsigned char>(c))) return "expected 64 hex characters";
      return std::nullopt;
  }
  return "unknown type";
}

PathParse parse_path(const std::vector<std::string>& toks, bool want_value) {
  PathParse r;
  const Node* cur = &schema_root();
  size_t i = 0;
  auto fail = [&](size_t at, std::string msg) {
    r.error = std::move(msg);
    r.error_at = at;
    return r;
  };
  while (i < toks.size()) {
    const Node* nx = cur->child(toks[i]);
    if (!nx) {
      std::string opts;
      for (auto& c : cur->children) opts += (opts.empty() ? "" : " ") + c.name;
      return fail(i, "syntax error at '" + toks[i] + "', expected one of: " + opts);
    }
    r.key.push_back(toks[i]);
    if (!nx->feature.empty()) r.feature = nx->feature;
    if (nx->secret) r.secret = true;
    ++i;
    cur = nx;
    r.last = cur;
    if (cur->kind == Node::List) {
      if (i == toks.size()) {
        if (want_value) return fail(i, "missing " + std::string(vtype_name(cur->type)) + " for " + cur->name);
        return r;
      }
      if (auto e = check_value(*cur, toks[i])) return fail(i, cur->name + " key: " + *e);
      r.key.push_back(toks[i]);
      ++i;
    } else if (cur->kind == Node::Leaf) {
      r.leaf = cur;
      if (i == toks.size()) {
        if (want_value) return fail(i, "missing value " + std::string(vtype_name(cur->type)));
        return r;
      }
      if (!want_value) return fail(i, "unexpected token after leaf");
      if (i + 1 != toks.size()) return fail(i + 1, "unexpected token after value");
      if (auto e = check_value(*cur, toks[i])) return fail(i, *e);
      r.value = toks[i];
      return r;
    }
  }
  if (want_value) return fail(i, "incomplete path");
  return r;
}

std::vector<std::string> complete_path(const std::vector<std::string>& toks,
                                       const std::map<std::string, std::string>& cfg) {
  std::vector<std::string> out;
  const Node* cur = &schema_root();
  std::string prefix;
  size_t i = 0;
  while (i < toks.size()) {
    const Node* nx = cur->child(toks[i]);
    if (!nx) return {};
    prefix += (prefix.empty() ? "" : " ") + toks[i];
    ++i;
    cur = nx;
    if (cur->kind == Node::List) {
      if (i == toks.size()) {
        // offer existing keys, then the placeholder
        std::string p = prefix + " ";
        for (auto it = cfg.lower_bound(p); it != cfg.end() && it->first.compare(0, p.size(), p) == 0; ++it) {
          auto rest = it->first.substr(p.size());
          auto k = rest.substr(0, rest.find(' '));
          if (out.empty() || out.back() != k) out.push_back(k);
        }
        out.push_back(vtype_name(cur->type));
        return out;
      }
      prefix += " " + toks[i];
      ++i;
    } else if (cur->kind == Node::Leaf) {
      if (i != toks.size()) return {};
      if (cur->type == VType::Enum) return cur->enums;
      if (cur->type == VType::Bool) return {"true", "false"};
      return {vtype_name(cur->type)};
    }
  }
  for (auto& c : cur->children) out.push_back(c.name);
  return out;
}

}  // namespace fw
