#include "config.hpp"

#include "schema.hpp"
#include "util.hpp"

namespace fw {

std::optional<std::vector<std::string>> tokenize(const std::string& line, std::string* err) {
  std::vector<std::string> out;
  size_t i = 0, n = line.size();
  while (i < n) {
    while (i < n && (line[i] == ' ' || line[i] == '\t')) ++i;
    if (i >= n) break;
    std::string w;
    if (line[i] == '"') {
      ++i;
      bool closed = false;
      while (i < n) {
        char c = line[i++];
        if (c == '\\' && i < n && (line[i] == '"' || line[i] == '\\')) {
          w += line[i++];
        } else if (c == '"') {
          closed = true;
          break;
        } else {
          w += c;
        }
      }
      if (!closed) {
        if (err) *err = "unterminated quote";
        return std::nullopt;
      }
    } else {
      while (i < n && line[i] != ' ' && line[i] != '\t') w += line[i++];
    }
    out.push_back(std::move(w));
  }
  return out;
}

std::string quote_if_needed(const std::string& v) {
  bool need = v.empty();
  for (char c : v)
    if (c == ' ' || c == '\t' || c == '"' || c == '\\' || c == '#' || c == '{' || c == '}' || c == ';') need = true;
  if (!need) return v;
  std::string q = "\"";
  for (char c : v) {
    if (c == '"' || c == '\\') q += '\\';
    q += c;
  }
  return q + "\"";
}

std::string config_set(Config& c, const std::vector<std::string>& toks) {
  auto p = parse_path(toks, true);
  if (!p.error.empty()) return p.error;
  c[join(p.key, " ")] = *p.value;
  return "";
}

bool key_in_subtree(const std::string& key, const std::string& prefix) {
  if (prefix.empty()) return true;
  return key == prefix || (key.size() > prefix.size() && key.compare(0, prefix.size(), prefix) == 0 && key[prefix.size()] == ' ');
}

std::string config_delete(Config& c, const std::vector<std::string>& toks) {
  auto p = parse_path(toks, false);
  if (!p.error.empty()) return p.error;
  std::string prefix = join(p.key, " ");
  size_t n = 0;
  for (auto it = c.lower_bound(prefix); it != c.end() && it->first.compare(0, prefix.size(), prefix) == 0;) {
    if (key_in_subtree(it->first, prefix)) {
      it = c.erase(it);
      ++n;
    } else {
      ++it;
    }
  }
  return n ? "" : "statement not found";
}

bool key_is_secret(const std::string& key) {
  auto t = split_ws(key);
  return parse_path(t, false).secret;
}

std::string to_set_lines(const Config& c, bool mask) {
  std::string out;
  for (auto& [k, v] : c) {
    out += "set " + k + " ";
    out += (mask && key_is_secret(k)) ? "\"<masked>\"" : quote_if_needed(v);
    out += "\n";
  }
  return out;
}

std::optional<Config> parse_config(const std::string& text, std::string* err) {
  Config c;
  size_t lineno = 0, pos = 0;
  while (pos <= text.size()) {
    size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) nl = text.size();
    std::string line = trim(std::string_view(text).substr(pos, nl - pos));
    pos = nl + 1;
    ++lineno;
    if (line.empty() || line[0] == '#') {
      if (nl == text.size()) break;
      continue;
    }
    std::string terr;
    auto toks = tokenize(line, &terr);
    if (!toks) {
      if (err) *err = "line " + std::to_string(lineno) + ": " + terr;
      return std::nullopt;
    }
    if (toks->empty() || (*toks)[0] != "set") {
      if (err) *err = "line " + std::to_string(lineno) + ": expected 'set'";
      return std::nullopt;
    }
    toks->erase(toks->begin());
    if (auto e = config_set(c, *toks); !e.empty()) {
      if (err) *err = "line " + std::to_string(lineno) + ": " + e;
      return std::nullopt;
    }
    if (nl == text.size()) break;
  }
  return c;
}

std::string to_hierarchical(const Config& c, const std::string& subtree, bool mask) {
  // Walk keys in order, opening/closing braces as the shared prefix changes.
  // List entries ("rule 10") are rendered as one block header.
  std::string out;
  std::vector<std::string> open;  // currently open block headers
  auto group = [](const std::vector<std::string>& t) {
    // regroup tokens into block names: a list keyword absorbs its key
    std::vector<std::string> g;
    auto p = parse_path(t, false);
    const Node* cur = &schema_root();
    for (size_t i = 0; i < t.size(); ++i) {
      const Node* nx = cur ? cur->child(t[i]) : nullptr;
      if (nx && nx->kind == Node::List && i + 1 < t.size()) {
        g.push_back(t[i] + " " + t[i + 1]);
        ++i;
      } else {
        g.push_back(t[i]);
      }
      cur = nx;
    }
    (void)p;
    return g;
  };
  for (auto& [k, v] : c) {
    if (!key_in_subtree(k, subtree)) continue;
    auto g = group(split_ws(k));
    if (g.empty()) continue;
    std::vector<std::string> blocks(g.begin(), g.end() - 1);
    size_t common = 0;
    while (common < open.size() && common < blocks.size() && open[common] == blocks[common]) ++common;
    while (open.size() > common) {
      open.pop_back();
      out += std::string(open.size() * 4, ' ') + "}\n";
    }
    while (open.size() < blocks.size()) {
      out += std::string(open.size() * 4, ' ') + blocks[open.size()] + " {\n";
      open.push_back(blocks[open.size()]);
    }
    std::string val = (mask && key_is_secret(k)) ? "\"<masked>\"" : quote_if_needed(v);
    out += std::string(open.size() * 4, ' ') + g.back() + " " + val + ";\n";
  }
  while (!open.empty()) {
    open.pop_back();
    out += std::string(open.size() * 4, ' ') + "}\n";
  }
  return out;
}

std::vector<Change> diff(const Config& a, const Config& b) {
  std::vector<Change> d;
  auto ia = a.begin(), ib = b.begin();
  while (ia != a.end() || ib != b.end()) {
    if (ib == b.end() || (ia != a.end() && ia->first < ib->first)) {
      d.push_back({Change::Delete, ia->first, ia->second, ""});
      ++ia;
    } else if (ia == a.end() || ib->first < ia->first) {
      d.push_back({Change::Add, ib->first, "", ib->second});
      ++ib;
    } else {
      if (ia->second != ib->second) d.push_back({Change::Modify, ia->first, ia->second, ib->second});
      ++ia;
      ++ib;
    }
  }
  return d;
}

std::string render_diff(const std::vector<Change>& d) {
  std::string out;
  for (auto& c : d) {
    bool s = key_is_secret(c.key);
    auto shown = [s](const std::string& v) { return s ? std::string("\"<masked>\"") : quote_if_needed(v); };
    switch (c.kind) {
      case Change::Add: out += "+ set " + c.key + " " + shown(c.new_value) + "\n"; break;
      case Change::Delete: out += "- set " + c.key + " " + shown(c.old_value) + "\n"; break;
      case Change::Modify:
        out += "- set " + c.key + " " + shown(c.old_value) + "\n";
        out += "+ set " + c.key + " " + shown(c.new_value) + "\n";
        break;
    }
  }
  return out;
}

}  // namespace fw
