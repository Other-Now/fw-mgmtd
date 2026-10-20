#include "lineedit.hpp"

#include <algorithm>

namespace fw {

static std::string current_word(const std::string& buf) {
  if (buf.empty() || buf.back() == ' ') return "";
  auto sp = buf.rfind(' ');
  return sp == std::string::npos ? buf : buf.substr(sp + 1);
}

static bool in_quotes(const std::string& buf) {
  return std::count(buf.begin(), buf.end(), '"') % 2 == 1;
}

std::string LineEditor::replace_line(const std::string& prompt, const std::string& line) {
  buf_ = line;
  return echo_ ? "\r\x1b[K" + prompt + buf_ : "";
}

std::string LineEditor::on_tab(const std::string& prompt) {
  auto cands = complete_(buf_);
  std::vector<std::string> real;
  for (auto& c : cands)
    if (!c.empty() && c[0] != '<') real.push_back(c);
  std::string word = current_word(buf_);
  if (real.size() == 1) {
    std::string add = real[0].substr(word.size()) + " ";
    buf_ += add;
    return echo_ ? add : "";
  }
  if (real.size() > 1) {
    // extend to the longest common prefix first, list only if that adds nothing
    std::string lcp = real[0];
    for (auto& c : real) {
      size_t i = 0;
      while (i < lcp.size() && i < c.size() && lcp[i] == c[i]) ++i;
      lcp.resize(i);
    }
    if (lcp.size() > word.size()) {
      std::string add = lcp.substr(word.size());
      buf_ += add;
      return echo_ ? add : "";
    }
  }
  if (cands.empty()) return echo_ ? "\a" : "";
  std::string out = "\r\n";
  for (auto& c : cands) out += c + "  ";
  return out + "\r\n" + prompt + buf_;
}

std::string LineEditor::on_help(const std::string& prompt) {
  auto cands = complete_(buf_);
  std::string out = "?\r\nPossible completions:\r\n";
  for (auto& c : cands) out += "  " + c + "\r\n";
  if (cands.empty()) out += "  <no completions>\r\n";
  return out + prompt + buf_;
}

std::string LineEditor::feed(const std::string& in, std::vector<Event>& ev, const std::string& prompt) {
  std::string out;
  for (char ch : in) {
    unsigned char c = static_cast<unsigned char>(ch);
    if (esc_ == 1) {
      esc_ = c == '[' ? 2 : 0;
      continue;
    }
    if (esc_ == 2) {
      if (c >= 0x40 && c <= 0x7e) {
        esc_ = 0;
        if (c == 'A' && hist_pos_ > 0) out += replace_line(prompt, hist_[--hist_pos_]);
        else if (c == 'B' && hist_pos_ < hist_.size()) {
          ++hist_pos_;
          out += replace_line(prompt, hist_pos_ == hist_.size() ? "" : hist_[hist_pos_]);
        }
      }
      continue;
    }
    if (c == '\n' && last_cr_) {  // CRLF from the client counts once
      last_cr_ = false;
      continue;
    }
    last_cr_ = c == '\r';
    switch (c) {
      case 0x1b: esc_ = 1; break;
      case '\r':
      case '\n':
        if (echo_) out += "\r\n";
        ev.push_back({Event::Line, buf_});
        if (!buf_.empty() && (hist_.empty() || hist_.back() != buf_)) hist_.push_back(buf_);
        if (hist_.size() > 100) hist_.erase(hist_.begin());
        hist_pos_ = hist_.size();
        buf_.clear();
        break;
      case 0x7f:
      case 0x08:
        if (!buf_.empty()) {
          buf_.pop_back();
          if (echo_) out += "\b \b";
        }
        break;
      case 0x03:
        if (echo_) out += "^C\r\n";
        buf_.clear();
        ev.push_back({Event::Interrupt, ""});
        break;
      case 0x04:
        if (buf_.empty()) ev.push_back({Event::Eof, ""});
        break;
      case 0x15:  // Ctrl-U
        out += replace_line(prompt, "");
        break;
      case '\t':
        out += on_tab(prompt);
        break;
      case '?':
        if (!in_quotes(buf_)) {
          out += on_help(prompt);
          break;
        }
        [[fallthrough]];
      default:
        if (c >= 0x20 && buf_.size() < 4096) {
          buf_ += ch;
          if (echo_) out += ch;
        }
    }
  }
  return out;
}

}  // namespace fw
