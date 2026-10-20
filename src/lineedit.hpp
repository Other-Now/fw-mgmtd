// Terminal line editor for the SSH shell: echo, backspace, Ctrl-C/D/U, history
// (up/down), TAB completion and '?' help. Pure byte-in/bytes-out so it can be
// unit-tested without a terminal.
#pragma once
#include <functional>
#include <string>
#include <vector>

namespace fw {

class LineEditor {
 public:
  using Completer = std::function<std::vector<std::string>(const std::string& line)>;
  struct Event {
    enum Kind { Line, Eof, Interrupt } kind;
    std::string line;
  };

  LineEditor(Completer c, bool echo) : complete_(std::move(c)), echo_(echo) {}
  // Returns bytes to send back to the terminal; appends completed lines to ev.
  std::string feed(const std::string& in, std::vector<Event>& ev, const std::string& prompt);
  const std::string& buffer() const { return buf_; }

 private:
  std::string on_tab(const std::string& prompt);
  std::string on_help(const std::string& prompt);
  std::string replace_line(const std::string& prompt, const std::string& line);

  Completer complete_;
  bool echo_;
  std::string buf_;
  int esc_ = 0;  // 0 none, 1 saw ESC, 2 saw ESC [
  bool last_cr_ = false;
  std::vector<std::string> hist_;
  size_t hist_pos_ = 0;
};

}  // namespace fw
