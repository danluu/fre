// Test-only constructor and matcher oracle for pinned RE2. Not production code.

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "re2/re2.h"

namespace {

constexpr std::string_view kRevision =
    "972a15cedd008d846f1a39b2e88ce48d7f166cbd";
constexpr size_t kMaximumOracleGroups = 4096;

int HexNibble(char c) {
  if ('0' <= c && c <= '9') return c - '0';
  if ('a' <= c && c <= 'f') return c - 'a' + 10;
  if ('A' <= c && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool DecodeHex(std::string_view hex, std::string* out) {
  if (hex == "-") {
    out->clear();
    return true;
  }
  if ((hex.size() & 1U) != 0U) return false;
  out->clear();
  out->reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int high = HexNibble(hex[i]);
    const int low = HexNibble(hex[i + 1]);
    if (high < 0 || low < 0) return false;
    out->push_back(static_cast<char>((high << 4) | low));
  }
  return true;
}

std::string EncodeHex(std::string_view bytes) {
  constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char byte : bytes) {
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

bool HasFlag(std::string_view flags, std::string_view wanted) {
  size_t begin = 0;
  while (begin <= flags.size()) {
    const size_t comma = flags.find(',', begin);
    const size_t end = comma == std::string_view::npos ? flags.size() : comma;
    if (flags.substr(begin, end - begin) == wanted) return true;
    if (comma == std::string_view::npos) break;
    begin = comma + 1;
  }
  return false;
}

re2::RE2::Options MakeOptions(std::string_view syntax,
                              std::string_view encoding,
                              std::string_view flags) {
  re2::RE2::Options options;
  options.set_log_errors(false);
  options.set_posix_syntax(syntax == "posix");
  options.set_longest_match(HasFlag(flags, "longest"));
  options.set_encoding(encoding == "latin1"
                           ? re2::RE2::Options::EncodingLatin1
                           : re2::RE2::Options::EncodingUTF8);
  options.set_literal(HasFlag(flags, "literal"));
  options.set_never_nl(HasFlag(flags, "never_nl"));
  options.set_dot_nl(HasFlag(flags, "dot_nl"));
  options.set_never_capture(HasFlag(flags, "never_capture"));
  options.set_case_sensitive(!HasFlag(flags, "insensitive"));
  options.set_perl_classes(HasFlag(flags, "perl_classes"));
  options.set_word_boundary(HasFlag(flags, "word_boundary"));
  options.set_one_line(HasFlag(flags, "one_line"));
  return options;
}

std::string EncodeNames(const std::map<std::string, int>& names) {
  std::string out;
  bool first = true;
  for (const auto& [name, index] : names) {
    if (!first) out.push_back(',');
    first = false;
    out += EncodeHex(name);
    out.push_back(':');
    out += std::to_string(index);
  }
  return out;
}

std::string EncodeSpans(const std::vector<absl::string_view>& groups,
                        const std::string& haystack) {
  std::string out;
  bool first = true;
  const uintptr_t begin = reinterpret_cast<uintptr_t>(haystack.data());
  const uintptr_t end = begin + haystack.size();
  for (const absl::string_view group : groups) {
    if (!first) out.push_back(',');
    first = false;
    const uintptr_t address = reinterpret_cast<uintptr_t>(group.data());
    if (group.data() == nullptr || address < begin || address > end ||
        group.size() > static_cast<size_t>(end - address)) {
      out += "-1:-1";
      continue;
    }
    const ptrdiff_t start = static_cast<ptrdiff_t>(address - begin);
    out += std::to_string(start);
    out.push_back(':');
    out += std::to_string(start + static_cast<ptrdiff_t>(group.size()));
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 6) {
    std::cerr << "usage: fre-re2-oracle PATTERN_HEX HAYSTACK_HEX "
                 "perl|posix utf8|latin1 FLAGS\n";
    return 2;
  }
  std::string pattern;
  std::string haystack;
  if (!DecodeHex(argv[1], &pattern) || !DecodeHex(argv[2], &haystack)) {
    std::cerr << "pattern and haystack must be even-length hexadecimal\n";
    return 2;
  }
  const std::string_view syntax(argv[3]);
  const std::string_view encoding(argv[4]);
  if ((syntax != "perl" && syntax != "posix") ||
      (encoding != "utf8" && encoding != "latin1")) {
    std::cerr << "invalid syntax or encoding selector\n";
    return 2;
  }

  const re2::RE2::Options options = MakeOptions(syntax, encoding, argv[5]);
  const re2::RE2 expression(absl::string_view(pattern), options);
  std::cout << "fre.re2-oracle.v1\t" << kRevision << '\t'
            << (expression.ok() ? 1 : 0) << '\t'
            << static_cast<int>(expression.error_code()) << '\t'
            << EncodeHex(expression.error_arg()) << '\t'
            << EncodeHex(expression.error()) << '\t';
  if (!expression.ok()) {
    std::cout << "-1\t\t-1\t\n";
    return 0;
  }

  const int captures = expression.NumberOfCapturingGroups();
  std::cout << captures << '\t'
            << EncodeNames(expression.NamedCapturingGroups()) << '\t';
  if (captures < 0 || static_cast<size_t>(captures) > kMaximumOracleGroups) {
    std::cout << "-2\t\n";
    return 0;
  }
  std::vector<absl::string_view> groups(static_cast<size_t>(captures) + 1U);
  const bool matched = expression.Match(
      absl::string_view(haystack), 0, haystack.size(), re2::RE2::UNANCHORED,
      groups.data(), static_cast<int>(groups.size()));
  std::cout << (matched ? 1 : 0) << '\t';
  if (matched) std::cout << EncodeSpans(groups, haystack);
  std::cout << '\n';
  return 0;
}
