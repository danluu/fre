#include "fre.hpp"

#include <iostream>
#include <string_view>
#include <type_traits>
#include <utility>

int main() {
  static_assert(!std::is_copy_constructible<fre::Regex>::value, "move-only");
  static_assert(std::is_nothrow_move_constructible<fre::Regex>::value, "noexcept move");

  auto compiled = fre::Regex::compile(std::string_view("needle", 6));
  if (!compiled) {
    std::cerr << compiled.diagnostic.message() << '\n';
    return 20;
  }
  fre::Regex regex = std::move(compiled.value);
  if (!regex.valid()) {
    return 21;
  }

  const std::string_view haystack("zzneedlezz", 10);
  const auto exists = regex.exists(haystack);
  const auto selected = regex.selected_end(haystack);
  const auto match = regex.span(haystack);
  const auto plan = regex.plan();
  if (!exists || !exists.value || !selected || !selected.value.found ||
      selected.value.end != 8 || !match || !match.value.found ||
      match.value.start != 2 || match.value.end != 8 || !plan ||
      plan.value.plan != FRE_V1_PLAN_EXACT_LITERAL) {
    return 22;
  }

  const auto invalid = fre::Regex::compile(std::string_view("(", 1));
  if (invalid || invalid.status != fre::Status::compile_error ||
      invalid.diagnostic.message().empty()) {
    return 23;
  }

  std::cout << "fre C++17 smoke: ok\n";
  return 0;
}
