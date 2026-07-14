#ifndef FRE_V1_HPP_INCLUDED
#define FRE_V1_HPP_INCLUDED

#include "fre.h"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>

namespace fre {

enum class Status : std::uint32_t {
  ok = FRE_V1_STATUS_OK,
  invalid_argument = FRE_V1_STATUS_INVALID_ARGUMENT,
  abi_mismatch = FRE_V1_STATUS_ABI_MISMATCH,
  struct_too_small = FRE_V1_STATUS_STRUCT_TOO_SMALL,
  invalid_pattern_encoding = FRE_V1_STATUS_INVALID_PATTERN_ENCODING,
  unsupported_profile = FRE_V1_STATUS_UNSUPPORTED_PROFILE,
  unsupported_config = FRE_V1_STATUS_UNSUPPORTED_CONFIG,
  compile_error = FRE_V1_STATUS_COMPILE_ERROR,
  search_error = FRE_V1_STATUS_SEARCH_ERROR,
  panic = FRE_V1_STATUS_PANIC,
  null_with_nonzero_length = FRE_V1_STATUS_NULL_WITH_NONZERO_LENGTH,
  length_overflow = FRE_V1_STATUS_LENGTH_OVERFLOW,
};

class Diagnostic {
 public:
  Diagnostic() noexcept : value_{} {
    value_.abi_version = FRE_V1_ABI_VERSION;
    value_.struct_size = static_cast<std::uint32_t>(sizeof(value_));
  }

  std::uint32_t category() const noexcept { return value_.category; }
  bool truncated() const noexcept { return value_.message_truncated != 0; }
  std::string_view message() const noexcept {
    return {reinterpret_cast<const char *>(value_.message), value_.message_length};
  }

 private:
  friend class Regex;
  fre_v1_diagnostic value_;
};

template <typename T>
struct Result {
  Status status = Status::invalid_argument;
  T value{};
  Diagnostic diagnostic{};

  explicit operator bool() const noexcept { return status == Status::ok; }
};

struct SelectedEnd {
  bool found = false;
  std::size_t end = 0;
};

struct Match {
  bool found = false;
  std::size_t start = 0;
  std::size_t end = 0;
};

class CompileResult;

class Regex {
 public:
  Regex() noexcept = default;
  Regex(const Regex &) = delete;
  Regex &operator=(const Regex &) = delete;

  Regex(Regex &&other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

  Regex &operator=(Regex &&other) noexcept {
    if (this != &other) {
      reset();
      handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
  }

  ~Regex() noexcept { reset(); }

  static CompileResult compile(std::string_view pattern) noexcept;
  static CompileResult compile(
      std::string_view pattern, const fre_v1_config &config) noexcept;

  bool valid() const noexcept { return handle_ != nullptr; }

  Result<bool> exists(std::string_view haystack) const noexcept {
    Result<bool> result;
    fre_v1_exists_result output = FRE_V1_RECORD_INIT(fre_v1_exists_result);
    result.status = static_cast<Status>(fre_v1_regex_exists(
        handle_, bytes(haystack), haystack.size(), &output,
        &result.diagnostic.value_));
    if (result.status == Status::ok) {
      result.value = output.matched != 0;
    }
    return result;
  }

  Result<SelectedEnd> selected_end(std::string_view haystack) const noexcept {
    Result<SelectedEnd> result;
    fre_v1_selected_end_result output =
        FRE_V1_RECORD_INIT(fre_v1_selected_end_result);
    result.status = static_cast<Status>(fre_v1_regex_selected_end(
        handle_, bytes(haystack), haystack.size(), &output,
        &result.diagnostic.value_));
    if (result.status == Status::ok) {
      result.value = {output.found != 0, output.end};
    }
    return result;
  }

  Result<Match> span(std::string_view haystack) const noexcept {
    Result<Match> result;
    fre_v1_match_result output = FRE_V1_RECORD_INIT(fre_v1_match_result);
    result.status = static_cast<Status>(fre_v1_regex_span(
        handle_, bytes(haystack), haystack.size(), &output,
        &result.diagnostic.value_));
    if (result.status == Status::ok) {
      result.value = {output.found != 0, output.start, output.end};
    }
    return result;
  }

  Result<fre_v1_plan_info> plan() const noexcept {
    Result<fre_v1_plan_info> result;
    result.value = FRE_V1_RECORD_INIT(fre_v1_plan_info);
    result.status = static_cast<Status>(
        fre_v1_regex_plan(handle_, &result.value, &result.diagnostic.value_));
    return result;
  }

 private:
  friend class CompileResult;

  explicit Regex(fre_v1_regex *handle) noexcept : handle_(handle) {}

  static const std::uint8_t *bytes(std::string_view view) noexcept {
    return reinterpret_cast<const std::uint8_t *>(view.data());
  }

  void reset() noexcept {
    if (handle_ != nullptr) {
      (void)fre_v1_regex_release(handle_);
      handle_ = nullptr;
    }
  }

  fre_v1_regex *handle_ = nullptr;
};

class CompileResult {
 public:
  CompileResult() noexcept = default;
  CompileResult(const CompileResult &) = delete;
  CompileResult &operator=(const CompileResult &) = delete;
  CompileResult(CompileResult &&) noexcept = default;
  CompileResult &operator=(CompileResult &&) noexcept = default;

  explicit operator bool() const noexcept { return status == Status::ok; }

  Status status = Status::invalid_argument;
  Regex value{};
  Diagnostic diagnostic{};
};

inline CompileResult Regex::compile(std::string_view pattern) noexcept {
  fre_v1_config config = FRE_V1_RECORD_INIT(fre_v1_config);
  CompileResult result;
  result.status = static_cast<Status>(fre_v1_config_default(&config));
  if (result.status != Status::ok) {
    return result;
  }
  return compile(pattern, config);
}

inline CompileResult Regex::compile(
    std::string_view pattern, const fre_v1_config &config) noexcept {
  CompileResult result;
  fre_v1_regex *handle = nullptr;
  result.status = static_cast<Status>(fre_v1_regex_compile(
      &config, bytes(pattern), pattern.size(), &handle,
      &result.diagnostic.value_));
  if (result.status == Status::ok) {
    result.value = Regex(handle);
  }
  return result;
}

static_assert(!std::is_copy_constructible<Regex>::value, "Regex is move-only");
static_assert(std::is_nothrow_move_constructible<Regex>::value, "Regex move is noexcept");

}  // namespace fre

#endif /* FRE_V1_HPP_INCLUDED */
