#include "fre.h"

#include <stdio.h>
#include <string.h>

static void init_header(void *record, size_t size) {
  fre_v1_header *header = (fre_v1_header *)record;
  memset(record, 0, size);
  header->abi_version = FRE_V1_ABI_VERSION;
  header->struct_size = (uint32_t)size;
}

int main(void) {
  fre_v1_abi_descriptor descriptor;
  init_header(&descriptor, sizeof(descriptor));
  if (fre_v1_get_abi_descriptor(&descriptor) != FRE_V1_STATUS_OK ||
      descriptor.abi_major != 1 ||
      (descriptor.feature_bits & FRE_V1_FEATURE_SPAN) == 0) {
    return 10;
  }

  fre_v1_config config;
  init_header(&config, sizeof(config));
  if (fre_v1_config_default(&config) != FRE_V1_STATUS_OK ||
      config.profile != FRE_V1_PROFILE_RUST_BYTES ||
      config.jit_policy != FRE_V1_JIT_DENY) {
    return 11;
  }

  static const uint8_t pattern[] = {'n', 'e', 'e', 'd', 'l', 'e'};
  static const uint8_t haystack[] = {'z', 'z', 'n', 'e', 'e', 'd', 'l', 'e', 'z'};
  fre_v1_diagnostic diagnostic;
  init_header(&diagnostic, sizeof(diagnostic));
  fre_v1_regex *regex = NULL;
  fre_v1_status status = fre_v1_regex_compile(
      &config, pattern, sizeof(pattern), &regex, &diagnostic);
  if (status != FRE_V1_STATUS_OK || regex == NULL) {
    (void)fwrite(diagnostic.message, 1, diagnostic.message_length, stderr);
    return 12;
  }

  fre_v1_exists_result exists;
  init_header(&exists, sizeof(exists));
  if (fre_v1_regex_exists(regex, haystack, sizeof(haystack), &exists, NULL) !=
          FRE_V1_STATUS_OK ||
      exists.matched != 1) {
    return 13;
  }

  fre_v1_selected_end_result selected;
  init_header(&selected, sizeof(selected));
  if (fre_v1_regex_selected_end(
          regex, haystack, sizeof(haystack), &selected, NULL) != FRE_V1_STATUS_OK ||
      selected.found != 1 || selected.end != 8) {
    return 14;
  }

  fre_v1_match_result match;
  init_header(&match, sizeof(match));
  if (fre_v1_regex_span(regex, haystack, sizeof(haystack), &match, NULL) !=
          FRE_V1_STATUS_OK ||
      match.found != 1 || match.start != 2 || match.end != 8) {
    return 15;
  }

  fre_v1_plan_info plan;
  init_header(&plan, sizeof(plan));
  if (fre_v1_regex_plan(regex, &plan, NULL) != FRE_V1_STATUS_OK ||
      plan.plan != FRE_V1_PLAN_EXACT_LITERAL) {
    return 16;
  }

  if (fre_v1_regex_retain(regex) != FRE_V1_STATUS_OK ||
      fre_v1_regex_release(regex) != FRE_V1_STATUS_OK ||
      fre_v1_regex_release(regex) != FRE_V1_STATUS_OK) {
    return 17;
  }

  puts("fre C11 smoke: ok");
  return 0;
}
