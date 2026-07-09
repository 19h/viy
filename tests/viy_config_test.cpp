#include "viy_config.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using viy::ViyConfig;

namespace {

#define CHECK(expr) do { if ( !(expr) ) { \
  std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
            << ": " #expr "\n"; std::abort(); } } while ( false )

const std::vector<const char *> variables = {
  "VIY_ENABLED", "VIY_MAX_INSNS", "VIY_TIMEOUT_MS", "VIY_MAX_FUNCS",
  "VIY_FUNCS_PER_TICK", "VIY_TICK_MS", "VIY_MAX_EPOCHS",
  "VIY_EXPLORE_RUNS", "VIY_WORKERS", "VIY_MAKE_CODE", "VIY_WANT_DREFS",
  "VIY_STATIC", "VIY_NATIVE", "VIY_DEOBF", "VIY_PERSIST_EVIDENCE",
  "VIY_STRICT_PERMS", "VIY_IMPORT_SUMMARIES", "VIY_PTR_REFS",
  "VIY_TYPE_DATA", "VIY_COMMENTS", "VIY_STRINGS", "VIY_RUNTIME_STRINGS",
  "VIY_UNICODE_STRINGS", "VIY_TABLES", "VIY_FUNCTION_RECOVERY",
  "VIY_TAIL_RECOVERY", "VIY_SMC_EVIDENCE", "VIY_APPLY_RUNTIME_BYTES",
  "VIY_MAX_RUNTIME_BYTES", "VIY_SWITCH", "VIY_PURGE", "VIY_NORET",
  "VIY_SET_NORET", "VIY_ARGREGS", "VIY_OPAQUE", "VIY_OPAQUE_RUNS",
  "VIY_HEXRAYS_BRIDGE"
};

void clear_environment()
{
  for ( const char *name : variables )
#if defined(_WIN32)
    CHECK(_putenv_s(name, "") == 0);
#else
    CHECK(unsetenv(name) == 0);
#endif
}

void set(const char *name, const char *value)
{
#if defined(_WIN32)
  CHECK(_putenv_s(name, value) == 0);
#else
  CHECK(setenv(name, value, 1) == 0);
#endif
}

void test_defaults_and_booleans()
{
  clear_environment();
  const ViyConfig defaults = viy::viy_load_config();
  CHECK(defaults.enabled && defaults.want_native && defaults.want_deobf);
  CHECK(defaults.max_insns == 200000 && defaults.timeout_ms == 1000);
  CHECK(defaults.funcs_per_tick == 2 && defaults.tick_ms == 15);
  CHECK(defaults.max_epochs == 3 && defaults.explore_runs == 4);
  CHECK(defaults.workers == 0 && defaults.opaque_runs == 3);
  CHECK(!defaults.want_switch && !defaults.want_tail_recovery
        && !defaults.apply_runtime_bytes && !defaults.want_hexrays_bridge);

  for ( const char *false_value : {"0", "false", "no", "off"} )
  {
    clear_environment();
    set("VIY_NATIVE", false_value);
    CHECK(!viy::viy_load_config().want_native);
  }
  clear_environment();
  set("VIY_NATIVE", "FALSE");
  CHECK(viy::viy_load_config().want_native); // documented exact tokens only
  set("VIY_DEOBF", "0");
  set("VIY_HEXRAYS_BRIDGE", "yes");
  const ViyConfig toggled = viy::viy_load_config();
  CHECK(!toggled.want_deobf && toggled.want_hexrays_bridge);
}

void test_numeric_validation_and_bounds()
{
  clear_environment();
  set("VIY_MAX_INSNS", "0");
  set("VIY_TIMEOUT_MS", "0");
  set("VIY_MAX_FUNCS", "0x20");
  set("VIY_FUNCS_PER_TICK", "0");
  set("VIY_TICK_MS", "0");
  set("VIY_MAX_EPOCHS", "999999999999999999");
  set("VIY_EXPLORE_RUNS", "999");
  set("VIY_WORKERS", "999");
  set("VIY_OPAQUE_RUNS", "1");
  set("VIY_MAX_RUNTIME_BYTES", "18446744073709551615");
  const ViyConfig bounded = viy::viy_load_config();
  CHECK(bounded.max_insns == 200000 && bounded.timeout_ms == 1000);
  CHECK(bounded.max_funcs == 0x20);
  CHECK(bounded.funcs_per_tick == 1 && bounded.tick_ms == 1);
  CHECK(bounded.max_epochs == 16 && bounded.explore_runs == 64);
  CHECK(bounded.workers == 64 && bounded.opaque_runs == 2);
  CHECK(bounded.max_runtime_bytes == 64ull * 1024 * 1024);

  for ( const char *bad : {"-1", "12junk", "", "   ",
                            "18446744073709551616"} )
  {
    clear_environment();
    set("VIY_MAX_INSNS", bad);
    CHECK(viy::viy_load_config().max_insns == 200000);
  }
  clear_environment();
  set("VIY_MAX_INSNS", "  4096 \t\n");
  CHECK(viy::viy_load_config().max_insns == 4096);
}

} // namespace

int main()
{
  test_defaults_and_booleans();
  test_numeric_validation_and_bounds();
  clear_environment();
  return 0;
}
