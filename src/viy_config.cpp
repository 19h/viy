/*
 * viy_config.cpp — environment-override config loading (no IDA dependency).
 */
#include "viy_config.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

namespace viy {

namespace {

bool env_bool(const char *name, bool dflt)
{
  const char *v = std::getenv(name);
  if ( v == nullptr || v[0] == '\0' )
    return dflt;
  return !(std::strcmp(v, "0") == 0 || std::strcmp(v, "false") == 0
        || std::strcmp(v, "no") == 0 || std::strcmp(v, "off") == 0);
}

uint64_t env_u64(const char *name, uint64_t dflt)
{
  const char *v = std::getenv(name);
  if ( v == nullptr || v[0] == '\0' )
    return dflt;
  while ( *v == ' ' || *v == '\t' )
    ++v;
  if ( *v == '-' )        // reject negatives (would wrap to a huge cap)
    return dflt;
  errno = 0;
  char *end = nullptr;
  unsigned long long parsed = std::strtoull(v, &end, 0);
  if ( end == v || errno == ERANGE )
    return dflt;
  while ( *end == ' ' || *end == '\t' || *end == '\r' || *end == '\n' )
    ++end;
  if ( *end != '\0' )
    return dflt;
  return (uint64_t)parsed;
}

int env_int(const char *name, int dflt)
{
  const uint64_t parsed = env_u64(name, uint64_t(dflt));
  if ( parsed > uint64_t(std::numeric_limits<int>::max()) )
    return std::numeric_limits<int>::max();
  return int(parsed);
}

} // namespace

ViyConfig viy_load_config()
{
  ViyConfig c;
  c.enabled     = env_bool("VIY_ENABLED", c.enabled);
  c.max_insns   = env_u64("VIY_MAX_INSNS", c.max_insns);
  c.timeout_ms  = env_u64("VIY_TIMEOUT_MS", c.timeout_ms);
  c.max_funcs   = env_u64("VIY_MAX_FUNCS", c.max_funcs);
  c.funcs_per_tick = env_int("VIY_FUNCS_PER_TICK", c.funcs_per_tick);
  c.tick_ms     = env_int("VIY_TICK_MS", c.tick_ms);
  c.max_epochs = env_int("VIY_MAX_EPOCHS", c.max_epochs);
  c.explore_runs = env_int("VIY_EXPLORE_RUNS", c.explore_runs);
  c.workers = env_int("VIY_WORKERS", c.workers);
  c.make_code   = env_bool("VIY_MAKE_CODE", c.make_code);
  c.want_drefs  = env_bool("VIY_WANT_DREFS", c.want_drefs);
  c.want_static = env_bool("VIY_STATIC", c.want_static);
  c.want_native = env_bool("VIY_NATIVE", c.want_native);
  c.want_deobf = env_bool("VIY_DEOBF", c.want_deobf);
  c.persist_evidence = env_bool("VIY_PERSIST_EVIDENCE", c.persist_evidence);
  c.strict_perms = env_bool("VIY_STRICT_PERMS", c.strict_perms);
  c.want_import_summaries = env_bool("VIY_IMPORT_SUMMARIES", c.want_import_summaries);
  c.want_ptr_refs   = env_bool("VIY_PTR_REFS", c.want_ptr_refs);
  c.want_data_types = env_bool("VIY_TYPE_DATA", c.want_data_types);
  c.want_comments   = env_bool("VIY_COMMENTS", c.want_comments);
  c.want_strings    = env_bool("VIY_STRINGS", c.want_strings);
  c.want_runtime_strings = env_bool("VIY_RUNTIME_STRINGS", c.want_runtime_strings);
  c.want_unicode_strings = env_bool("VIY_UNICODE_STRINGS", c.want_unicode_strings);
  c.want_tables = env_bool("VIY_TABLES", c.want_tables);
  c.want_function_recovery = env_bool("VIY_FUNCTION_RECOVERY", c.want_function_recovery);
  c.want_tail_recovery = env_bool("VIY_TAIL_RECOVERY", c.want_tail_recovery);
  c.want_smc_evidence = env_bool("VIY_SMC_EVIDENCE", c.want_smc_evidence);
  c.apply_runtime_bytes = env_bool("VIY_APPLY_RUNTIME_BYTES", c.apply_runtime_bytes);
  c.max_runtime_bytes = env_u64("VIY_MAX_RUNTIME_BYTES", c.max_runtime_bytes);
  c.want_switch     = env_bool("VIY_SWITCH", c.want_switch);
  c.want_purge      = env_bool("VIY_PURGE", c.want_purge);
  c.want_noret      = env_bool("VIY_NORET", c.want_noret);
  c.set_noret       = env_bool("VIY_SET_NORET", c.set_noret);
  c.want_argregs    = env_bool("VIY_ARGREGS", c.want_argregs);
  c.want_opaque     = env_bool("VIY_OPAQUE", c.want_opaque);
  c.opaque_runs     = env_int("VIY_OPAQUE_RUNS", c.opaque_runs);
  c.want_hexrays_bridge = env_bool("VIY_HEXRAYS_BRIDGE", c.want_hexrays_bridge);
  if ( c.opaque_runs < 2 )
    c.opaque_runs = 2;
  if ( c.opaque_runs > 16 )
    c.opaque_runs = 16;

  if ( c.funcs_per_tick < 1 )
    c.funcs_per_tick = 1;
  if ( c.tick_ms < 1 )
    c.tick_ms = 1;
  if ( c.max_epochs < 1 )
    c.max_epochs = 1;
  if ( c.max_epochs > 16 )
    c.max_epochs = 16;
  if ( c.explore_runs < 1 )
    c.explore_runs = 1;
  if ( c.explore_runs > 64 )
    c.explore_runs = 64;
  if ( c.workers < 0 )
    c.workers = 0;
  if ( c.workers > 64 )
    c.workers = 64;
  if ( c.max_runtime_bytes > 64ull * 1024 * 1024 )
    c.max_runtime_bytes = 64ull * 1024 * 1024;
  // Never allow an "unbounded" run: the emulator must always terminate.
  if ( c.max_insns == 0 )
    c.max_insns = 200000;
  if ( c.timeout_ms == 0 )
    c.timeout_ms = 1000;
  return c;
}

} // namespace viy
