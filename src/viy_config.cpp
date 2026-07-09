/*
 * viy_config.cpp — environment-override config loading (no IDA dependency).
 */
#include "viy_config.hpp"

#include <cstdlib>
#include <cstring>
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
  char *end = nullptr;
  unsigned long long parsed = std::strtoull(v, &end, 0);
  if ( end == v )
    return dflt;
  return (uint64_t)parsed;
}

} // namespace

ViyConfig viy_load_config()
{
  ViyConfig c;
  c.enabled     = env_bool("VIY_ENABLED", c.enabled);
  c.max_insns   = env_u64("VIY_MAX_INSNS", c.max_insns);
  c.timeout_ms  = env_u64("VIY_TIMEOUT_MS", c.timeout_ms);
  c.max_funcs   = env_u64("VIY_MAX_FUNCS", c.max_funcs);
  c.funcs_per_tick = (int)env_u64("VIY_FUNCS_PER_TICK", (uint64_t)c.funcs_per_tick);
  c.tick_ms     = (int)env_u64("VIY_TICK_MS", (uint64_t)c.tick_ms);
  c.make_code   = env_bool("VIY_MAKE_CODE", c.make_code);
  c.want_drefs  = env_bool("VIY_WANT_DREFS", c.want_drefs);
  c.want_static = env_bool("VIY_STATIC", c.want_static);
  c.want_ptr_refs   = env_bool("VIY_PTR_REFS", c.want_ptr_refs);
  c.want_data_types = env_bool("VIY_TYPE_DATA", c.want_data_types);
  c.want_comments   = env_bool("VIY_COMMENTS", c.want_comments);
  c.want_strings    = env_bool("VIY_STRINGS", c.want_strings);
  c.want_switch     = env_bool("VIY_SWITCH", c.want_switch);
  c.want_purge      = env_bool("VIY_PURGE", c.want_purge);
  c.want_noret      = env_bool("VIY_NORET", c.want_noret);
  c.set_noret       = env_bool("VIY_SET_NORET", c.set_noret);
  c.want_argregs    = env_bool("VIY_ARGREGS", c.want_argregs);
  c.want_opaque     = env_bool("VIY_OPAQUE", c.want_opaque);
  c.opaque_runs     = (int)env_u64("VIY_OPAQUE_RUNS", (uint64_t)c.opaque_runs);
  if ( c.opaque_runs < 2 )
    c.opaque_runs = 2;
  if ( c.opaque_runs > 16 )
    c.opaque_runs = 16;

  if ( c.funcs_per_tick < 1 )
    c.funcs_per_tick = 1;
  if ( c.tick_ms < 1 )
    c.tick_ms = 1;
  // Never allow an "unbounded" run: the emulator must always terminate.
  if ( c.max_insns == 0 )
    c.max_insns = 200000;
  if ( c.timeout_ms == 0 )
    c.timeout_ms = 1000;
  return c;
}

} // namespace viy
