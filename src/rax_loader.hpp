/*
 * rax_loader.hpp — graceful runtime loader for librax (the RAX emulation engine).
 *
 * viy compiles against rax.h ONLY for the C typedefs and the RAX_API_MAJOR/MINOR
 * constants; it links NOTHING against librax. Every rax_* function is referenced
 * through `decltype` in an unevaluated context, so no rax_* symbol is ever
 * odr-used and the plugin has no load-time dependency on librax. All calls go
 * through the function-pointer table resolved here at runtime via dlopen/dlsym.
 *
 * A missing, unloadable, ABI-incompatible, or symbol-incomplete library yields a
 * clean "unavailable" result (rax_load() == nullptr) — never a hard link
 * dependency, never a crash, never an exception. This is what lets viy be
 * "transparent and invisible": IDA always loads the plugin; when librax is not
 * present the plugin simply does nothing.
 *
 */
#pragma once

#include <rax.h> // rax_* declarations (typedefs + constants only — NO link dependency)

namespace viy {

// The subset of the rax C ABI that viy drives. Listed once as (field, symbol)
// pairs so the struct fields and the dlsym names can never drift.
#define VIY_RAX_FUNCS(X)                                     \
  /* version + diagnostics (used for the ABI gate) */        \
  X(version,                  rax_version)                   \
  X(version_string,           rax_version_string)            \
  X(strerror,                 rax_strerror)                  \
  /* engine lifecycle */                                     \
  X(engine_open_config,       rax_engine_open_config)        \
  X(engine_close,             rax_engine_close)              \
  X(engine_supports_stepping, rax_engine_supports_stepping)  \
  X(engine_errmsg,            rax_engine_errmsg)             \
  /* memory */                                               \
  X(mem_map,                  rax_mem_map)                   \
  X(mem_protect,              rax_mem_protect)               \
  X(mem_write,                rax_mem_write)                 \
  /* registers */                                            \
  X(reg_write_u64,            rax_reg_write_u64)             \
  X(reg_read_u64,             rax_reg_read_u64)              \
  /* execution control */                                    \
  X(emu_start,                rax_emu_start)                 \
  X(emu_stop,                 rax_emu_stop)                  \
  X(emu_last_exit,            rax_emu_last_exit)             \
  X(emu_icount,               rax_emu_icount)                \
  /* hooks */                                                \
  X(hook_add_code,            rax_hook_add_code)             \
  X(hook_add_mem,             rax_hook_add_mem)              \
  X(hook_add_invalid,         rax_hook_add_invalid)          \
  X(hook_del,                 rax_hook_del)                  \
  /* snapshots (per-run isolation) */                        \
  X(context_save,             rax_context_save)              \
  X(context_restore,          rax_context_restore)

// Optional capabilities.  These are deliberately kept out of the mandatory
// surface above: an older, ABI-compatible librax must remain usable for the
// core discovery pass.  New analyses probe the corresponding field before use
// and degrade independently when a capability is absent.
#define VIY_RAX_OPTIONAL_FUNCS(X)                            \
  /* lifecycle/introspection */                              \
  X(engine_reset,             rax_engine_reset)              \
  X(engine_arch,              rax_engine_arch)               \
  X(engine_mode,              rax_engine_mode)               \
  /* complete memory inspection */                           \
  X(mem_unmap,               rax_mem_unmap)                  \
  X(mem_read,                rax_mem_read)                   \
  X(mem_write_virt,          rax_mem_write_virt)             \
  X(mem_read_virt,           rax_mem_read_virt)              \
  X(mem_translate,           rax_mem_translate)              \
  X(mem_regions,             rax_mem_regions)                \
  /* complete register access */                             \
  X(reg_size,                rax_reg_size)                   \
  X(reg_read,                rax_reg_read)                   \
  X(reg_write,               rax_reg_write)                  \
  /* granular execution */                                   \
  X(emu_step,                rax_emu_step)                   \
  X(interrupt,               rax_interrupt)                  \
  X(nmi,                     rax_nmi)                        \
  X(can_interrupt,           rax_can_interrupt)              \
  /* richer hooks for environment models and coverage */     \
  X(hook_add_block,          rax_hook_add_block)             \
  X(hook_add_intr,           rax_hook_add_intr)              \
  X(hook_add_io_in,          rax_hook_add_io_in)             \
  X(hook_add_io_out,         rax_hook_add_io_out)            \
  X(hook_add_mmio_read,      rax_hook_add_mmio_read)         \
  X(hook_add_mmio_write,     rax_hook_add_mmio_write)

// Resolved rax_* entry points. Every field is valid iff rax_load() != nullptr.
struct RaxApi
{
#define X(field, sym) decltype(&sym) field = nullptr;
  VIY_RAX_FUNCS(X)
  VIY_RAX_OPTIONAL_FUNCS(X)
#undef X

  // Optional (rax API >= 1.2): the static instruction decoder. May be null with
  // an older librax that only provides the emulation surface — callers must
  // check `decode != nullptr` (see rax_can_decode) and degrade gracefully.
  decltype(&rax_decode) decode = nullptr;

  // Optional (rax API >= 1.3): stateless SMIR instruction-effect analysis.
  // The result is entirely caller-owned fixed-layout data; no Rust pointer
  // crosses this boundary. Older 1.x libraries remain fully usable.
  decltype(&rax_analyze) analyze = nullptr;
};

// Load librax exactly once for the process (thread-safe), caching the outcome.
// Returns the resolved API on success, or nullptr when emulation is unavailable
// (librax absent / unloadable / ABI-incompatible / missing a required symbol).
// Safe to call from any thread; in practice invoked once on the main thread.
const RaxApi *rax_load();

// Convenience: true iff librax is loaded and ABI-compatible.
inline bool rax_available() { return rax_load() != nullptr; }

// True iff the loaded librax additionally exposes the static decoder (rax >= 1.2).
inline bool rax_can_decode()
{
  const RaxApi *a = rax_load();
  return a != nullptr && a->decode != nullptr;
}

// True iff the loaded librax additionally exposes the versioned stateless
// instruction-effect analyzer (rax >= 1.3).
inline bool rax_can_analyze()
{
  const RaxApi *a = rax_load();
  return a != nullptr && a->analyze != nullptr;
}

// Precise reason emulation is unavailable (empty when available). For an
// optional one-line diagnostic; viy stays silent by default.
const char *rax_unavailable_reason();

} // namespace viy
