/*
 * viy.cpp — plugin lifecycle & the transparent, chunked sweep.
 *
 * viy is a hidden, multi-IDB, database-modifying plugin. IDA instantiates one
 * plugmod per open database; in its constructor viy hooks HT_IDB and waits for
 * the first auto-analysis pass to finish (idb_event::auto_empty_finally). It
 * then snapshots the program, and emulates each function through rax on the main
 * thread in small timer-driven batches so the UI never freezes. Every reference
 * the emulation reveals but the static analysis missed is added (see
 * ref_discovery). If librax is absent or the target architecture/backend can't
 * be driven, viy does nothing at all — no dialogs, no errors, at most a single
 * summary line when it actually found something.
 */
#include <unordered_set>

#include <pro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>

#include "rax_loader.hpp"
#include "viy_config.hpp"
#include "program_model.hpp"
#include "emu_driver.hpp"
#include "ref_discovery.hpp"
#include "static_decoder.hpp"
#include "enrich.hpp"
#include "advanced.hpp"

using namespace viy;

//-----------------------------------------------------------------------------
struct viy_t;

struct viy_idb_listener_t : public event_listener_t
{
  viy_t *owner = nullptr;
  ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//-----------------------------------------------------------------------------
struct viy_t : public plugmod_t
{
  ViyConfig cfg;
  viy_idb_listener_t idb;
  qtimer_t timer = nullptr;

  ProgramImage img;
  EmuDriver *drv = nullptr;
  const RaxApi *api = nullptr;

  size_t next = 0;         // next function-entry index to emulate
  size_t funcs_done = 0;
  RefStats stats;          // from the emulation (indirect) pass
  RefStats sstats;         // from the static-decode (direct) pass
  EnrichStats estats;      // from the value-derived enrichment pass
  AdvStats astats;         // from the function-level advanced analyses
  bool started = false;

  viy_t();
  virtual ~viy_t();
  virtual bool idaapi run(size_t) override;

  void on_analysis_done();
  void start_sweep();
  bool process_batch(int count); // true => more entries remain
  void finish();
};

//-----------------------------------------------------------------------------
ssize_t idaapi viy_idb_listener_t::on_event(ssize_t code, va_list)
{
  if ( code == idb_event::auto_empty_finally && owner != nullptr )
    owner->on_analysis_done();
  return 0;
}

//-----------------------------------------------------------------------------
static int idaapi viy_sweep_cb(void *ud)
{
  viy_t *self = static_cast<viy_t *>(ud);
  if ( self->process_batch(self->cfg.funcs_per_tick) )
    return self->cfg.tick_ms; // keep firing at the same cadence
  self->timer = nullptr;      // IDA unregisters the timer when we return -1
  self->finish();
  return -1;
}

//-----------------------------------------------------------------------------
viy_t::viy_t()
{
  cfg = viy_load_config();
  idb.owner = this;
  hook_event_listener(HT_IDB, &idb);
  // If the database is already fully analyzed when we load, run right away.
  if ( auto_is_ok() )
    on_analysis_done();
}

//-----------------------------------------------------------------------------
viy_t::~viy_t()
{
  if ( timer != nullptr )
  {
    unregister_timer(timer);
    timer = nullptr;
  }
  unhook_event_listener(HT_IDB, &idb);
  delete drv;
  drv = nullptr;
}

//-----------------------------------------------------------------------------
void viy_t::on_analysis_done()
{
  if ( started )
    return; // one-shot per database

  if ( !cfg.enabled )
    return;

  api = rax_load();
  if ( api == nullptr )
    return; // librax unavailable — stay completely silent

  ViyArch arch;
  bool be;
  if ( !viy_detect_arch(arch, be) )
    return; // architecture viy does not drive

  viy_snapshot(img, cfg);
  if ( img.entries.empty() )
    return;

  // The dynamic pass needs a stepping+snapshot-capable backend (x86-64, AArch64
  // today). The static pass only needs the decoder, so it runs even where
  // emulation cannot discover — e.g. AArch32, which rax runs to-exit (no code
  // hooks) but decodes fully.
  drv = new EmuDriver(api, img);
  const bool can_emulate = drv->can_discover();
  if ( !can_emulate )
  {
    delete drv; // free the engine; the static pass does not need it
    drv = nullptr;
  }
  const bool static_arch_ok = img.arch == ViyArch::X86_32 || img.arch == ViyArch::X86_64
                           || img.arch == ViyArch::ARM64 || img.arch == ViyArch::ARM32;
  const bool can_static = cfg.want_static && api->decode != nullptr && static_arch_ok;

  if ( !can_emulate && !can_static )
    return; // neither pass can run on this database/backend

  started = true;
  next = 0;
  funcs_done = 0;
  stats = RefStats{};
  sstats = RefStats{};
  estats = EnrichStats{};
  astats = AdvStats{};
  start_sweep();
}

//-----------------------------------------------------------------------------
void viy_t::start_sweep()
{
  timer = register_timer(cfg.tick_ms, viy_sweep_cb, this);
  if ( timer == nullptr )
  {
    // No UI timer available (e.g. headless idalib): run to completion inline.
    while ( process_batch(cfg.funcs_per_tick ) )
      ; // keep going
    finish();
  }
}

//-----------------------------------------------------------------------------
bool viy_t::process_batch(int count)
{
  for ( int i = 0; i < count && next < img.entries.size(); ++i, ++next )
  {
    const uint64_t fstart = img.entries[next].start;
    const uint64_t fend   = img.entries[next].end;

    // Dynamic pass: emulate to resolve INDIRECT control flow + data refs.
    // (drv is null when the backend can't discover; the static pass still runs.)
    EmuEvents ev;
    EmuOutcome outcome;
    std::unordered_set<uint64_t> reached;
    if ( drv != nullptr )
    {
      drv->emulate_from(fstart, fend, cfg, ev, &outcome, cfg.want_opaque, /*seed=*/0);
      if ( cfg.want_opaque )
      {
        // Extra runs with varied inputs to gauge which branch sides are
        // reachable (opaque-predicate hints).
        reached.insert(ev.exec_pcs.begin(), ev.exec_pcs.end());
        for ( int k = 1; k < cfg.opaque_runs; ++k )
        {
          EmuEvents ev2;
          drv->emulate_from(fstart, fend, cfg, ev2, nullptr, /*record_pcs=*/true,
                            (uint64_t)k * 2654435761u + 1u);
          reached.insert(ev2.exec_pcs.begin(), ev2.exec_pcs.end());
        }
      }
    }
    RefStats s = viy_apply_missing(ev, cfg);
    stats.crefs += s.crefs;
    stats.drefs += s.drefs;
    stats.code_made += s.code_made;

    // Enrichment: turn the concrete values observed during emulation into typed
    // pointers, typed globals, and resolved-target comments.
    EnrichStats en = viy_enrich(ev, cfg);
    estats.ptr_refs += en.ptr_refs;
    estats.typed    += en.typed;
    estats.strings  += en.strings;
    estats.comments += en.comments;

    // No-return needs corroboration: only when the natural (seed 0) run halted
    // without returning do we spend a few varied-input runs to confirm that NO
    // input path returns — a single zero-argument run is never trusted.
    bool noret_corroborated = false;
    if ( drv != nullptr && (cfg.want_noret || cfg.set_noret)
      && !outcome.returned
      && (outcome.stop_reason == RAX_STOP_HLT || outcome.stop_reason == RAX_STOP_SHUTDOWN) )
    {
      bool any_return = false;
      for ( int k = 1; k <= 4 && !any_return; ++k )
      {
        EmuEvents evx;
        EmuOutcome ox;
        drv->emulate_from(fstart, fend, cfg, evx, &ox, /*record_pcs=*/false,
                          (uint64_t)k * 0x9E3779B1u + 7u);
        if ( ox.returned )
          any_return = true;
      }
      noret_corroborated = !any_return;
    }

    // Advanced: switch reconstruction, stack purge, no-return / arg-reg /
    // opaque-predicate hints.
    viy_advanced(img.arch, fstart, fend, ev, outcome, reached, noret_corroborated, cfg, astats);

    // Static pass: rax's decoder recovers any DIRECT targets IDA missed.
    if ( cfg.want_static )
      viy_static_decode_func(api, img.arch, img.big_endian, fstart, fend, cfg, sstats);

    ++funcs_done;
  }
  return next < img.entries.size();
}

//-----------------------------------------------------------------------------
void viy_t::finish()
{
  const unsigned long long ind_c = (unsigned long long)stats.crefs;   // indirect (emulated)
  const unsigned long long dir_c = (unsigned long long)sstats.crefs;  // direct (static decode)
  const unsigned long long drefs = (unsigned long long)stats.drefs;
  const unsigned long long ptrs  = (unsigned long long)estats.ptr_refs;
  const unsigned long long typed = (unsigned long long)estats.typed;
  const unsigned long long strs  = (unsigned long long)estats.strings;
  const unsigned long long cmts  = (unsigned long long)estats.comments;
  const unsigned long long sw    = (unsigned long long)astats.switches;
  const unsigned long long pg    = (unsigned long long)astats.purges;
  const unsigned long long nr    = (unsigned long long)astats.norets;
  const unsigned long long ar    = (unsigned long long)astats.argregs;
  const unsigned long long op    = (unsigned long long)astats.opaque;
  if ( ind_c || dir_c || drefs || ptrs || typed || strs || cmts || sw || pg || nr || ar || op )
  {
    const char *rv = (api != nullptr && api->version_string != nullptr)
                   ? api->version_string() : "?";
    msg("viy: %llu code xref(s) [%llu indirect, %llu direct], %llu data xref(s), "
        "%llu ptr, %llu typed, %llu string(s); "
        "%llu switch(es), %llu purge(s), %llu noret, %llu argregs, %llu opaque; "
        "%llu comment(s) across %llu function(s) [rax %s]\n",
        ind_c + dir_c, ind_c, dir_c, drefs, ptrs, typed, strs,
        sw, pg, nr, ar, op, cmts,
        (unsigned long long)funcs_done, rv);
  }
  // Found nothing => say nothing.
}

//-----------------------------------------------------------------------------
bool idaapi viy_t::run(size_t)
{
  // Hidden plugin: normally driven by auto_empty_finally. If invoked manually
  // (e.g. via the plugin API), kick off the sweep if it has not run yet.
  if ( !started )
    on_analysis_done();
  return true;
}

//-----------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new viy_t;
}

//-----------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI | PLUGIN_MOD | PLUGIN_HIDE, // per-IDB, changes DB, invisible in menus
  init,
  nullptr, // term  (must be nullptr for PLUGIN_MULTI)
  nullptr, // run   (must be nullptr for PLUGIN_MULTI; plugmod_t::run is used)
  "viy: recover indirect xrefs the analysis missed, via rax emulation",
  "",
  "viy",
};
