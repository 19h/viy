/*
 * ref_discovery.cpp — classify emulation events, diff against existing xrefs,
 * and add only the ones the main analysis missed. Main thread only.
 */
#include "ref_discovery.hpp"

#include <pro.h>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <auto.hpp>

namespace viy {

namespace {

// Does a code ref already exist from->to? (XREF_CODE returns only crefs.)
bool cref_exists(ea_t from, ea_t to)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_from(from, XREF_CODE); ok; ok = xb.next_from() )
    if ( xb.to == to )
      return true;
  return false;
}

// Does a data ref already exist from->to? (XREF_DATA returns only drefs.)
bool dref_exists(ea_t from, ea_t to)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_from(from, XREF_DATA); ok; ok = xb.next_from() )
    if ( xb.to == to )
      return true;
  return false;
}

// A code target must live in an executable segment (perm==0 means "no info",
// which we allow so bare loaders aren't over-filtered).
bool target_is_executable(ea_t to)
{
  segment_t *s = getseg(to);
  if ( s == nullptr )
    return false;
  return s->perm == 0 || (s->perm & SEGPERM_EXEC) != 0;
}

} // namespace

bool viy_try_add_cref(uint64_t from64, uint64_t to64, bool is_call,
                      const ViyConfig &cfg, RefStats &stats)
{
  const ea_t from = (ea_t)from64;
  const ea_t to   = (ea_t)to64;

  if ( !is_mapped(to) )
    return false;                       // target must be inside the loaded image
  // A code target must live in an executable segment and begin an instruction —
  // never point a cref into data or mid-instruction. This is the guard that
  // stops a garbage target (e.g. an in-image data address the loosely seeded
  // emulation branched to) from becoming a spurious function/cref that would
  // rewrite data bytes as code.
  if ( !target_is_executable(to) || is_tail(get_flags(to)) )
    return false;
  const flags64_t ff = get_flags(from);
  if ( !is_head(ff) || !is_code(ff) )   // source must be a real instruction
    return false;
  if ( cref_exists(from, to) )          // already known — do not duplicate
    return false;

  // The arches viy drives (x86-32/64, ARM32/64) have a flat address space, so
  // every transfer is "near". Far types belong to segmented 16-bit models we do
  // not handle; emitting them here would mislabel ordinary refs.
  const cref_t type = is_call ? fl_CN : fl_JN;
  if ( !add_cref(from, to, cref_t(int(type) | XREF_USER)) )
    return false;
  ++stats.crefs;

  // Turn a freshly discovered, still-unexplored target into code so the rest of
  // the analysis can follow it. (fl_CN already creates a function.)
  if ( cfg.make_code && is_unknown(get_flags(to)) )
  {
    if ( is_call )
      auto_make_proc(to);
    else
      auto_make_code(to);
    plan_ea(to);
    ++stats.code_made;
  }
  return true;
}

RefStats viy_apply_missing(const EmuEvents &ev, const ViyConfig &cfg)
{
  RefStats st;

  // ---- code references (indirect calls / jumps / jump-table targets) ------
  for ( const ExecEdge &e : ev.edges )
  {
    const ea_t from = (ea_t)e.from;

    // Classify the SOURCE: only an indirect transfer is a candidate here. Direct
    // calls/jumps are already resolved statically (and dedupe anyway); returns
    // and conditional branches are neither CF_CALL nor CF_JUMP. (Direct-target
    // recovery is the job of the static-decode pass.)
    const flags64_t ff = get_flags(from);
    if ( !is_head(ff) || !is_code(ff) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, from) <= 0 )
      continue;
    const uint32 feat = insn.get_canon_feature(PH);
    const bool is_call = (feat & CF_CALL) != 0;
    const bool is_ijmp = (feat & CF_JUMP) != 0; // CF_JUMP == indirect jump
    if ( !is_call && !is_ijmp )
      continue;

    viy_try_add_cref(e.from, e.to, is_call, cfg, st);
  }

  // ---- data references (computed loads/stores) ----------------------------
  // Memory hooks may still be active when drefs are disabled because runtime
  // strings and SMC correlation consume transient writes. The IDB switch must
  // nevertheless be an absolute gate on computed add_dref mutations.
  if ( !cfg.want_drefs )
    return st;
  for ( const DataAcc &d : ev.data )
  {
    if ( d.scope != DataScope::IMAGE )
      continue;
    const ea_t from = (ea_t)d.from;
    const ea_t to   = (ea_t)d.addr;

    if ( !is_mapped(to) )
      continue;
    if ( is_code(get_flags(to)) )       // executing code, not a data reference
      continue;
    const flags64_t ff = get_flags(from);
    if ( !is_head(ff) || !is_code(ff) )
      continue;
    if ( dref_exists(from, to) )
      continue;

    dref_t type = (d.kind == RAX_MEM_WRITE) ? dr_W : dr_R;
    if ( !add_dref(from, to, dref_t(int(type) | XREF_USER)) )
      continue;
    ++st.drefs;
  }

  return st;
}

} // namespace viy
