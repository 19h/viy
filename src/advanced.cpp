/*
 * advanced.cpp — function-level analyses. Main thread only.
 */
#include "advanced.hpp"

#include <algorithm>
#include <unordered_map>
#include <vector>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <nalt.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <name.hpp>

namespace viy {

namespace {

bool target_ok_code(ea_t to)
{
  if ( !is_mapped(to) || is_tail(get_flags(to)) )
    return false;
  segment_t *s = getseg(to);
  return s != nullptr && (s->perm == 0 || (s->perm & SEGPERM_EXEC) != 0);
}

bool in_func(ea_t ea, const FuncRange &function)
{
  return function.contains(uint64_t(ea));
}

qstring ea_label(ea_t ea)
{
  qstring n = get_name(ea);
  if ( !n.empty() )
    return n;
  qstring s;
  s.sprnt("0x%a", ea);
  return s;
}

bool add_rpt_comment(ea_t ea, const char *text)
{
  qstring cur;
  if ( get_cmt(&cur, ea, true) > 0 && !cur.empty() )
    return false;
  return set_cmt(ea, text, true);
}

const char *stop_reason_name(int r)
{
  switch ( r )
  {
    case RAX_STOP_HLT:      return "halt";
    case RAX_STOP_EXCEPTION: return "exception";
    case RAX_STOP_SHUTDOWN: return "shutdown";
    default:               return "terminal";
  }
}

// ---- switch reconstruction ----------------------------------------------
void do_switches(const FuncRange &function, const EmuEvents &ev, AdvStats &stats)
{
  // Group each indirect jump's observed targets.
  std::unordered_map<ea_t, std::vector<ea_t>> groups;
  for ( const ExecEdge &e : ev.edges )
  {
    const ea_t from = (ea_t)e.from;
    const ea_t to   = (ea_t)e.to;
    if ( !in_func(from, function) || !target_ok_code(to) )
      continue;
    insn_t insn;
    if ( decode_insn(&insn, from) <= 0 )
      continue;
    const uint32 feat = insn.get_canon_feature(PH);
    if ( (feat & CF_JUMP) == 0 || (feat & CF_CALL) != 0 )
      continue; // only indirect jumps (jump tables), not calls
    std::vector<ea_t> &v = groups[from];
    if ( std::find(v.begin(), v.end(), to) == v.end() )
      v.push_back(to);
  }

  for ( auto &kv : groups )
  {
    const ea_t J = kv.first;
    std::vector<ea_t> &targets = kv.second;
    if ( targets.size() < 2 )
      continue; // a single target is a resolved jump, not a switch

    switch_info_t existing;
    if ( get_switch_info(&existing, J) > 0 )
      continue; // already a switch — never overwrite

    switch_info_t si;                      // ctor sets SWI_VERSION
    si.flags  |= SWI_USER | SWI_CUSTOM;    // custom => IDA reads NO table bytes from memory
    si.ncases  = (uint16)std::min<size_t>(targets.size(), 0xFFFF);
    si.jumps   = J;                        // anchor; not decoded in custom mode
    si.lowcase = 0;
    si.defjump = BADADDR;                  // no default case
    si.startea = J;

    set_switch_info(J, si);
    if ( !create_switch_table(J, si) )
    {
      del_switch_info(J);                  // roll back a switch that couldn't be realized
      continue;
    }
    for ( ea_t t : targets )               // custom xrefs aren't auto-created here
      add_cref(J, t, fl_JN);
    create_switch_xrefs(J, si);
    // The observed target set can be a subset of the real cases, so say so.
    qstring c;
    c.sprnt("viy: switch, %u case(s) observed by emulation (may be incomplete)",
            (unsigned)targets.size());
    add_rpt_comment(J, c.c_str());
    ++stats.switches;
  }
}

// ---- stack purge (x86) --------------------------------------------------
void do_purge(ViyArch arch, ea_t lo, const EmuOutcome &outcome,
              const ViyConfig &cfg, AdvStats &stats)
{
  if ( !cfg.want_purge || !outcome.sp_valid )
    return;
  // Callee arg cleanup (`ret N`) is a 16/32-bit stdcall notion; set_purged is a
  // no-op in 64-bit mode (needs PR_PURGING), and x86-64 ABIs are caller-cleaned.
  if ( arch != ViyArch::X86_32 )
    return;
  const int ptrsz = 4;
  const int64_t purge = outcome.sp_delta - ptrsz; // bytes popped beyond the return address
  if ( purge <= 0 || purge > 512 || (purge % ptrsz) != 0 )
    return; // 0 => cdecl (nothing to set); reject implausible values

  func_t *pfn = get_func(lo);
  if ( pfn == nullptr || pfn->start_ea != lo )
    return;
  if ( (pfn->flags & FUNC_PURGED_OK) != 0 || pfn->argsize != 0 )
    return; // IDA already knows the purge — don't clobber
  if ( set_purged(pfn->start_ea, (int)purge, /*override_old_value=*/false) )
    ++stats.purges;
}

// ---- no-return hint -----------------------------------------------------
void do_noret(ea_t lo, const EmuOutcome &outcome, bool corroborated,
              const ViyConfig &cfg, AdvStats &stats)
{
  if ( !cfg.want_noret && !cfg.set_noret )
    return;
  // The caller confirms across SEVERAL varied-input runs that the function never
  // returned and halted definitively — a single (zero-argument) run is never
  // enough, since a function may only halt on one input path.
  if ( !corroborated )
    return;

  func_t *pfn = get_func(lo);
  if ( pfn == nullptr || pfn->start_ea != lo || !pfn->does_return() )
    return; // already no-return, or not a function head

  if ( cfg.want_comments )
  {
    qstring txt;
    txt.sprnt("viy: appears no-return (emulation stopped: %s, never returned)",
              stop_reason_name(outcome.stop_reason));
    add_rpt_comment(lo, txt.c_str());
  }
  if ( cfg.set_noret )
  {
    pfn->flags |= FUNC_NORET;
    update_func(pfn);
    reanalyze_function(pfn);
  }
  ++stats.norets;
}

// ---- argument-register inference (static read-before-write) -------------
void do_argregs(ViyArch arch, const FuncRange &function,
                const ViyConfig &cfg, AdvStats &stats)
{
  if ( !cfg.want_argregs || !cfg.want_comments )
    return;

  // Candidate integer argument registers, resolved to IDA reg ids by name.
  static const char *x64_sysv[] = { "rdi", "rsi", "rdx", "rcx", "r8", "r9" };
  static const char *x64_win[] = { "rcx", "rdx", "r8", "r9" };
  static const char *a64[] = { "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7" };
  static const char *a32[] = { "R0", "R1", "R2", "R3" };
  static const char *rv64[] = { "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7" };
  static const char *hex[] = { "R0", "R1", "R2", "R3", "R4", "R5" };
  const char *const *names = nullptr;
  size_t nnames = 0;
  int width = 8;
  if ( arch == ViyArch::X86_64 )
  {
    const bool windows = inf_get_filetype() == f_PE;
    names = windows ? x64_win : x64_sysv;
    nnames = windows ? qnumber(x64_win) : qnumber(x64_sysv);
    width = 8;
  }
  else if ( arch == ViyArch::ARM64 ) { names = a64; nnames = 8; width = 8; }
  else if ( arch == ViyArch::ARM32 || arch == ViyArch::CORTEX_M )
    { names = a32; nnames = qnumber(a32); width = 4; }
  else if ( arch == ViyArch::RISCV64 )
    { names = rv64; nnames = qnumber(rv64); width = 8; }
  else if ( arch == ViyArch::HEXAGON )
    { names = hex; nnames = qnumber(hex); width = 4; }
  else return; // only well-defined reg-arg ABIs

  std::vector<int> arg_ids;
  for ( size_t i = 0; i < nnames; ++i )
  {
    int r = str2reg(names[i]);
    if ( r >= 0 )
      arg_ids.push_back(r);
  }
  if ( arg_ids.empty() )
    return;
  auto is_arg = [&](int r) { return std::find(arg_ids.begin(), arg_ids.end(), r) != arg_ids.end(); };

  std::unordered_set<int> written;
  std::vector<int> found; // arg regs read before being written, in encounter order
  const ea_t lo = ea_t(function.start);
  ea_t ea = lo;
  std::unordered_set<ea_t> visited;
  for ( int steps = 0; steps < 64 && ea != BADADDR && in_func(ea, function); ++steps )
  {
    if ( !visited.insert(ea).second )
      break;
    insn_t insn;
    if ( decode_insn(&insn, ea) <= 0 )
      break;
    const uint32 feat = insn.get_canon_feature(PH);

    for ( int i = 0; i < UA_MAXOP; ++i )
    {
      const op_t &op = insn.ops[i];
      if ( op.type == o_void )
        break;
      if ( op.type == o_reg )
      {
        const int rr = op.reg;
        if ( has_cf_use(feat, i) && written.find(rr) == written.end()
          && is_arg(rr) && std::find(found.begin(), found.end(), rr) == found.end() )
          found.push_back(rr);
        if ( has_cf_chg(feat, i) )
          written.insert(rr);
      }
      else if ( (op.type == o_displ || op.type == o_phrase) && arch == ViyArch::ARM64 )
      {
        // AArch64 stores the base register in op.reg/op.phrase, so it is a
        // reliable READ. On x86 the base of a SIB-form operand lives in the SIB
        // byte (not op.reg), so we skip memory operands there rather than risk a
        // wrong register in the hint.
        const int br = op.reg;
        if ( written.find(br) == written.end() && is_arg(br)
          && std::find(found.begin(), found.end(), br) == found.end() )
          found.push_back(br);
      }
    }

    if ( is_call_insn(insn) )
      break; // a call clobbers caller-saved regs; stop inferring

    ea_t next = ea + insn.size;
    if ( (feat & CF_STOP) != 0 && !is_ret_insn(insn) )
    {
      // Follow a single direct in-function successor.  This handles entry
      // stubs whose body lives in a non-contiguous tail without turning the
      // hint into a speculative multi-path dataflow result.
      ea_t sole = BADADDR;
      size_t count = 0;
      xrefblk_t xb;
      for ( bool ok = xb.first_from(ea, XREF_CODE | XREF_NOFLOW);
            ok; ok = xb.next_from() )
      {
        if ( in_func(xb.to, function) )
        {
          sole = xb.to;
          ++count;
        }
      }
      if ( count != 1 )
        break;
      next = sole;
    }
    if ( !in_func(next, function) )
      break;
    ea = next;
  }

  if ( found.empty() )
    return;
  qstring txt = "viy: arg regs: ";
  for ( size_t i = 0; i < found.size(); ++i )
  {
    qstring rn;
    get_reg_name(&rn, found[i], width);
    if ( i != 0 )
      txt.append(", ");
    txt.append(rn);
  }
  if ( add_rpt_comment(lo, txt.c_str()) )
    ++stats.argregs;
}

// ---- opaque predicate / dead branch (comment hint) ----------------------
void do_opaque(const FuncRange &function,
               const std::unordered_set<uint64_t> &reached,
               const ViyConfig &cfg, AdvStats &stats)
{
  if ( !cfg.want_opaque || reached.empty() )
    return;

  std::vector<FuncChunk> chunks = function.chunks;
  if ( chunks.empty() )
    chunks.push_back(FuncChunk{ function.start, function.end });
  for ( const FuncChunk &chunk : chunks )
  {
    ea_t ea = ea_t(chunk.start);
    const ea_t hi = ea_t(chunk.end);
    while ( ea != BADADDR && ea < hi )
    {
      const flags64_t ff = get_flags(ea);
      if ( is_code(ff) && is_head(ff) && reached.count((uint64_t)ea) != 0 )
      {
        insn_t insn;
        if ( decode_insn(&insn, ea) > 0 )
        {
          const uint32 feat = insn.get_canon_feature(PH);
          // A 2-way conditional branch: flow continues (not CF_STOP) and it is not
          // a call (a call also has a non-flow code xref to its callee, which must
          // not be mistaken for a branch target).
          if ( (feat & (CF_STOP | CF_CALL)) == 0 && !is_call_insn(insn) )
          {
            // the non-flow code target of this instruction (the branch target)
            ea_t T = BADADDR;
            xrefblk_t xb;
            for ( bool ok = xb.first_from(ea, XREF_CODE | XREF_NOFLOW);
                  ok; ok = xb.next_from() )
            {
              T = xb.to;
              break;
            }
            const ea_t F = ea + insn.size;
            if ( T != BADADDR && T != F )
            {
              const bool tR = reached.count((uint64_t)T) != 0;
              const bool fR = reached.count((uint64_t)F) != 0;
              if ( tR != fR ) // exactly one side ever reached => the other looks dead
              {
                qstring txt;
                if ( tR )
                  txt.sprnt("viy: predicate always taken (fall-through %s never reached in %d runs)",
                            ea_label(F).c_str(), cfg.opaque_runs);
                else
                  txt.sprnt("viy: predicate always not-taken (branch %s never reached in %d runs)",
                            ea_label(T).c_str(), cfg.opaque_runs);
                if ( add_rpt_comment(ea, txt.c_str()) )
                  ++stats.opaque;
              }
            }
          }
        }
      }
      const ea_t nxt = next_head(ea, hi);
      if ( nxt <= ea )
        break;
      ea = nxt;
    }
  }
}

} // namespace

void viy_advanced(ViyArch arch, uint64_t func_start, uint64_t func_end,
                  const EmuEvents &ev, const EmuOutcome &outcome,
                  const std::unordered_set<uint64_t> &reached,
                  bool noret_corroborated,
                  const ViyConfig &cfg, AdvStats &stats)
{
  FuncRange function;
  function.start = func_start;
  function.end = func_end;
  if ( func_end > func_start )
    function.chunks.push_back(FuncChunk{ func_start, func_end });
  viy_advanced(arch, function, ev, outcome, reached,
               noret_corroborated, cfg, stats);
}

void viy_advanced(ViyArch arch, const FuncRange &function,
                  const EmuEvents &ev, const EmuOutcome &outcome,
                  const std::unordered_set<uint64_t> &reached,
                  bool noret_corroborated,
                  const ViyConfig &cfg, AdvStats &stats)
{
  if ( function.end <= function.start && function.chunks.empty() )
    return;
  const ea_t lo = ea_t(function.start);

  if ( cfg.want_switch )
    do_switches(function, ev, stats);
  do_purge(arch, lo, outcome, cfg, stats);
  do_noret(lo, outcome, noret_corroborated, cfg, stats);
  do_argregs(arch, function, cfg, stats);
  do_opaque(function, reached, cfg, stats);
}

} // namespace viy
