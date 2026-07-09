/*
 * static_decoder.cpp — rax static-decode cross-check.
 *
 * For each control-transfer instruction that IDA left WITHOUT a resolved outgoing
 * code xref, ask rax's decoder whether the encoding carries a direct target. If
 * it does, add the (missing) cref. This is cheap — rax is consulted only for the
 * handful of unresolved transfers, not every instruction — safe (it only adds
 * through viy_try_add_cref, which guards target/head/dedupe), and complements the
 * emulator, which handles the INDIRECT transfers this pass deliberately leaves
 * alone. Main thread only.
 */
#include "static_decoder.hpp"

#include <pro.h>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segregs.hpp>

namespace viy {

namespace {

// rax decode parameters for a ViyArch. For AArch32 the ARM-vs-Thumb mode is not
// fixed for the whole image — it changes per address (interworking) — so
// `per_insn_thumb` is set and the caller resolves the mode from IDA's T segment
// register at each instruction. x86-16 (seg:off) is not handled.
struct DecodeArch
{
  bool     ok = false;
  int      rax_arch = 0;
  uint32_t base_mode = 0;      // endianness / fixed bitness bits
  bool     per_insn_thumb = false; // AArch32: OR in RAX_MODE_ARM/THUMB per insn
};

DecodeArch decode_arch_for(ViyArch a, bool be)
{
  DecodeArch d;
  const uint32_t endian = be ? RAX_MODE_BIG_ENDIAN : RAX_MODE_LITTLE_ENDIAN;
  switch ( a )
  {
    case ViyArch::X86_32:
      d = { true, RAX_ARCH_X86, RAX_MODE_32, false }; break;
    case ViyArch::X86_64:
      d = { true, RAX_ARCH_X86, RAX_MODE_64, false }; break;
    case ViyArch::ARM64:
      d = { true, RAX_ARCH_ARM64, endian, false }; break;
    case ViyArch::ARM32:
      // ARMv7 / AArch32 (and Cortex-M, which is Thumb-only) — rax decodes both
      // ARM and Thumb; the state comes from IDA per address.
      d = { true, RAX_ARCH_ARM, endian, true }; break;
    default:
      break;
  }
  return d;
}

// Does IDA already record a resolved outgoing code TARGET from `ea`?
// XREF_NOFLOW excludes the ordinary fall-through (fl_F) cref that every call and
// conditional branch carries — otherwise this would read as "target known" for
// every call and the pass would never recover a direct call target.
bool has_outgoing_cref(ea_t ea)
{
  xrefblk_t xb;
  return xb.first_from(ea, XREF_CODE | XREF_NOFLOW);
}

constexpr size_t kMaxInsnBytes    = 16;
constexpr size_t kMaxInsnsPerFunc = 65536; // bound the work per function

} // namespace

void viy_static_decode_func(const RaxApi *api, ViyArch arch, bool big_endian,
                            uint64_t func_start, uint64_t func_end,
                            const ViyConfig &cfg, RefStats &stats)
{
  if ( api == nullptr || api->decode == nullptr )
    return; // older librax without the static decoder — nothing to do

  const DecodeArch da = decode_arch_for(arch, big_endian);
  if ( !da.ok )
    return;

  // AArch32 needs IDA's T (Thumb) segment register to pick ARM vs Thumb per
  // address. Resolve its register number once (-1 if the processor has none).
  const int t_reg = da.per_insn_thumb ? str2reg("T") : -1;

  const ea_t end = (ea_t)func_end;
  ea_t ea = (ea_t)func_start;
  for ( size_t budget = kMaxInsnsPerFunc;
        ea != BADADDR && ea < end && budget != 0;
        --budget )
  {
    const flags64_t ff = get_flags(ea);
    if ( is_code(ff) && is_head(ff) )
    {
      insn_t insn;
      if ( decode_insn(&insn, ea) > 0 )
      {
        // Only consult rax for a control transfer IDA could not resolve. A
        // transfer is CF_CALL (call), CF_JUMP (indirect jump) or CF_STOP (jmp /
        // ret); if IDA already has an outgoing cref, its target is known.
        const uint32 feat = insn.get_canon_feature(PH);
        const bool transfer = (feat & (CF_CALL | CF_JUMP | CF_STOP)) != 0;
        if ( transfer && !has_outgoing_cref(ea) )
        {
          uint32_t mode = da.base_mode;
          if ( da.per_insn_thumb )
          {
            const sel_t t = t_reg >= 0 ? get_sreg(ea, t_reg) : sel_t(0);
            mode |= (t != 0 && t != BADSEL) ? RAX_MODE_THUMB : RAX_MODE_ARM;
          }

          uint8_t buf[kMaxInsnBytes];
          const ssize_t got = get_bytes(buf, (ssize_t)sizeof(buf), ea, GMB_READALL);
          if ( got > 0 )
          {
            rax_decoded d;
            if ( api->decode(da.rax_arch, mode, (uint64_t)ea, buf, (size_t)got, &d) == RAX_OK
              && d.valid != 0 && d.has_target != 0
              && (d.flow == RAX_FLOW_CALL
               || d.flow == RAX_FLOW_BRANCH
               || d.flow == RAX_FLOW_COND_BRANCH) )
            {
              const bool is_call = d.flow == RAX_FLOW_CALL;
              viy_try_add_cref((uint64_t)ea, d.target, is_call, cfg, stats);
            }
          }
        }
      }
    }

    const ea_t nxt = next_head(ea, end);
    if ( nxt <= ea )
      break;
    ea = nxt;
  }
}

} // namespace viy
