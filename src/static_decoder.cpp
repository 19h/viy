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

#include "decoder_core.hpp"

namespace viy {

namespace {

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
    return; // linked table without the decoder capability — nothing to do

  const DecoderArchitecture da =
      viy_decoder_architecture(arch, big_endian);
  if ( !da.valid )
    return;

  // AArch32 needs IDA's T (Thumb) segment register to pick ARM vs Thumb per
  // address. Resolve its register number once (-1 if the processor has none).
  const int t_reg = da.per_instruction_thumb ? str2reg("T") : -1;

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
          DecoderArmState arm_state = DecoderArmState::Unknown;
          if ( da.per_instruction_thumb )
          {
            const sel_t t = t_reg >= 0 ? get_sreg(ea, t_reg) : BADSEL;
            if ( t != BADSEL )
              arm_state = t == 0 ? DecoderArmState::Arm
                                 : DecoderArmState::Thumb;
          }
          uint32_t mode = 0;
          const size_t wanted = viy_decoder_window_size(
              uint64_t(ea), uint64_t(end), kMaxInsnBytes);
          if ( wanted != 0 && viy_decoder_mode(da, arm_state, mode) )
          {
            uint8_t buf[kMaxInsnBytes] = {};
            const ssize_t got = get_bytes(buf, ssize_t(wanted), ea, GMB_READALL);
            if ( got > 0 )
            {
              const DecoderDecodeResult decoded = viy_decode_one(
                  api->decode, da.rax_arch, mode, uint64_t(ea), buf, size_t(got));
              const DecoderDirectTarget target =
                  viy_decoder_direct_target(decoded.instruction);
              if ( decoded.status == DecoderDecodeStatus::Valid && target.valid )
              {
                const bool is_call = target.kind == DecoderTargetKind::Call;
                viy_try_add_cref(uint64_t(ea), target.address,
                                 is_call, cfg, stats);
              }
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
