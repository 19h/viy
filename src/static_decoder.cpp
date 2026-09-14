/* Apply direct targets from the worker decoder audit. All IDB checks and
 * mutations remain on the main thread; no RAX calls occur in this adapter. */
#include "static_decoder.hpp"

#include <pro.h>
#include <xref.hpp>

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

} // namespace

void viy_apply_static_decode(
    const std::vector<DecoderAuditInstruction> &instructions,
    const ViyConfig &cfg, RefStats &stats)
{
  for (const DecoderAuditInstruction &instruction : instructions)
  {
    const ea_t ea = ea_t(instruction.input.address);
    if (!instruction.input.control_transfer || has_outgoing_cref(ea))
      continue;
    const DecoderDirectTarget target =
        viy_decoder_direct_target(instruction.decoded.instruction);
    if (instruction.decoded.status == DecoderDecodeStatus::Valid && target.valid)
      viy_try_add_cref(instruction.input.address, target.address,
                       target.kind == DecoderTargetKind::Call, cfg, stats);
  }
}

} // namespace viy
