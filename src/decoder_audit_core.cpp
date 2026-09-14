#include "decoder_audit.hpp"

namespace viy {

DecoderAuditInstruction viy_analyze_decoder_input(
    const RaxApi *api, const ProgramImage &image, const DecoderAuditInput &input)
{
  DecoderAuditInstruction result;
  result.input = input;
  if (api == nullptr || !input.mode_known)
    return result;
  const DecoderArchitecture arch =
      viy_decoder_architecture(image.arch, image.big_endian);
  if (!arch.valid)
    return result;
  const LoadedByteView bytes = image.loaded_view(input.address, input.maximum_bytes);
  if (bytes.size == 0)
    return result;
  result.analyzed = viy_analyze_instruction_effects(
      api, image, input.address, input.mode, result.effects, bytes.size);
  if (result.analyzed)
    result.decoded = viy_accept_rax_decoded(result.effects.summary.decoded, bytes.size);
  else
    result.decoded = viy_decode_one(api->decode, arch.rax_arch, input.mode,
                                    input.address, bytes.data, bytes.size);
  return result;
}

} // namespace viy
