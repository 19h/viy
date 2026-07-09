/*
 * program_model.cpp — read the analyzed program out of the IDA database.
 *
 * Main-thread only (touches the database). Produces a ProgramImage that the
 * IDA-free emulation driver consumes.
 */
#include "program_model.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>

namespace viy {

bool ProgramImage::byte_loaded(uint64_t ea) const
{
  for ( const SegImage &s : segs )
  {
    if ( ea < s.start || ea >= s.end )
      continue;
    uint64_t off = ea - s.start;
    if ( off / 8 >= s.mask.size() )
      return false;
    return (s.mask[off / 8] & (1u << (off & 7))) != 0;
  }
  return false;
}

bool viy_detect_arch(ViyArch &arch_out, bool &big_endian_out)
{
  arch_out = ViyArch::UNSUPPORTED;
  big_endian_out = inf_is_be();

  const int id = PH.id;
  const uint bits = inf_get_app_bitness(); // 16 / 32 / 64
  const bool is64 = inf_is_64bit();

  switch ( id )
  {
    case PLFM_386:
      arch_out = bits == 64 ? ViyArch::X86_64
               : bits == 32 ? ViyArch::X86_32
                            : ViyArch::X86_16;
      break;
    case PLFM_ARM:
      arch_out = is64 ? ViyArch::ARM64 : ViyArch::ARM32;
      break;
    default:
      arch_out = ViyArch::UNSUPPORTED;
      break;
  }
  return arch_out != ViyArch::UNSUPPORTED;
}

void viy_snapshot(ProgramImage &img, const ViyConfig &cfg)
{
  // Idempotent: reset so a repeated call (e.g. a later reanalysis pass) does not
  // accumulate duplicate segment buffers or entries.
  img.segs.clear();
  img.entries.clear();
  img.lo = img.hi = 0;

  viy_detect_arch(img.arch, img.big_endian);

  // ---- segments -----------------------------------------------------------
  const int nsegs = get_segm_qty();
  bool have_bounds = false;
  for ( int i = 0; i < nsegs; ++i )
  {
    segment_t *s = getnseg(i);
    if ( s == nullptr || s->end_ea <= s->start_ea )
      continue;

    SegImage si;
    si.start   = (uint64_t)s->start_ea;
    si.end     = (uint64_t)s->end_ea;
    si.perm    = (uint32_t)s->perm;
    si.bitness = (uint8_t)s->bitness;

    const size_t len = (size_t)(s->end_ea - s->start_ea);
    si.bytes.assign(len, 0);
    si.mask.assign((len + 7) / 8, 0);

    // GMB_READALL: fill what is loaded, mark the rest in `mask`. A -1 result
    // means the user cancelled a (non-existent here) wait box; treat as empty.
    ssize_t got = get_bytes(si.bytes.data(), (ssize_t)len, s->start_ea,
                            GMB_READALL, si.mask.data());
    if ( got < 0 )
      continue;

    if ( !have_bounds )
    {
      img.lo = si.start;
      img.hi = si.end;
      have_bounds = true;
    }
    else
    {
      if ( si.start < img.lo ) img.lo = si.start;
      if ( si.end   > img.hi ) img.hi = si.end;
    }
    img.segs.push_back(std::move(si));
  }

  // ---- function entries ---------------------------------------------------
  const size_t nfuncs = get_func_qty();
  const size_t cap = cfg.max_funcs != 0 ? (size_t)cfg.max_funcs : nfuncs;
  img.entries.reserve(nfuncs < cap ? nfuncs : cap);
  for ( size_t i = 0; i < nfuncs; ++i )
  {
    if ( img.entries.size() >= cap )
      break;
    func_t *pfn = getn_func(i);
    if ( pfn == nullptr )
      continue;
    // Skip pure library/thunk stubs: their targets are already resolved and
    // emulating them adds noise, not missed refs.
    if ( (pfn->flags & (FUNC_LIB | FUNC_THUNK)) != 0 )
      continue;
    img.entries.push_back(FuncRange{ (uint64_t)pfn->start_ea, (uint64_t)pfn->end_ea });
  }
}

} // namespace viy
