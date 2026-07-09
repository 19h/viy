/*
 * enrich.cpp — value-derived IDA enrichments. Main thread only.
 */
#include "enrich.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <offset.hpp>
#include <nalt.hpp>

namespace viy {

namespace {

// Human label for an address: its name if it has one, else a hex address.
qstring ea_label(ea_t ea)
{
  qstring n = get_name(ea);
  if ( !n.empty() )
    return n;
  qstring s;
  s.sprnt("0x%a", ea);
  return s;
}

// A data (non-executable) segment — where globals/pointer tables live.
bool in_data_seg(ea_t ea)
{
  segment_t *s = getseg(ea);
  return s != nullptr && (s->perm == 0 || (s->perm & SEGPERM_EXEC) == 0);
}

bool dref_exists(ea_t from, ea_t to)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_from(from, XREF_DATA); ok; ok = xb.next_from() )
    if ( xb.to == to )
      return true;
  return false;
}

// Add a repeatable comment only when there isn't one already (never clobber).
bool add_rpt_comment(ea_t ea, const char *text)
{
  qstring cur;
  if ( get_cmt(&cur, ea, true) > 0 && !cur.empty() )
    return false;
  return set_cmt(ea, text, true);
}

// Type `length` undefined bytes at `ea` as a scalar of that size.
bool type_scalar(ea_t ea, uint32_t length)
{
  switch ( length )
  {
    case 1:  return create_byte(ea, 1);
    case 2:  return create_word(ea, 2);
    case 4:  return create_dword(ea, 4);
    case 8:  return create_qword(ea, 8);
    case 16: return create_oword(ea, 16);
    default: return false;
  }
}

// Create a C string at `a` if the undefined bytes there form a printable,
// NUL-terminated run. options=0 (no ALOPT_IGNHEADS) so length stops at the first
// defined item — the run stays entirely within undefined bytes.
bool try_make_string(ea_t a)
{
  if ( !is_loaded(a) )
    return false;
  size_t len = get_max_strlit_length(a, STRTYPE_C, 0); // stops at a defined item
  // get_max_strlit_length ignores NAMES on undefined bytes, so truncate before
  // any named interior location — never absorb a named address into the string.
  for ( size_t i = 1; i < len; ++i )
  {
    if ( has_name(get_flags((ea_t)(a + i))) )
    {
      len = i;
      break;
    }
  }
  if ( len < 4 )
    return false; // too short to be worth a string
  return create_strlit(a, len, STRTYPE_C);
}

} // namespace

EnrichStats viy_enrich(const EmuEvents &ev, const ViyConfig &cfg)
{
  EnrichStats st;
  const uint32_t pbits = inf_is_64bit() ? 8u : 4u; // pointer width

  // ---- comments on resolved indirect transfers ----------------------------
  if ( cfg.want_comments )
  {
    for ( const ExecEdge &e : ev.edges )
    {
      const ea_t from = (ea_t)e.from;
      const ea_t to   = (ea_t)e.to;
      if ( !is_mapped(to) )
        continue;
      const flags64_t ff = get_flags(from);
      if ( !is_head(ff) || !is_code(ff) )
        continue;
      insn_t insn;
      if ( decode_insn(&insn, from) <= 0 )
        continue;
      if ( (insn.get_canon_feature(PH) & (CF_CALL | CF_JUMP)) == 0 )
        continue; // only annotate the indirect transfers viy resolved
      qstring txt;
      txt.sprnt("viy: -> %s", ea_label(to).c_str());
      if ( add_rpt_comment(from, txt.c_str()) )
        ++st.comments;
    }
  }

  // ---- value-derived data enrichments -------------------------------------
  for ( const DataAcc &d : ev.data )
  {
    const ea_t from = (ea_t)d.from;
    const ea_t addr = (ea_t)d.addr;
    if ( !is_mapped(addr) || is_code(get_flags(addr)) )
      continue;                              // must be a data location
    const flags64_t sf = get_flags(from);
    if ( !is_head(sf) || !is_code(sf) )
      continue;                              // source must be a real instruction
    if ( !is_unknown(get_flags(addr)) || !in_data_seg(addr) )
      continue;                              // only ever touch undefined data

    // (1) Pointer materialization: a pointer-width read of an initialized slot
    // whose STORED value is an in-image address => the slot holds a pointer.
    // Type it and mark it an offset, which makes IDA create the dref and render
    // "offset <target>" (vtables, fn-ptr tables). The offset target must come
    // from the DB bytes (that is what op_plain_offset renders), so we read the
    // stored pointer back and validate THAT — never the emulated value, which
    // can diverge from disk for .bss/relocated slots and would leave a bogus
    // "offset 0". The read event (pointer-width, mapped runtime value) is only
    // the hint that this slot is used as a pointer.
    bool did_ptr = false;
    if ( cfg.want_ptr_refs && d.kind == RAX_MEM_READ && d.size == pbits
      && is_mapped((ea_t)d.value) && is_loaded(addr) )
    {
      const ea_t stored = pbits == 8 ? (ea_t)get_qword(addr) : (ea_t)get_dword(addr);
      if ( stored >= 0x1000 && stored != addr && is_mapped(stored) )
      {
        const bool typed = pbits == 8 ? create_qword(addr, 8) : create_dword(addr, 4);
        if ( typed && op_plain_offset(addr, 0, 0) )
        {
          ++st.ptr_refs;
          did_ptr = true;
          if ( cfg.want_comments )
          {
            qstring txt;
            txt.sprnt("viy: %s -> %s", ea_label(addr).c_str(), ea_label(stored).c_str());
            add_rpt_comment(from, txt.c_str());
          }
        }
      }
    }

    // (2) Otherwise, if the undefined bytes look like a C string, create one;
    // failing that, give the undefined global a data type matching the access
    // size, so the listing shows a sized item instead of raw bytes.
    if ( !did_ptr )
    {
      if ( cfg.want_strings && try_make_string(addr) )
        ++st.strings;
      else if ( cfg.want_data_types && type_scalar(addr, d.size) )
        ++st.typed;
    }
  }

  return st;
}

} // namespace viy
