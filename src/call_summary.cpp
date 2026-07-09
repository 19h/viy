#include "call_summary.hpp"

#include <algorithm>
#include <cctype>
#include <string>

#include <pro.h>
#include <bytes.hpp>
#include <name.hpp>

namespace viy {

namespace {

std::string canonical_name(const char *raw)
{
  std::string name = raw != nullptr ? raw : "";
  std::transform(name.begin(), name.end(), name.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  // Import/thunk decorations can be nested (for example j___imp_memcpy), so
  // peel wrappers to a fixed point.  Keep one leading underscore on names
  // whose spelling is semantically significant only until classification:
  // `_exit` canonicalizes to `exit`, which has the same summary.
  bool changed = true;
  while ( changed && !name.empty() )
  {
    changed = false;
    for ( const char *prefix : { "__imp_", "imp_", "j_", "__", "_" } )
    {
      const size_t n = std::char_traits<char>::length(prefix);
      if ( name.compare(0, n, prefix) == 0 )
      {
        name.erase(0, n);
        changed = true;
        break;
      }
    }
  }
  // Covers ELF symbol versions and x86 stdcall suffixes.  Do this after
  // wrapper stripping so `_memcpy@12` and `memcpy@@GLIBC_2.14` converge.
  if ( const size_t at = name.find('@'); at != std::string::npos )
    name.resize(at);
  return name;
}

bool classify(const std::string &name, EmuSummaryKind *kind)
{
  const auto starts_with = [&](const char *prefix)
  { return name.compare(0, std::char_traits<char>::length(prefix), prefix) == 0; };
  if ( name == "memcpy" ) *kind = EmuSummaryKind::MEMCPY;
  else if ( name == "memmove" ) *kind = EmuSummaryKind::MEMMOVE;
  else if ( name == "memset" ) *kind = EmuSummaryKind::MEMSET;
  // stpcpy deliberately is not aliased to strcpy: its return value is the end
  // pointer, not the destination pointer.
  else if ( name == "strcpy" ) *kind = EmuSummaryKind::STRCPY;
  else if ( name == "strncpy" ) *kind = EmuSummaryKind::STRNCPY;
  else if ( name == "strlen" ) *kind = EmuSummaryKind::STRLEN;
  else if ( name == "strcmp" ) *kind = EmuSummaryKind::STRCMP;
  else if ( name == "malloc" || starts_with("operator new(")
         || starts_with("operator new[](") || name == "znwm" || name == "znwj"
         || name == "znam" || name == "znaj" )
    *kind = EmuSummaryKind::ALLOCATE;
  else if ( name == "calloc" ) *kind = EmuSummaryKind::CALLOCATE;
  else if ( name == "free" || starts_with("operator delete(")
         || starts_with("operator delete[](") || starts_with("zdlpv")
         || starts_with("zdapv") )
    *kind = EmuSummaryKind::DEALLOCATE;
  else if ( name == "exit" || name == "abort"
         || name == "terminate" || name == "quick_exit"
         || name == "fatal" || name == "panic" || name == "stack_chk_fail" )
    *kind = EmuSummaryKind::TERMINATE;
  else return false;
  return true;
}

} // namespace

std::vector<EmuCallSummary> viy_collect_call_summaries()
{
  std::vector<EmuCallSummary> out;
  const size_t count = get_nlist_size();
  out.reserve(std::min<size_t>(count, 1024));
  for ( size_t i = 0; i < count; ++i )
  {
    const ea_t ea = get_nlist_ea(i);
    if ( ea == BADADDR || !is_mapped(ea) )
      continue;
    EmuSummaryKind kind;
    if ( classify(canonical_name(get_nlist_name(i)), &kind) )
      out.push_back(EmuCallSummary{ uint64_t(ea), kind });
  }
  std::sort(out.begin(), out.end(), [](const EmuCallSummary &a, const EmuCallSummary &b)
  {
    return a.address < b.address;
  });
  out.erase(std::unique(out.begin(), out.end(), [](const EmuCallSummary &a,
                                                   const EmuCallSummary &b)
  { return a.address == b.address; }), out.end());
  return out;
}

} // namespace viy
