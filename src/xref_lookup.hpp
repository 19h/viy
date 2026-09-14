// IDA-independent lookup algorithm for an SDK-compatible xref cursor.
#pragma once

namespace viy {

// flags must select an address-ordered group (data or code without flow).
// The SDK overload seeks to the first reference after an arbitrary target;
// it does not require stepping through all earlier outgoing references.
template <typename Cursor, typename Address>
bool viy_sorted_xref_exists(Cursor &cursor, Address from, Address to, int flags)
{
  const bool found = to == 0 ? cursor.first_from(from, flags)
                            : cursor.next_from(from, Address(to - 1), flags);
  return found && cursor.to == to;
}

// Ordinary flow is reported before address-ordered code refs, regardless of
// its target address. Check it before seeking the non-flow group.
template <typename Cursor, typename Address>
bool viy_code_xref_exists(Cursor &cursor, Address from, Address to,
                          int code_flags, int noflow_flag)
{
  if (cursor.first_from(from, code_flags) && cursor.to == to)
    return true;
  return viy_sorted_xref_exists(cursor, from, to, code_flags | noflow_flag);
}

} // namespace viy
