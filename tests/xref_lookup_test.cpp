#include "xref_lookup.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <optional>
#include <set>

namespace {
constexpr int code = 4;
constexpr int noflow = 1;
constexpr int data = 2;
using Address = uint64_t;

struct Cursor
{
  Address to = 0;
  std::set<Address> crefs;
  std::set<Address> drefs;
  std::optional<Address> flow;
  size_t first_calls = 0;
  size_t seek_calls = 0;

  bool first_from(Address, int flags)
  {
    ++first_calls;
    if ((flags & code) && !(flags & noflow) && flow)
    {
      to = *flow;
      return true;
    }
    const auto &refs = flags & data ? drefs : crefs;
    if (refs.empty()) return false;
    to = *refs.begin();
    return true;
  }
  bool next_from(Address, Address after, int flags)
  {
    ++seek_calls;
    const auto &refs = flags & data ? drefs : crefs;
    const auto next = refs.upper_bound(after);
    if (next == refs.end()) return false;
    to = *next;
    return true;
  }
  // Deliberately no next_from(): lookup must never perform a linear walk.
};

void check(bool condition)
{
  if (!condition) std::exit(1);
}
}

int main()
{
  Cursor cursor;
  for (Address target = 0; target < 100000; target += 2)
    cursor.drefs.insert(target);
  cursor.drefs.insert(std::numeric_limits<Address>::max() - 1);
  cursor.crefs = {0, 9, 200000};
  cursor.flow = 123; // Flow is first even when lower explicit targets exist.
  for (Address target = 0; target < 100003; ++target)
  {
    check(viy::viy_sorted_xref_exists(cursor, Address{17}, target, data)
          == (cursor.drefs.count(target) != 0));
    check(viy::viy_code_xref_exists(cursor, Address{17}, target, code, noflow)
          == (cursor.crefs.count(target) != 0 || cursor.flow == target));
  }
  for (Address target : {std::numeric_limits<Address>::max() - 1,
                         std::numeric_limits<Address>::max()})
    check(viy::viy_sorted_xref_exists(cursor, Address{17}, target, data)
          == (cursor.drefs.count(target) != 0));
  check(cursor.seek_calls <= 2 * 100003 + 2);
  check(cursor.first_calls <= 100003 + 2);

  // No cache survives host mutations: deletions and additions are visible.
  cursor.drefs.erase(2);
  cursor.drefs.insert(3);
  check(!viy::viy_sorted_xref_exists(cursor, Address{17}, Address{2}, data));
  check(viy::viy_sorted_xref_exists(cursor, Address{17}, Address{3}, data));
  cursor.crefs.clear();
  check(viy::viy_code_xref_exists(cursor, Address{17}, Address{123}, code, noflow));
  cursor.flow.reset();
  check(!viy::viy_code_xref_exists(cursor, Address{17}, Address{123}, code, noflow));
  check(!viy::viy_code_xref_exists(cursor, Address{17}, Address{0}, code, noflow));
  cursor.drefs.clear();
  check(!viy::viy_sorted_xref_exists(cursor, Address{17}, Address{0}, data));
  std::cout << "xref seek regressions passed\n";
}
