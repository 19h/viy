#include "runtime_enrich_core.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

using viy::DataAcc;
using viy::DataScope;
using viy::ExecEdge;
using viy::ExecPoint;
using viy::MemoryBytes;
using viy::runtime_core::RuntimeEncoding;
using viy::runtime_core::RunKey;
using viy::runtime_core::StringCollection;
using viy::runtime_core::StringLayout;
using viy::runtime_core::StringScanOptions;

[[noreturn]] void fail(const char *expression, int line)
{
  std::cerr << "runtime enrichment core check failed at line " << line
            << ": " << expression << '\n';
  std::exit(1);
}

#define CHECK(expression) \
  do { if ( !(expression) ) fail(#expression, __LINE__); } while ( false )

MemoryBytes observation(uint64_t addr, std::vector<uint8_t> bytes,
                        DataScope scope, uint32_t run_id, uint64_t seed)
{
  MemoryBytes result;
  result.addr = addr;
  result.bytes = std::move(bytes);
  result.scope = scope;
  result.run_id = run_id;
  result.seed = seed;
  return result;
}

StringScanOptions nul_options(bool big_endian = false)
{
  StringScanOptions result;
  result.image_big_endian = big_endian;
  result.allow_unicode = true;
  result.allow_length_prefixed = false;
  return result;
}

StringCollection scan(const std::vector<uint8_t> &bytes,
                      const StringScanOptions &options,
                      uint64_t addr = 0x1000,
                      DataScope scope = DataScope::IMAGE)
{
  return viy::runtime_core::collect_string_groups(
    { observation(addr, bytes, scope, 1, 0x11) }, options);
}

bool has_string_at(const StringCollection &collection, uint64_t addr)
{
  return std::any_of(collection.groups.begin(), collection.groups.end(),
    [addr](const auto &entry) { return entry.first.addr == addr; });
}

const viy::runtime_core::StringGroup &only_string(
        const StringCollection &collection)
{
  CHECK(collection.groups.size() == 1);
  return collection.groups.begin()->second;
}

void append_u16(std::vector<uint8_t> *bytes, uint16_t value, bool big_endian)
{
  if ( big_endian )
  {
    bytes->push_back(static_cast<uint8_t>(value >> 8));
    bytes->push_back(static_cast<uint8_t>(value));
  }
  else
  {
    bytes->push_back(static_cast<uint8_t>(value));
    bytes->push_back(static_cast<uint8_t>(value >> 8));
  }
}

void append_u32(std::vector<uint8_t> *bytes, uint32_t value, bool big_endian)
{
  if ( big_endian )
  {
    bytes->push_back(static_cast<uint8_t>(value >> 24));
    bytes->push_back(static_cast<uint8_t>(value >> 16));
    bytes->push_back(static_cast<uint8_t>(value >> 8));
    bytes->push_back(static_cast<uint8_t>(value));
  }
  else
  {
    bytes->push_back(static_cast<uint8_t>(value));
    bytes->push_back(static_cast<uint8_t>(value >> 8));
    bytes->push_back(static_cast<uint8_t>(value >> 16));
    bytes->push_back(static_cast<uint8_t>(value >> 24));
  }
}

std::vector<uint8_t> utf16_sample(bool big_endian, bool terminated)
{
  // Four Unicode scalars: A, U+1F600, B, C.  The supplementary scalar proves
  // surrogate-pair handling rather than merely fixed-width ASCII lanes.
  std::vector<uint8_t> bytes;
  append_u16(&bytes, 0x0041, big_endian);
  append_u16(&bytes, 0xD83D, big_endian);
  append_u16(&bytes, 0xDE00, big_endian);
  append_u16(&bytes, 0x0042, big_endian);
  append_u16(&bytes, 0x0043, big_endian);
  if ( terminated )
    append_u16(&bytes, 0, big_endian);
  return bytes;
}

std::vector<uint8_t> utf32_sample(bool big_endian, bool terminated)
{
  std::vector<uint8_t> bytes;
  append_u32(&bytes, 0x41, big_endian);
  append_u32(&bytes, 0x1F642, big_endian);
  append_u32(&bytes, 0x42, big_endian);
  append_u32(&bytes, 0x43, big_endian);
  if ( terminated )
    append_u32(&bytes, 0, big_endian);
  return bytes;
}

void test_write_grouping_and_conflicts()
{
  const std::vector<uint8_t> stable{ 1, 2, 3, 4 };
  const std::vector<MemoryBytes> observations{
    observation(0x1000, stable, DataScope::IMAGE, 7, 0xAA),
    observation(0x1000, stable, DataScope::IMAGE, 7, 0xAA), // duplicate run
    observation(0x1000, stable, DataScope::IMAGE, 7, 0xBB), // distinct seed
    observation(0x2000, { 9 }, DataScope::STACK, 8, 0xCC),
    observation(0x2000, { 9 }, DataScope::STACK, 8, 0xCC),
  };
  const auto collection = viy::runtime_core::collect_write_groups(observations);
  CHECK(collection.observations == 5);
  CHECK(collection.groups.size() == 2);
  CHECK(collection.corroborated_groups == 1);
  CHECK(collection.uncorroborated_groups == 1);
  const auto stable_it = collection.groups.find(
    viy::runtime_core::WriteKey{ 0x1000, DataScope::IMAGE, stable });
  CHECK(stable_it != collection.groups.end());
  CHECK(stable_it->second.runs.size() == 2);
  CHECK(stable_it->second.corroborated());

  CHECK(!viy::runtime_core::range_has_conflict(
    { observation(0x1001, { 2, 3 }, DataScope::IMAGE, 1, 1) },
    0x1000, stable, DataScope::IMAGE));
  CHECK(viy::runtime_core::range_has_conflict(
    { observation(0x1002, { 0xFF }, DataScope::IMAGE, 99, 99) },
    0x1000, stable, DataScope::IMAGE));
  CHECK(!viy::runtime_core::range_has_conflict(
    { observation(0x1002, { 0xFF }, DataScope::STACK, 99, 99),
      observation(0x2000, { 0xFF }, DataScope::IMAGE, 99, 99) },
    0x1000, stable, DataScope::IMAGE));
  CHECK(viy::runtime_core::range_has_conflict({}, 0x1000, {}, DataScope::IMAGE));
  CHECK(viy::runtime_core::range_has_conflict(
    { observation(std::numeric_limits<uint64_t>::max(), { 1, 2 },
                  DataScope::IMAGE, 1, 1) },
    0x1000, stable, DataScope::IMAGE));
}

void test_ascii_and_strict_utf8()
{
  const auto ascii = scan({ 'h', 'e', 'l', 'l', 'o', 0 }, nul_options());
  const auto &ascii_group = only_string(ascii);
  CHECK(ascii_group.key.encoding == RuntimeEncoding::ASCII);
  CHECK(ascii_group.key.layout == StringLayout::NUL_TERMINATED);
  CHECK(ascii_group.codepoints.size() == 5);

  const std::vector<uint8_t> stable_text{ 's', 't', 'a', 'b', 'l', 'e', 0 };
  const auto corroborated = viy::runtime_core::collect_string_groups({
    observation(0x1200, stable_text, DataScope::STACK, 2, 0x20),
    observation(0x1200, stable_text, DataScope::STACK, 2, 0x20),
    observation(0x1200, stable_text, DataScope::STACK, 2, 0x21),
  }, nul_options());
  CHECK(corroborated.observations == 3);
  const auto &corroborated_group = only_string(corroborated);
  CHECK(corroborated_group.runs.size() == 2);
  CHECK(corroborated_group.corroborated());

  const auto utf8 = scan({ 0xC3, 0xA9, 'a', 'b', 'c', 0 }, nul_options());
  const auto &utf8_group = only_string(utf8);
  CHECK(utf8_group.key.encoding == RuntimeEncoding::UTF8);
  CHECK(utf8_group.codepoints.size() == 4);
  CHECK(utf8_group.codepoints.front() == 0xE9);

  // Invalid lead, continuation, overlong encoding, surrogate, and out-of-range
  // scalar must not produce a candidate at the malformed start.
  const std::vector<std::vector<uint8_t>> invalid{
    { 0x80, 'a', 'b', 'c', 0 },
    { 0xE2, 0x28, 0xA1, 'x', 0 },
    { 0xC0, 0xAF, 'a', 'b', 'c', 0 },
    { 0xE0, 0x80, 0xAF, 'a', 'b', 'c', 0 },
    { 0xED, 0xA0, 0x80, 'a', 'b', 'c', 0 },
    { 0xF4, 0x90, 0x80, 0x80, 'a', 'b', 'c', 0 },
  };
  for ( const auto &bytes : invalid )
    CHECK(!has_string_at(scan(bytes, nul_options()), 0x1000));
}

void test_utf16_and_utf32()
{
  for ( bool big_endian : { false, true } )
  {
    const auto utf16 = scan(utf16_sample(big_endian, true),
                            nul_options(big_endian));
    const auto &group16 = only_string(utf16);
    CHECK(group16.key.encoding == (big_endian ? RuntimeEncoding::UTF16_BE
                                             : RuntimeEncoding::UTF16_LE));
    CHECK(group16.codepoints.size() == 4);
    CHECK(group16.codepoints[1] == 0x1F600);

    const auto utf32 = scan(utf32_sample(big_endian, true),
                            nul_options(big_endian));
    const auto &group32 = only_string(utf32);
    CHECK(group32.key.encoding == (big_endian ? RuntimeEncoding::UTF32_BE
                                             : RuntimeEncoding::UTF32_LE));
    CHECK(group32.codepoints.size() == 4);
    CHECK(group32.codepoints[1] == 0x1F642);

    std::vector<uint8_t> lone_high;
    append_u16(&lone_high, 0x0041, big_endian);
    append_u16(&lone_high, 0xD83D, big_endian);
    append_u16(&lone_high, 0x0042, big_endian);
    append_u16(&lone_high, 0x0043, big_endian);
    append_u16(&lone_high, 0, big_endian);
    CHECK(!has_string_at(scan(lone_high, nul_options(big_endian)), 0x1000));

    std::vector<uint8_t> invalid32;
    append_u32(&invalid32, 0x41, big_endian);
    append_u32(&invalid32, 0xD800, big_endian);
    append_u32(&invalid32, 0x42, big_endian);
    append_u32(&invalid32, 0x43, big_endian);
    append_u32(&invalid32, 0, big_endian);
    CHECK(!has_string_at(scan(invalid32, nul_options(big_endian)), 0x1000));
  }
}

void test_bounds_offsets_scopes_and_determinism()
{
  CHECK(scan({ 'a', 'b', 'c', 0 }, nul_options()).groups.empty());
  CHECK(scan({ 'a', 'b', 'c', 'd', 0 }, nul_options()).groups.size() == 1);

  StringScanOptions bounded = nul_options();
  bounded.max_candidate_bytes = 5; // excludes hello's terminator
  const auto bounded_scan = scan({ 'h', 'e', 'l', 'l', 'o', 0 }, bounded);
  CHECK(!has_string_at(bounded_scan, 0x1000));
  CHECK(has_string_at(bounded_scan, 0x1001));
  CHECK(scan({ 'h', 'e', 'l', 'l', 'o', 0 }, nul_options(),
             std::numeric_limits<uint64_t>::max() - 2).groups.empty());

  const std::vector<uint8_t> adjacent{
    1, 2, 'o', 'n', 'e', '1', 0, 't', 'w', 'o', '2', 0
  };
  const auto multiple = scan(adjacent, nul_options(), 0x4000);
  CHECK(multiple.groups.size() == 2);
  CHECK(has_string_at(multiple, 0x4002));
  CHECK(has_string_at(multiple, 0x4007));

  bounded = nul_options();
  bounded.max_candidates_per_write = 1;
  CHECK(scan(adjacent, bounded, 0x4000).groups.size() == 1);

  const std::vector<uint8_t> text{ 's', 'c', 'o', 'p', 'e', 0 };
  std::vector<MemoryBytes> scoped{
    observation(0x5000, text, DataScope::HEAP, 3, 3),
    observation(0x5000, text, DataScope::IMAGE, 1, 1),
    observation(0x5000, text, DataScope::STACK, 2, 2),
  };
  const auto first = viy::runtime_core::collect_string_groups(scoped,
                                                               nul_options());
  std::reverse(scoped.begin(), scoped.end());
  const auto second = viy::runtime_core::collect_string_groups(scoped,
                                                                nul_options());
  CHECK(first.groups.size() == 3);
  CHECK(second.groups.size() == first.groups.size());
  auto left = first.groups.begin();
  auto right = second.groups.begin();
  for ( ; left != first.groups.end(); ++left, ++right )
  {
    CHECK(right != second.groups.end());
    CHECK(left->first.addr == right->first.addr);
    CHECK(left->first.scope == right->first.scope);
    CHECK(left->first.encoding == right->first.encoding);
    CHECK(left->first.layout == right->first.layout);
    CHECK(left->first.raw == right->first.raw);
    CHECK(left->second.runs == right->second.runs);
  }
  CHECK(first.groups.begin()->first.scope == DataScope::IMAGE);
}

std::vector<uint8_t> pascal_ascii(size_t prefix_width, bool big_endian)
{
  std::vector<uint8_t> bytes;
  if ( prefix_width == 1 )
    bytes.push_back(4);
  else if ( prefix_width == 2 )
    append_u16(&bytes, 4, big_endian);
  else
    append_u32(&bytes, 4, big_endian);
  bytes.insert(bytes.end(), { 't', 'e', 's', 't' });
  return bytes;
}

void test_length_prefixed_strings()
{
  for ( bool big_endian : { false, true } )
  {
    StringScanOptions options;
    options.image_big_endian = big_endian;
    options.allow_unicode = true;
    options.allow_length_prefixed = true;
    const std::pair<size_t, StringLayout> layouts[] = {
      { 1, StringLayout::PASCAL8 },
      { 2, StringLayout::PASCAL16 },
      { 4, StringLayout::PASCAL32 },
    };
    for ( const auto &layout : layouts )
    {
      const auto found = scan(pascal_ascii(layout.first, big_endian), options);
      const auto &group = only_string(found);
      CHECK(group.key.encoding == RuntimeEncoding::ASCII);
      CHECK(group.key.layout == layout.second);
      CHECK(group.codepoints.size() == 4);
    }

    // Prefix value is encoded-code-unit count: five UTF-16 units represent
    // four scalars because U+1F600 is a surrogate pair.
    std::vector<uint8_t> prefixed16{ 5 };
    const auto payload16 = utf16_sample(big_endian, false);
    prefixed16.insert(prefixed16.end(), payload16.begin(), payload16.end());
    const auto unicode16 = scan(prefixed16, options);
    const auto &group16 = only_string(unicode16);
    CHECK(group16.key.layout == StringLayout::PASCAL8);
    CHECK(group16.key.encoding == (big_endian ? RuntimeEncoding::UTF16_BE
                                             : RuntimeEncoding::UTF16_LE));
    CHECK(group16.codepoints.size() == 4);

    std::vector<uint8_t> prefixed32{ 4 };
    const auto payload32 = utf32_sample(big_endian, false);
    prefixed32.insert(prefixed32.end(), payload32.begin(), payload32.end());
    const auto unicode32 = scan(prefixed32, options);
    const auto &group32 = only_string(unicode32);
    CHECK(group32.key.encoding == (big_endian ? RuntimeEncoding::UTF32_BE
                                             : RuntimeEncoding::UTF32_LE));
  }

  StringScanOptions little;
  little.image_big_endian = false;
  little.allow_length_prefixed = true;
  StringScanOptions big = little;
  big.image_big_endian = true;
  CHECK(!has_string_at(scan(pascal_ascii(2, false), big), 0x1000));
  CHECK(!has_string_at(scan(pascal_ascii(2, true), little), 0x1000));

  // Insufficient payload and configured byte cap are rejected before any
  // multiplication/allocation based on the untrusted prefix.
  CHECK(scan({ 0xFF, 'a', 'b', 'c', 'd' }, little).groups.empty());
  little.max_candidate_bytes = 4;
  CHECK(scan(pascal_ascii(1, false), little).groups.empty());

  // Both byte-oriented "ABCD" and four native UTF-16 units "ABCDEFGH"
  // would be valid for this one-byte prefix.  Reject rather than guess.
  StringScanOptions ambiguous;
  ambiguous.image_big_endian = false;
  ambiguous.allow_unicode = true;
  ambiguous.allow_length_prefixed = true;
  CHECK(scan({ 4, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' },
             ambiguous).groups.empty());
}

DataAcc access(int kind, uint64_t addr, uint32_t size,
               uint32_t run_id, uint64_t seed, uint64_t sequence)
{
  DataAcc result;
  result.addr = addr;
  result.size = size;
  result.kind = kind;
  result.scope = DataScope::IMAGE;
  result.run_id = run_id;
  result.seed = seed;
  result.sequence = sequence;
  return result;
}

ExecPoint execution(uint64_t pc, uint32_t run_id, uint64_t seed,
                    uint64_t sequence)
{
  ExecPoint result;
  result.pc = pc;
  result.run_id = run_id;
  result.seed = seed;
  result.sequence = sequence;
  return result;
}

ExecEdge edge(uint64_t target, uint32_t run_id, uint64_t seed,
              uint64_t sequence)
{
  ExecEdge result;
  result.to = target;
  result.run_id = run_id;
  result.seed = seed;
  result.sequence = sequence;
  return result;
}

void test_temporal_correlations()
{
  const DataAcc write = access(RAX_MEM_WRITE, 0x7002, 2, 4, 0x44, 10);
  auto runs = viy::runtime_core::write_then_execute_runs(
    { write }, { execution(0x7003, 4, 0x44, 11) },
    0x7000, 8, DataScope::IMAGE);
  CHECK(runs == std::set<RunKey>({ RunKey{ 4, 0x44 } }));

  CHECK(viy::runtime_core::write_then_execute_runs(
    { write }, { execution(0x7003, 4, 0x44, 9) },
    0x7000, 8, DataScope::IMAGE).empty());
  CHECK(viy::runtime_core::write_then_execute_runs(
    { write }, { execution(0x7003, 5, 0x44, 11) },
    0x7000, 8, DataScope::IMAGE).empty());
  CHECK(viy::runtime_core::write_then_execute_runs(
    { write }, { execution(0x7003, 4, 0x45, 11) },
    0x7000, 8, DataScope::IMAGE).empty());
  CHECK(viy::runtime_core::write_then_execute_runs(
    { access(RAX_MEM_WRITE, 0x8000, 1, 4, 0x44, 1) },
    { execution(0x7003, 4, 0x44, 2) },
    0x7000, 8, DataScope::IMAGE).empty());

  const DataAcc read = access(RAX_MEM_READ, 0x9000, 8, 7, 0x77, 20);
  CHECK(viy::runtime_core::read_precedes_edge(read,
                                              edge(0xA000, 7, 0x77, 21)));
  CHECK(!viy::runtime_core::read_precedes_edge(read,
                                               edge(0xA000, 7, 0x77, 19)));
  CHECK(!viy::runtime_core::read_precedes_edge(read,
                                               edge(0xA000, 8, 0x77, 21)));
  CHECK(!viy::runtime_core::read_precedes_edge(read,
                                               edge(0xA000, 7, 0x78, 21)));
  DataAcc not_read = read;
  not_read.kind = RAX_MEM_WRITE;
  CHECK(!viy::runtime_core::read_precedes_edge(not_read,
                                               edge(0xA000, 7, 0x77, 21)));
}

} // namespace

int main()
{
  test_write_grouping_and_conflicts();
  test_ascii_and_strict_utf8();
  test_utf16_and_utf32();
  test_bounds_offsets_scopes_and_determinism();
  test_length_prefixed_strings();
  test_temporal_correlations();
  std::cout << "runtime enrichment core tests passed\n";
  return 0;
}
