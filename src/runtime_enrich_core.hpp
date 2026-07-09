/*
 * runtime_enrich_core.hpp -- IDA-free policy for runtime-value enrichment.
 *
 * The emulator produces exact final memory observations.  This module turns
 * those observations into deterministic, provenance-aware write and string
 * groups and implements the fail-closed overlap/conflict policy.  Keeping the
 * policy independent of IDA makes the mutation gates in runtime_enrich.cpp
 * directly testable without copying their logic into a test harness.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "emu_driver.hpp"

namespace viy {
namespace runtime_core {

constexpr size_t kDefaultMinimumStringChars = 4;
constexpr size_t kDefaultMaxStringCandidatesPerWrite = 64;
constexpr size_t kDefaultMaxRuntimeStringBytes = 4096;

struct RunKey
{
  uint32_t run_id = 0;
  uint64_t seed = 0;

  bool operator<(const RunKey &r) const
  {
    return std::tie(run_id, seed) < std::tie(r.run_id, r.seed);
  }

  bool operator==(const RunKey &r) const
  {
    return run_id == r.run_id && seed == r.seed;
  }
};

RunKey run_key(const MemoryBytes &observation);
RunKey run_key(const DataAcc &observation);
RunKey run_key(const ExecEdge &observation);
RunKey run_key(const ExecPoint &observation);

enum class RuntimeEncoding : uint8_t
{
  ASCII = 0,
  UTF8,
  UTF16_LE,
  UTF16_BE,
  UTF32_LE,
  UTF32_BE,
};

// NUL_TERMINATED includes the terminator in StringKey::raw.  Pascal layouts
// include their 1-, 2-, or 4-byte length prefix in StringKey::raw and have no
// terminator.  A Pascal length counts encoded code units, matching IDA's
// STRTYPE_PASCAL/LEN2/LEN4 layouts (bytes for ASCII/UTF-8, 16- or 32-bit units
// for the fixed-width encodings).
enum class StringLayout : uint8_t
{
  NUL_TERMINATED = 0,
  PASCAL8,
  PASCAL16,
  PASCAL32,
};

const char *encoding_name(RuntimeEncoding encoding);
const char *layout_name(StringLayout layout);
size_t layout_prefix_size(StringLayout layout);
std::string escaped_preview(const std::vector<uint32_t> &codepoints);

struct WriteKey
{
  uint64_t addr = 0;
  DataScope scope = DataScope::IMAGE;
  std::vector<uint8_t> bytes;

  bool operator<(const WriteKey &r) const
  {
    return std::tie(scope, addr, bytes) < std::tie(r.scope, r.addr, r.bytes);
  }
};

struct WriteGroup
{
  WriteKey key;
  std::set<RunKey> runs;

  bool corroborated() const { return runs.size() >= 2; }
};

using WriteGroups = std::map<WriteKey, WriteGroup>;

struct WriteCollection
{
  WriteGroups groups;
  size_t observations = 0;
  size_t corroborated_groups = 0;
  size_t uncorroborated_groups = 0;
};

WriteCollection collect_write_groups(const std::vector<MemoryBytes> &observations);

// True if any same-scope observation has a different byte anywhere in the
// overlap with [addr, addr + expected.size()).  Empty/overflowing candidates
// and malformed overflowing observations fail closed.
bool range_has_conflict(const std::vector<MemoryBytes> &observations,
                        uint64_t addr,
                        const std::vector<uint8_t> &expected,
                        DataScope scope);

// Return runs in which an overlapping same-scope write happened strictly
// before execution entered the candidate range.  This is the temporal gate for
// self-modifying-code correlation.
std::set<RunKey> write_then_execute_runs(
        const std::vector<DataAcc> &accesses,
        const std::vector<ExecPoint> &execution,
        uint64_t addr,
        size_t size,
        DataScope scope);

// Temporal/provenance gate for correlating a pointer read with a later
// control-flow edge.  Address/value matching remains the caller's concern.
bool read_precedes_edge(const DataAcc &read, const ExecEdge &edge);

struct StringKey
{
  uint64_t addr = 0;
  DataScope scope = DataScope::IMAGE;
  RuntimeEncoding encoding = RuntimeEncoding::ASCII;
  StringLayout layout = StringLayout::NUL_TERMINATED;
  std::vector<uint8_t> raw;

  bool operator<(const StringKey &r) const
  {
    return std::tie(scope, addr, encoding, layout, raw)
         < std::tie(r.scope, r.addr, r.encoding, r.layout, r.raw);
  }
};

struct StringGroup
{
  StringKey key;
  std::vector<uint32_t> codepoints;
  std::set<RunKey> runs;

  bool corroborated() const { return runs.size() >= 2; }
};

using StringGroups = std::map<StringKey, StringGroup>;

struct StringScanOptions
{
  bool image_big_endian = false;
  bool allow_unicode = true;
  bool allow_length_prefixed = true;
  size_t minimum_characters = kDefaultMinimumStringChars;
  size_t max_candidate_bytes = kDefaultMaxRuntimeStringBytes;
  size_t max_candidates_per_write = kDefaultMaxStringCandidatesPerWrite;
};

struct StringCollection
{
  StringGroups groups;
  // Number of successful per-observation decodes before exact-value grouping.
  size_t observations = 0;
};

// Scan every final-write buffer from left to right.  A successful candidate is
// consumed whole, allowing multiple adjacent strings while preventing nested
// suffixes of one candidate from being reported.  At an offset with multiple
// incompatible valid interpretations, no candidate is emitted (ambiguity
// guard) and scanning advances by one byte.
StringCollection collect_string_groups(
        const std::vector<MemoryBytes> &observations,
        const StringScanOptions &options = StringScanOptions{});

} // namespace runtime_core
} // namespace viy
