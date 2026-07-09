/*
 * runtime_enrich_core.cpp -- IDA-free runtime enrichment policy.
 */
#include "runtime_enrich_core.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace viy {
namespace runtime_core {

namespace {

struct DecodedString
{
  RuntimeEncoding encoding = RuntimeEncoding::ASCII;
  StringLayout layout = StringLayout::NUL_TERMINATED;
  size_t raw_size = 0;
  std::vector<uint32_t> codepoints;
  std::vector<uint8_t> raw;
};

bool checked_end(uint64_t start, size_t size, uint64_t *end)
{
  if ( size > std::numeric_limits<uint64_t>::max() - start )
    return false;
  *end = start + static_cast<uint64_t>(size);
  return true;
}

bool ranges_overlap(uint64_t left, size_t left_size,
                    uint64_t right, size_t right_size)
{
  uint64_t left_end = 0;
  uint64_t right_end = 0;
  return left_size != 0 && right_size != 0
      && checked_end(left, left_size, &left_end)
      && checked_end(right, right_size, &right_end)
      && left < right_end && right < left_end;
}

bool scalar_is_text(uint32_t cp)
{
  if ( cp == '\t' || cp == '\n' || cp == '\r' )
    return true;
  if ( cp < 0x20 || (cp >= 0x7F && cp <= 0x9F) )
    return false;
  return cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
}

void append_utf8(std::string &out, uint32_t cp)
{
  if ( cp <= 0x7F )
  {
    out.push_back(static_cast<char>(cp));
  }
  else if ( cp <= 0x7FF )
  {
    out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
  else if ( cp <= 0xFFFF )
  {
    out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
  else
  {
    out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
  }
}

uint16_t read_u16(const uint8_t *p, bool big_endian)
{
  if ( big_endian )
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
  return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t read_u32(const uint8_t *p, bool big_endian)
{
  if ( big_endian )
  {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         | static_cast<uint32_t>(p[3]);
  }
  return static_cast<uint32_t>(p[0])
       | (static_cast<uint32_t>(p[1]) << 8)
       | (static_cast<uint32_t>(p[2]) << 16)
       | (static_cast<uint32_t>(p[3]) << 24);
}

bool decode_utf8_exact(const uint8_t *bytes, size_t size,
                       size_t minimum_characters,
                       std::vector<uint32_t> *codepoints,
                       RuntimeEncoding *encoding)
{
  std::vector<uint32_t> result;
  size_t i = 0;
  bool all_ascii = true;
  while ( i < size )
  {
    const uint8_t first = bytes[i];
    uint32_t cp = 0;
    size_t extra = 0;
    if ( first < 0x80 )
    {
      cp = first;
    }
    else if ( first >= 0xC2 && first <= 0xDF )
    {
      cp = first & 0x1F;
      extra = 1;
    }
    else if ( first >= 0xE0 && first <= 0xEF )
    {
      cp = first & 0x0F;
      extra = 2;
    }
    else if ( first >= 0xF0 && first <= 0xF4 )
    {
      cp = first & 0x07;
      extra = 3;
    }
    else
    {
      return false;
    }

    if ( extra >= size - i )
      return false;
    for ( size_t j = 1; j <= extra; ++j )
    {
      const uint8_t continuation = bytes[i + j];
      if ( (continuation & 0xC0) != 0x80 )
        return false;
      cp = (cp << 6) | (continuation & 0x3F);
    }
    // The lead-byte bounds plus these scalar checks reject overlong forms,
    // UTF-16 surrogates and values beyond Unicode's maximum scalar.
    if ( (extra == 2 && cp < 0x800)
      || (extra == 3 && cp < 0x10000)
      || !scalar_is_text(cp) )
    {
      return false;
    }
    all_ascii = all_ascii && cp < 0x80;
    result.push_back(cp);
    i += extra + 1;
  }
  if ( result.size() < minimum_characters )
    return false;
  *codepoints = std::move(result);
  *encoding = all_ascii ? RuntimeEncoding::ASCII : RuntimeEncoding::UTF8;
  return true;
}

bool decode_utf16_exact(const uint8_t *bytes, size_t size, bool big_endian,
                        size_t minimum_characters,
                        std::vector<uint32_t> *codepoints)
{
  if ( size == 0 || size % 2 != 0 )
    return false;
  std::vector<uint32_t> result;
  size_t i = 0;
  while ( i < size )
  {
    const uint16_t first = read_u16(bytes + i, big_endian);
    uint32_t cp = first;
    if ( first >= 0xD800 && first <= 0xDBFF )
    {
      if ( size - i < 4 )
        return false;
      const uint16_t second = read_u16(bytes + i + 2, big_endian);
      if ( second < 0xDC00 || second > 0xDFFF )
        return false;
      cp = 0x10000
         + ((static_cast<uint32_t>(first - 0xD800) << 10)
           | static_cast<uint32_t>(second - 0xDC00));
      i += 2;
    }
    else if ( first >= 0xDC00 && first <= 0xDFFF )
    {
      return false;
    }
    if ( !scalar_is_text(cp) )
      return false;
    result.push_back(cp);
    i += 2;
  }
  if ( result.size() < minimum_characters )
    return false;
  *codepoints = std::move(result);
  return true;
}

bool decode_utf32_exact(const uint8_t *bytes, size_t size, bool big_endian,
                        size_t minimum_characters,
                        std::vector<uint32_t> *codepoints)
{
  if ( size == 0 || size % 4 != 0 )
    return false;
  std::vector<uint32_t> result;
  for ( size_t i = 0; i < size; i += 4 )
  {
    const uint32_t cp = read_u32(bytes + i, big_endian);
    if ( !scalar_is_text(cp) )
      return false;
    result.push_back(cp);
  }
  if ( result.size() < minimum_characters )
    return false;
  *codepoints = std::move(result);
  return true;
}

bool assign_candidate(const uint8_t *start, size_t raw_size,
                      RuntimeEncoding encoding, StringLayout layout,
                      std::vector<uint32_t> codepoints,
                      DecodedString *out)
{
  out->encoding = encoding;
  out->layout = layout;
  out->raw_size = raw_size;
  out->codepoints = std::move(codepoints);
  out->raw.assign(start, start + raw_size);
  return true;
}

bool decode_nul_utf8(const uint8_t *bytes, size_t size,
                     size_t minimum_characters, DecodedString *out)
{
  const uint8_t *terminator = std::find(bytes, bytes + size, uint8_t{0});
  if ( terminator == bytes + size )
    return false;
  const size_t payload_size = static_cast<size_t>(terminator - bytes);
  std::vector<uint32_t> codepoints;
  RuntimeEncoding encoding = RuntimeEncoding::ASCII;
  if ( !decode_utf8_exact(bytes, payload_size, minimum_characters,
                          &codepoints, &encoding) )
  {
    return false;
  }
  return assign_candidate(bytes, payload_size + 1, encoding,
                          StringLayout::NUL_TERMINATED,
                          std::move(codepoints), out);
}

bool decode_nul_utf16(const uint8_t *bytes, size_t size, bool big_endian,
                      size_t minimum_characters, DecodedString *out)
{
  for ( size_t payload_size = 0; payload_size + 1 < size; payload_size += 2 )
  {
    if ( read_u16(bytes + payload_size, big_endian) != 0 )
      continue;
    std::vector<uint32_t> codepoints;
    if ( !decode_utf16_exact(bytes, payload_size, big_endian,
                             minimum_characters, &codepoints) )
    {
      return false;
    }
    return assign_candidate(bytes, payload_size + 2,
                            big_endian ? RuntimeEncoding::UTF16_BE
                                       : RuntimeEncoding::UTF16_LE,
                            StringLayout::NUL_TERMINATED,
                            std::move(codepoints), out);
  }
  return false;
}

bool decode_nul_utf32(const uint8_t *bytes, size_t size, bool big_endian,
                      size_t minimum_characters, DecodedString *out)
{
  for ( size_t payload_size = 0; payload_size + 3 < size; payload_size += 4 )
  {
    if ( read_u32(bytes + payload_size, big_endian) != 0 )
      continue;
    std::vector<uint32_t> codepoints;
    if ( !decode_utf32_exact(bytes, payload_size, big_endian,
                             minimum_characters, &codepoints) )
    {
      return false;
    }
    return assign_candidate(bytes, payload_size + 4,
                            big_endian ? RuntimeEncoding::UTF32_BE
                                       : RuntimeEncoding::UTF32_LE,
                            StringLayout::NUL_TERMINATED,
                            std::move(codepoints), out);
  }
  return false;
}

// Pick the candidate explaining the most Unicode scalars, then the most raw
// bytes.  Native-endian fixed-width candidates are inserted first, making an
// otherwise exact tie deterministic and architecture-appropriate.
bool best_nul_candidate(const uint8_t *bytes, size_t size,
                        const StringScanOptions &options, DecodedString *out)
{
  std::vector<DecodedString> candidates;
  if ( options.allow_unicode )
  {
    DecodedString candidate;
    if ( decode_nul_utf32(bytes, size, options.image_big_endian,
                          options.minimum_characters, &candidate) )
    {
      candidates.push_back(candidate);
    }
    if ( decode_nul_utf16(bytes, size, options.image_big_endian,
                          options.minimum_characters, &candidate) )
    {
      candidates.push_back(candidate);
    }
  }
  DecodedString byte_candidate;
  if ( decode_nul_utf8(bytes, size, options.minimum_characters, &byte_candidate) )
    candidates.push_back(std::move(byte_candidate));
  if ( candidates.empty() )
    return false;

  const auto best = std::max_element(candidates.begin(), candidates.end(),
    [](const DecodedString &a, const DecodedString &b)
    {
      return std::make_pair(a.codepoints.size(), a.raw_size)
           < std::make_pair(b.codepoints.size(), b.raw_size);
    });
  *out = *best;
  return true;
}

uint64_t read_prefix(const uint8_t *bytes, size_t width, bool big_endian)
{
  switch ( width )
  {
    case 1: return bytes[0];
    case 2: return read_u16(bytes, big_endian);
    case 4: return read_u32(bytes, big_endian);
    default: return 0;
  }
}

bool checked_payload_size(uint64_t units, size_t unit_width,
                          size_t prefix_width, size_t maximum,
                          size_t *payload_size, size_t *raw_size)
{
  if ( units == 0 || units > std::numeric_limits<size_t>::max() / unit_width )
    return false;
  const size_t payload = static_cast<size_t>(units) * unit_width;
  if ( payload > maximum || prefix_width > maximum - payload )
    return false;
  *payload_size = payload;
  *raw_size = prefix_width + payload;
  return true;
}

void add_pascal_interpretations(const uint8_t *bytes, size_t size,
                                size_t prefix_width, StringLayout layout,
                                const StringScanOptions &options,
                                std::vector<DecodedString> *candidates)
{
  if ( prefix_width > size )
    return;
  const uint64_t units = read_prefix(bytes, prefix_width,
                                     options.image_big_endian);
  const uint8_t *payload = bytes + prefix_width;
  const size_t available = size - prefix_width;

  size_t payload_size = 0;
  size_t raw_size = 0;
  if ( checked_payload_size(units, 1, prefix_width,
                            options.max_candidate_bytes,
                            &payload_size, &raw_size)
    && payload_size <= available )
  {
    std::vector<uint32_t> codepoints;
    RuntimeEncoding encoding = RuntimeEncoding::ASCII;
    if ( decode_utf8_exact(payload, payload_size, options.minimum_characters,
                           &codepoints, &encoding) )
    {
      DecodedString candidate;
      assign_candidate(bytes, raw_size, encoding, layout,
                       std::move(codepoints), &candidate);
      candidates->push_back(std::move(candidate));
    }
  }

  if ( !options.allow_unicode )
    return;
  // Length-prefixed fixed-width strings use the image byte order.  Trying the
  // opposite order makes ordinary ASCII-range UTF-16 payloads valid in both
  // directions (e.g. U+0041 versus U+4100), defeating the ambiguity guard.
  const bool string_big_endian = options.image_big_endian;
  if ( checked_payload_size(units, 2, prefix_width,
                            options.max_candidate_bytes,
                            &payload_size, &raw_size)
    && payload_size <= available )
  {
    std::vector<uint32_t> codepoints;
    if ( decode_utf16_exact(payload, payload_size, string_big_endian,
                            options.minimum_characters, &codepoints) )
    {
      DecodedString candidate;
      assign_candidate(bytes, raw_size,
                       string_big_endian ? RuntimeEncoding::UTF16_BE
                                         : RuntimeEncoding::UTF16_LE,
                       layout, std::move(codepoints), &candidate);
      candidates->push_back(std::move(candidate));
    }
  }
  if ( checked_payload_size(units, 4, prefix_width,
                            options.max_candidate_bytes,
                            &payload_size, &raw_size)
    && payload_size <= available )
  {
    std::vector<uint32_t> codepoints;
    if ( decode_utf32_exact(payload, payload_size, string_big_endian,
                            options.minimum_characters, &codepoints) )
    {
      DecodedString candidate;
      assign_candidate(bytes, raw_size,
                       string_big_endian ? RuntimeEncoding::UTF32_BE
                                         : RuntimeEncoding::UTF32_LE,
                       layout, std::move(codepoints), &candidate);
      candidates->push_back(std::move(candidate));
    }
  }
}

bool unique_pascal_candidate(const uint8_t *bytes, size_t size,
                             const StringScanOptions &options,
                             DecodedString *out)
{
  if ( !options.allow_length_prefixed )
    return false;
  std::vector<DecodedString> candidates;
  add_pascal_interpretations(bytes, size, 1, StringLayout::PASCAL8,
                             options, &candidates);
  add_pascal_interpretations(bytes, size, 2, StringLayout::PASCAL16,
                             options, &candidates);
  add_pascal_interpretations(bytes, size, 4, StringLayout::PASCAL32,
                             options, &candidates);
  if ( candidates.size() != 1 )
    return false;
  *out = std::move(candidates.front());
  return true;
}

bool same_candidate(const DecodedString &a, const DecodedString &b)
{
  return a.encoding == b.encoding && a.layout == b.layout
      && a.raw == b.raw && a.codepoints == b.codepoints;
}

} // namespace

RunKey run_key(const MemoryBytes &observation)
{
  return RunKey{ observation.run_id, observation.seed };
}

RunKey run_key(const DataAcc &observation)
{
  return RunKey{ observation.run_id, observation.seed };
}

RunKey run_key(const ExecEdge &observation)
{
  return RunKey{ observation.run_id, observation.seed };
}

RunKey run_key(const ExecPoint &observation)
{
  return RunKey{ observation.run_id, observation.seed };
}

const char *encoding_name(RuntimeEncoding encoding)
{
  switch ( encoding )
  {
    case RuntimeEncoding::ASCII:    return "ASCII";
    case RuntimeEncoding::UTF8:     return "UTF-8";
    case RuntimeEncoding::UTF16_LE: return "UTF-16LE";
    case RuntimeEncoding::UTF16_BE: return "UTF-16BE";
    case RuntimeEncoding::UTF32_LE: return "UTF-32LE";
    case RuntimeEncoding::UTF32_BE: return "UTF-32BE";
  }
  return "text";
}

const char *layout_name(StringLayout layout)
{
  switch ( layout )
  {
    case StringLayout::NUL_TERMINATED: return "NUL-terminated";
    case StringLayout::PASCAL8:        return "Pascal-8";
    case StringLayout::PASCAL16:       return "Pascal-16";
    case StringLayout::PASCAL32:       return "Pascal-32";
  }
  return "unknown-layout";
}

size_t layout_prefix_size(StringLayout layout)
{
  switch ( layout )
  {
    case StringLayout::NUL_TERMINATED: return 0;
    case StringLayout::PASCAL8:        return 1;
    case StringLayout::PASCAL16:       return 2;
    case StringLayout::PASCAL32:       return 4;
  }
  return 0;
}

std::string escaped_preview(const std::vector<uint32_t> &codepoints)
{
  std::string out;
  size_t shown = 0;
  for ( uint32_t cp : codepoints )
  {
    if ( shown == 80 || out.size() > 160 )
    {
      out += "...";
      break;
    }
    ++shown;
    switch ( cp )
    {
      case '\\': out += "\\\\"; break;
      case '"':  out += "\\\""; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: append_utf8(out, cp); break;
    }
  }
  return out;
}

WriteCollection collect_write_groups(const std::vector<MemoryBytes> &observations)
{
  WriteCollection result;
  result.observations = observations.size();
  for ( const MemoryBytes &observation : observations )
  {
    if ( observation.bytes.empty() )
      continue;
    WriteKey key{ observation.addr, observation.scope, observation.bytes };
    WriteGroup &group = result.groups[key];
    group.key = key;
    group.runs.insert(run_key(observation));
  }
  for ( const auto &entry : result.groups )
  {
    if ( entry.second.corroborated() )
      ++result.corroborated_groups;
    else
      ++result.uncorroborated_groups;
  }
  return result;
}

bool range_has_conflict(const std::vector<MemoryBytes> &observations,
                        uint64_t addr,
                        const std::vector<uint8_t> &expected,
                        DataScope scope)
{
  uint64_t expected_end = 0;
  if ( expected.empty() || !checked_end(addr, expected.size(), &expected_end) )
    return true;
  for ( const MemoryBytes &observation : observations )
  {
    if ( observation.scope != scope || observation.bytes.empty() )
      continue;
    uint64_t observed_end = 0;
    if ( !checked_end(observation.addr, observation.bytes.size(), &observed_end) )
      return true;
    const uint64_t lo = std::max(addr, observation.addr);
    const uint64_t hi = std::min(expected_end, observed_end);
    if ( lo >= hi )
      continue;
    for ( uint64_t ea = lo; ea < hi; ++ea )
    {
      const size_t expected_offset = static_cast<size_t>(ea - addr);
      const size_t observed_offset = static_cast<size_t>(ea - observation.addr);
      if ( expected[expected_offset] != observation.bytes[observed_offset] )
        return true;
    }
  }
  return false;
}

std::set<RunKey> write_then_execute_runs(
        const std::vector<DataAcc> &accesses,
        const std::vector<ExecPoint> &execution,
        uint64_t addr,
        size_t size,
        DataScope scope)
{
  std::set<RunKey> result;
  uint64_t end = 0;
  if ( size == 0 || !checked_end(addr, size, &end) )
    return result;
  for ( const DataAcc &access : accesses )
  {
    if ( access.kind != RAX_MEM_WRITE || access.scope != scope
      || access.size == 0
      || !ranges_overlap(addr, size, access.addr,
                         static_cast<size_t>(access.size)) )
    {
      continue;
    }
    for ( const ExecPoint &point : execution )
    {
      if ( point.run_id == access.run_id && point.seed == access.seed
        && point.sequence > access.sequence
        && point.pc >= addr && point.pc < end )
      {
        result.insert(run_key(access));
        break;
      }
    }
  }
  return result;
}

bool read_precedes_edge(const DataAcc &read, const ExecEdge &edge)
{
  return read.kind == RAX_MEM_READ
      && read.run_id == edge.run_id && read.seed == edge.seed
      && read.sequence < edge.sequence;
}

StringCollection collect_string_groups(
        const std::vector<MemoryBytes> &observations,
        const StringScanOptions &options)
{
  StringCollection result;
  if ( options.minimum_characters == 0 || options.max_candidate_bytes == 0
    || options.max_candidates_per_write == 0 )
  {
    return result;
  }

  for ( const MemoryBytes &observation : observations )
  {
    size_t offset = 0;
    size_t count = 0;
    while ( offset < observation.bytes.size()
         && count < options.max_candidates_per_write )
    {
      const size_t remaining = observation.bytes.size() - offset;
      const size_t probe_size = std::min(options.max_candidate_bytes, remaining);
      const uint8_t *probe = observation.bytes.data() + offset;
      DecodedString nul_candidate;
      DecodedString pascal_candidate;
      const bool has_nul = best_nul_candidate(probe, probe_size, options,
                                               &nul_candidate);
      const bool has_pascal = unique_pascal_candidate(probe, probe_size, options,
                                                       &pascal_candidate);

      const DecodedString *selected = nullptr;
      if ( has_nul && has_pascal )
      {
        if ( same_candidate(nul_candidate, pascal_candidate) )
          selected = &nul_candidate;
        // Otherwise fail closed: the same start has two incompatible layouts.
      }
      else if ( has_nul )
      {
        selected = &nul_candidate;
      }
      else if ( has_pascal )
      {
        selected = &pascal_candidate;
      }

      if ( selected == nullptr || selected->raw_size == 0
        || selected->raw_size > remaining
        || offset > std::numeric_limits<uint64_t>::max() - observation.addr )
      {
        ++offset;
        continue;
      }

      const uint64_t candidate_addr =
        observation.addr + static_cast<uint64_t>(offset);
      uint64_t candidate_end = 0;
      if ( !checked_end(candidate_addr, selected->raw_size, &candidate_end) )
      {
        ++offset;
        continue;
      }

      StringKey key;
      key.addr = candidate_addr;
      key.scope = observation.scope;
      key.encoding = selected->encoding;
      key.layout = selected->layout;
      key.raw = selected->raw;
      StringGroup &group = result.groups[key];
      group.key = key;
      group.codepoints = selected->codepoints;
      group.runs.insert(run_key(observation));
      ++result.observations;
      ++count;
      offset += selected->raw_size;
    }
  }
  return result;
}

} // namespace runtime_core
} // namespace viy
