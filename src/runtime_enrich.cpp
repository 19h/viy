/*
 * runtime_enrich.cpp -- guarded runtime-value enrichments. Main thread only.
 */
#include "runtime_enrich.hpp"
#include "runtime_enrich_core.hpp"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <auto.hpp>
#include <offset.hpp>
#include <nalt.hpp>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace viy {

namespace {

constexpr size_t kMaxCommentSitesPerFinding = 16;

using runtime_core::RunKey;
using runtime_core::RuntimeEncoding;
using runtime_core::StringGroup;
using runtime_core::StringLayout;
using runtime_core::WriteKey;
using runtime_core::WriteGroup;
using runtime_core::WriteGroups;

RunKey run_key(const MemoryBytes &b) { return runtime_core::run_key(b); }
RunKey run_key(const DataAcc &a) { return RunKey{ a.run_id, a.seed }; }
RunKey run_key(const ExecEdge &e) { return RunKey{ e.run_id, e.seed }; }

bool checked_end(uint64_t start, size_t size, uint64_t *end)
{
  if ( size > std::numeric_limits<uint64_t>::max() - start )
    return false;
  *end = start + size;
  return true;
}

bool ranges_overlap(uint64_t a, size_t asz, uint64_t b, size_t bsz)
{
  uint64_t ae = 0, be = 0;
  return checked_end(a, asz, &ae) && checked_end(b, bsz, &be) && a < be && b < ae;
}

bool range_in_one_segment(const ProgramImage &img, uint64_t start, size_t size,
                          const SegImage **out = nullptr)
{
  uint64_t end = 0;
  if ( size == 0 || !checked_end(start, size, &end) )
    return false;
  const SegImage *seg = img.segment_at(start);
  if ( seg == nullptr || end > seg->end )
    return false;
  if ( out != nullptr )
    *out = seg;
  return true;
}

bool segment_is_executable(const SegImage *seg)
{
  return seg != nullptr && (seg->perm == 0 || seg->has_perm(ViySegPerm::EXEC));
}

bool segment_is_data(const SegImage *seg)
{
  return seg != nullptr && (seg->perm == 0 || !seg->has_perm(ViySegPerm::EXEC));
}

bool current_bytes(ea_t ea, size_t size, std::vector<uint8_t> *out)
{
  if ( size == 0 || size > size_t(std::numeric_limits<ssize_t>::max()) )
    return false;
  out->assign(size, 0);
  return get_bytes(out->data(), (ssize_t)size, ea, GMB_READALL) >= 0;
}

bool current_bytes_equal(ea_t ea, const std::vector<uint8_t> &bytes)
{
  std::vector<uint8_t> current;
  return current_bytes(ea, bytes.size(), &current) && current == bytes;
}

bool snapshot_bytes(const ProgramImage &img, uint64_t ea, size_t size,
                    std::vector<uint8_t> *out, bool require_loaded)
{
  out->clear();
  out->reserve(size);
  for ( size_t i = 0; i < size; ++i )
  {
    const SegImage *seg = img.segment_at(ea + i);
    if ( seg == nullptr )
      return false;
    const uint64_t off = ea + i - seg->start;
    const bool loaded = seg->byte_loaded(ea + i);
    if ( require_loaded && !loaded )
      return false;
    out->push_back(loaded && off < seg->bytes.size() ? seg->bytes[(size_t)off] : 0);
  }
  return true;
}

bool range_is_undefined(ea_t ea, size_t size)
{
  for ( size_t i = 0; i < size; ++i )
  {
    const flags64_t f = get_flags(ea + i);
    if ( !is_unknown(f) || has_name(f) )
      return false;
  }
  return true;
}

enum class CommentResult { Added, Existing, Failed };

CommentResult add_repeatable_comment(ea_t ea, const char *text)
{
  qstring current;
  if ( get_cmt(&current, ea, true) > 0 && !current.empty() )
    return CommentResult::Existing;
  return set_cmt(ea, text, true) ? CommentResult::Added : CommentResult::Failed;
}

void account_comment(CommentResult result, RuntimeEnrichStats &stats)
{
  if ( result == CommentResult::Added )
    ++stats.comments_added;
  else if ( result == CommentResult::Existing )
    ++stats.comments_skipped_existing;
}

std::set<ea_t> writer_sites(const EmuEvents &events, uint64_t addr, size_t size,
                            DataScope scope, const std::set<RunKey> &runs)
{
  std::set<ea_t> sites;
  for ( const DataAcc &a : events.data )
  {
    if ( a.kind != RAX_MEM_WRITE || a.size == 0 || a.scope != scope
      || runs.find(run_key(a)) == runs.end()
      || !ranges_overlap(addr, size, a.addr, a.size) )
    {
      continue;
    }
    const flags64_t f = get_flags((ea_t)a.from);
    if ( is_head(f) && is_code(f) )
      sites.insert((ea_t)a.from);
  }
  return sites;
}

void comment_writers(const EmuEvents &events, uint64_t addr, size_t size,
                     DataScope scope, const std::set<RunKey> &runs,
                     const qstring &text, RuntimeEnrichStats &stats,
                     size_t *category_count = nullptr)
{
  const std::set<ea_t> sites = writer_sites(events, addr, size, scope, runs);
  size_t attempted = 0;
  for ( ea_t site : sites )
  {
    if ( attempted++ == kMaxCommentSitesPerFinding )
      break;
    const CommentResult result = add_repeatable_comment(site, text.c_str());
    account_comment(result, stats);
    if ( category_count != nullptr && result == CommentResult::Added )
      ++*category_count;
  }
}

// True when any final observation disagrees with `expected` over the candidate
// range. This deliberately treats one divergent run as a conflict even when a
// different value reached the two-run corroboration threshold.
bool range_has_conflict(const EmuEvents &events, uint64_t addr,
                        const std::vector<uint8_t> &expected, DataScope scope)
{
  return runtime_core::range_has_conflict(events.final_writes, addr,
                                          expected, scope);
}

bool range_execution_observed(const EmuEvents &events, uint64_t addr, size_t size)
{
  uint64_t end = 0;
  if ( !checked_end(addr, size, &end) )
    return false;
  if ( std::any_of(events.execution.begin(), events.execution.end(),
                   [&](const ExecPoint &point)
                   { return point.pc >= addr && point.pc < end; }) )
  {
    return true;
  }
  if ( std::any_of(events.exec_pcs.begin(), events.exec_pcs.end(),
                   [&](uint64_t pc) { return pc >= addr && pc < end; }) )
    return true;
  return std::any_of(events.edges.begin(), events.edges.end(),
                     [&](const ExecEdge &edge)
                     { return edge.to >= addr && edge.to < end; });
}

struct PatchBudget
{
  uint64_t remaining = 0;
};

// Patch only a corroborated, conflict-free value while the database still
// matches the snapshot that was emulated. This prevents an opt-in runtime patch
// from overwriting a user or a concurrently-running analysis pass.
bool patch_runtime_range(const ProgramImage &img, const EmuEvents &events,
                         uint64_t addr, const std::vector<uint8_t> &bytes,
                         DataScope scope, const ViyConfig &cfg,
                         PatchBudget &budget, RuntimeEnrichStats &stats)
{
  if ( !cfg.apply_runtime_bytes || scope != DataScope::IMAGE || bytes.empty()
    || bytes.size() > budget.remaining || !range_in_one_segment(img, addr, bytes.size()) )
  {
    return false;
  }
  if ( range_has_conflict(events, addr, bytes, scope) )
  {
    ++stats.patches_skipped_conflict;
    return false;
  }
  if ( current_bytes_equal((ea_t)addr, bytes) )
    return true;

  std::vector<uint8_t> original, current;
  if ( !snapshot_bytes(img, addr, bytes.size(), &original, false)
    || !current_bytes((ea_t)addr, bytes.size(), &current)
    || current != original )
  {
    ++stats.patches_skipped_changed_db;
    return false;
  }

  patch_bytes((ea_t)addr, bytes.data(), bytes.size());
  if ( !current_bytes_equal((ea_t)addr, bytes) )
    return false;
  budget.remaining -= bytes.size();
  ++stats.runtime_ranges_patched;
  stats.runtime_bytes_patched += bytes.size();
  return true;
}

int32 runtime_string_base(RuntimeEncoding encoding, StringLayout layout)
{
  const bool width16 = encoding == RuntimeEncoding::UTF16_LE
                    || encoding == RuntimeEncoding::UTF16_BE;
  const bool width32 = encoding == RuntimeEncoding::UTF32_LE
                    || encoding == RuntimeEncoding::UTF32_BE;
  switch ( layout )
  {
    case StringLayout::NUL_TERMINATED:
      return width32 ? STRTYPE_C_32 : width16 ? STRTYPE_C_16 : STRTYPE_C;
    case StringLayout::PASCAL8:
      return width32 ? STRTYPE_PASCAL_32
                     : width16 ? STRTYPE_PASCAL_16 : STRTYPE_PASCAL;
    case StringLayout::PASCAL16:
      return width32 ? STRTYPE_LEN2_32
                     : width16 ? STRTYPE_LEN2_16 : STRTYPE_LEN2;
    case StringLayout::PASCAL32:
      return width32 ? STRTYPE_LEN4_32
                     : width16 ? STRTYPE_LEN4_16 : STRTYPE_LEN4;
  }
  return -1;
}

int32 runtime_string_type(RuntimeEncoding encoding, StringLayout layout)
{
  const int32 base = runtime_string_base(encoding, layout);
  if ( base < 0 || encoding == RuntimeEncoding::ASCII )
    return base;
  const char *name = runtime_core::encoding_name(encoding);
  const int index = add_encoding(name);
  return index > 0 && index < STRENC_NONE ? set_str_encoding_idx(base, index) : -1;
}

void account_string_encoding(RuntimeEncoding encoding, RuntimeEnrichStats &stats)
{
  switch ( encoding )
  {
    case RuntimeEncoding::ASCII: ++stats.ascii_strings; break;
    case RuntimeEncoding::UTF8: ++stats.utf8_strings; break;
    case RuntimeEncoding::UTF16_LE:
    case RuntimeEncoding::UTF16_BE: ++stats.utf16_strings; break;
    case RuntimeEncoding::UTF32_LE:
    case RuntimeEncoding::UTF32_BE: ++stats.utf32_strings; break;
  }
}

qstring runtime_string_comment(const StringGroup &group, const char *location)
{
  qstring text;
  const std::string preview = runtime_core::escaped_preview(group.codepoints);
  text.sprnt("viy: corroborated runtime %s %s string at %s 0x%a (%u runs): \"",
             runtime_core::encoding_name(group.key.encoding),
             runtime_core::layout_name(group.key.layout), location,
             (ea_t)group.key.addr,
             (unsigned)group.runs.size());
  text.append(preview.c_str());
  text.append("\"");
  return text;
}

void apply_runtime_strings(const ProgramImage &img, const EmuEvents &events,
                           const ViyConfig &cfg, PatchBudget &budget,
                           RuntimeEnrichStats &stats)
{
  if ( !cfg.want_runtime_strings )
    return;
  runtime_core::StringScanOptions scan_options;
  scan_options.image_big_endian = img.big_endian;
  scan_options.allow_unicode = cfg.want_unicode_strings;
  scan_options.allow_length_prefixed = true;
  const runtime_core::StringCollection collection =
    runtime_core::collect_string_groups(events.final_writes, scan_options);
  stats.string_observations = collection.observations;
  stats.string_candidates = collection.groups.size();
  for ( const auto &entry : collection.groups )
  {
    const StringGroup &group = entry.second;
    if ( group.runs.size() < 2 )
      continue;
    ++stats.strings_corroborated;
    account_string_encoding(group.key.encoding, stats);

    const bool conflict = range_has_conflict(events, group.key.addr, group.key.raw,
                                             group.key.scope);
    if ( conflict )
    {
      ++stats.strings_skipped_conflict;
      continue;
    }

    if ( group.key.scope == DataScope::STACK )
    {
      if ( cfg.want_comments )
      {
        const qstring text = runtime_string_comment(group, "stack");
        comment_writers(events, group.key.addr, group.key.raw.size(), group.key.scope,
                        group.runs, text, stats, &stats.stack_string_comments);
      }
      continue;
    }
    if ( group.key.scope != DataScope::IMAGE )
    {
      if ( cfg.want_comments )
      {
        const qstring text = runtime_string_comment(group, "runtime memory");
        comment_writers(events, group.key.addr, group.key.raw.size(), group.key.scope,
                        group.runs, text, stats, &stats.runtime_only_string_comments);
      }
      continue;
    }

    const SegImage *seg = nullptr;
    if ( !range_in_one_segment(img, group.key.addr, group.key.raw.size(), &seg)
      || !segment_is_data(seg)
      || range_execution_observed(events, group.key.addr, group.key.raw.size()) )
    {
      if ( cfg.want_comments )
      {
        const qstring text = runtime_string_comment(group, "runtime image");
        comment_writers(events, group.key.addr, group.key.raw.size(), group.key.scope,
                        group.runs, text, stats, &stats.runtime_only_string_comments);
      }
      continue;
    }

    const ea_t ea = (ea_t)group.key.addr;
    if ( is_strlit(get_flags(ea)) )
      continue; // already materialized by IDA or an earlier pass
    if ( !range_is_undefined(ea, group.key.raw.size()) )
    {
      ++stats.strings_skipped_defined;
      continue;
    }

    bool bytes_ready = current_bytes_equal(ea, group.key.raw);
    if ( !bytes_ready )
      bytes_ready = patch_runtime_range(img, events, group.key.addr, group.key.raw,
                                        group.key.scope, cfg, budget, stats);
    if ( bytes_ready )
    {
      const int32 strtype = runtime_string_type(group.key.encoding,
                                                group.key.layout);
      if ( strtype >= 0 && create_strlit(ea, group.key.raw.size(), strtype) )
      {
        ++stats.strings_created;
        continue;
      }
    }

    // The string exists only in the emulated state (or could not safely become
    // an IDB item). Preserve the finding at its writer without changing bytes.
    if ( cfg.want_comments )
    {
      const qstring text = runtime_string_comment(group, "runtime image");
      comment_writers(events, group.key.addr, group.key.raw.size(), group.key.scope,
                      group.runs, text, stats, &stats.runtime_only_string_comments);
    }
  }
}

std::set<RunKey> execution_runs_for(const WriteGroup &group, const EmuEvents &events)
{
  const std::set<RunKey> ordered = runtime_core::write_then_execute_runs(
    events.data, events.execution, group.key.addr, group.key.bytes.size(),
    group.key.scope);
  std::set<RunKey> result;
  std::set_intersection(ordered.begin(), ordered.end(),
                        group.runs.begin(), group.runs.end(),
                        std::inserter(result, result.end()));
  return result;
}

void apply_smc(const ProgramImage &img, const EmuEvents &events,
               const WriteGroups &groups,
               const ViyConfig &cfg, PatchBudget &budget,
               RuntimeEnrichStats &stats)
{
  if ( !cfg.want_smc_evidence )
    return;
  for ( const auto &entry : groups )
  {
    const WriteGroup &group = entry.second;
    if ( group.runs.size() < 2 || group.key.scope != DataScope::IMAGE )
      continue;
    const SegImage *seg = nullptr;
    if ( !range_in_one_segment(img, group.key.addr, group.key.bytes.size(), &seg)
      || !segment_is_executable(seg) )
    {
      continue;
    }

    std::vector<uint8_t> original;
    if ( !snapshot_bytes(img, group.key.addr, group.key.bytes.size(), &original, true)
      || original == group.key.bytes )
    {
      continue; // a write of the original code is not self-modifying evidence
    }
    ++stats.smc_candidates;

    const std::set<RunKey> executed = execution_runs_for(group, events);
    if ( !executed.empty() )
      ++stats.write_execute_correlations;

    if ( cfg.want_comments )
    {
      qstring text;
      text.sprnt("viy: corroborated runtime code write at 0x%a (%u byte(s), %u runs)%s",
                 (ea_t)group.key.addr, (unsigned)group.key.bytes.size(),
                 (unsigned)group.runs.size(),
                 !executed.empty() ? "; write-before-execution observed" : "");
      comment_writers(events, group.key.addr, group.key.bytes.size(), group.key.scope,
                      group.runs, text, stats, &stats.smc_comments);
    }

    // Code patching requires both explicit opt-in and positive execution
    // correlation. Exact bytes are already corroborated by two runs.
    if ( !executed.empty()
      && patch_runtime_range(img, events, group.key.addr, group.key.bytes,
                             group.key.scope, cfg, budget, stats) )
    {
      plan_range((ea_t)group.key.addr,
                 (ea_t)(group.key.addr + group.key.bytes.size()));
    }
  }
}

uint64_t decode_pointer(const uint8_t *bytes, size_t size, bool be)
{
  uint64_t value = 0;
  for ( size_t i = 0; i < size; ++i )
  {
    const size_t index = be ? i : (size - 1 - i);
    value = (value << 8) | bytes[index];
  }
  return value;
}

std::vector<uint8_t> encode_pointer(uint64_t value, size_t size, bool be)
{
  std::vector<uint8_t> bytes(size, 0);
  for ( size_t i = 0; i < size; ++i )
  {
    const size_t index = be ? (size - 1 - i) : i;
    bytes[index] = (uint8_t)(value >> (8 * i));
  }
  return bytes;
}

struct PointerKey
{
  uint64_t slot = 0;
  uint64_t target = 0;

  bool operator<(const PointerKey &r) const
  {
    return std::tie(slot, target) < std::tie(r.slot, r.target);
  }
};

struct PointerEvidence
{
  PointerKey key;
  std::set<RunKey> runs;
  bool from_final_write = false;
  bool indirect_correlated = false;
};

std::map<PointerKey, PointerEvidence> collect_pointer_evidence(
        const ProgramImage &img, const EmuEvents &events, size_t ptr_size)
{
  std::map<PointerKey, PointerEvidence> result;
  for ( const DataAcc &a : events.data )
  {
    if ( a.kind != RAX_MEM_READ || a.scope != DataScope::IMAGE || a.size != ptr_size
      || !img.contains(a.addr) )
    {
      continue;
    }
    uint8_t raw[8] = { 0 };
    for ( size_t i = 0; i < ptr_size; ++i )
      raw[i] = (uint8_t)(a.value >> (8 * i));
    const uint64_t observed_target = decode_pointer(raw, ptr_size, img.big_endian);
    if ( !img.contains(observed_target) )
      continue;
    PointerKey key{ a.addr, observed_target };
    PointerEvidence &evidence = result[key];
    evidence.key = key;
    evidence.runs.insert(run_key(a));
    for ( const ExecEdge &edge : events.edges )
      if ( edge.to == observed_target
        && runtime_core::read_precedes_edge(a, edge) )
      {
        const FuncRange *load_func = img.function_at(a.from);
        const FuncRange *edge_func = img.function_at(edge.from);
        if ( edge.from == a.from
          || (load_func != nullptr && edge_func != nullptr
            && load_func->start == edge_func->start) )
        {
          // The memory read is ordered before this same-run edge by the shared
          // hook sequence; normalization preserves repeated ordered events.
          evidence.indirect_correlated = true;
          break;
        }
      }
  }

  for ( const MemoryBytes &b : events.final_writes )
  {
    if ( b.scope != DataScope::IMAGE || b.bytes.size() < ptr_size )
      continue;
    const size_t first = (ptr_size - size_t(b.addr % ptr_size)) % ptr_size;
    for ( size_t off = first; off + ptr_size <= b.bytes.size(); off += ptr_size )
    {
      const uint64_t slot = b.addr + off;
      const uint64_t target = decode_pointer(b.bytes.data() + off, ptr_size, img.big_endian);
      if ( !img.contains(slot) || !img.contains(target) )
        continue;
      PointerKey key{ slot, target };
      PointerEvidence &evidence = result[key];
      evidence.key = key;
      evidence.runs.insert(run_key(b));
      evidence.from_final_write = true;
    }
  }
  return result;
}

struct StablePointer
{
  PointerEvidence evidence;
};

std::vector<StablePointer> stable_pointers(const ProgramImage &img,
                                           const EmuEvents &events,
                                           size_t ptr_size,
                                           const std::map<PointerKey, PointerEvidence> &all,
                                           RuntimeEnrichStats &stats)
{
  std::map<uint64_t, size_t> target_count;
  for ( const auto &entry : all )
    ++target_count[entry.first.slot];

  std::vector<StablePointer> stable;
  stats.pointer_slot_candidates = target_count.size();
  for ( const auto &entry : all )
  {
    const PointerEvidence &evidence = entry.second;
    const std::vector<uint8_t> expected = encode_pointer(evidence.key.target, ptr_size,
                                                         img.big_endian);
    if ( target_count[evidence.key.slot] == 1 && evidence.runs.size() >= 2
      && !range_has_conflict(events, evidence.key.slot, expected, DataScope::IMAGE) )
    {
      stable.push_back(StablePointer{ evidence });
      ++stats.pointer_slots_corroborated;
    }
  }
  std::sort(stable.begin(), stable.end(), [](const StablePointer &a, const StablePointer &b)
  {
    return a.evidence.key.slot < b.evidence.key.slot;
  });
  return stable;
}

void apply_pointer_cluster(const ProgramImage &img, const EmuEvents &events,
                           const std::vector<StablePointer> &cluster,
                           size_t ptr_size, const ViyConfig &cfg,
                           PatchBudget &budget, RuntimeEnrichStats &stats)
{
  if ( cluster.size() < 2 )
    return;
  const uint64_t base = cluster.front().evidence.key.slot;
  const SegImage *seg = nullptr;
  if ( !range_in_one_segment(img, base, cluster.size() * ptr_size, &seg)
    || !segment_is_data(seg)
    || range_execution_observed(events, base, cluster.size() * ptr_size) )
  {
    return;
  }
  const bool has_code_target = std::any_of(cluster.begin(), cluster.end(), [&](const StablePointer &p)
  {
    return img.executable(p.evidence.key.target, true);
  });
  const bool correlated = std::any_of(cluster.begin(), cluster.end(), [](const StablePointer &p)
  {
    return p.evidence.indirect_correlated;
  });
  if ( !has_code_target && !correlated )
    return;

  ++stats.pointer_clusters;
  if ( correlated )
    ++stats.pointer_clusters_correlated;
  if ( cfg.want_comments )
  {
    qstring text;
    text.sprnt("viy: corroborated runtime pointer table (%u contiguous slot(s))%s",
               (unsigned)cluster.size(), correlated ? "; indirect use observed" : "");
    account_comment(add_repeatable_comment((ea_t)base, text.c_str()), stats);
  }

  for ( const StablePointer &pointer : cluster )
  {
    const uint64_t slot = pointer.evidence.key.slot;
    const uint64_t target = pointer.evidence.key.target;
    const std::vector<uint8_t> bytes = encode_pointer(target, ptr_size, img.big_endian);
    bool ready = current_bytes_equal((ea_t)slot, bytes);
    if ( !ready && pointer.evidence.from_final_write && range_is_undefined((ea_t)slot, ptr_size) )
      ready = patch_runtime_range(img, events, slot, bytes, DataScope::IMAGE,
                                  cfg, budget, stats);
    if ( !ready || !range_is_undefined((ea_t)slot, ptr_size) )
      continue;
    const bool created = ptr_size == 8 ? create_qword((ea_t)slot, 8)
                       : ptr_size == 4 ? create_dword((ea_t)slot, 4)
                                       : create_word((ea_t)slot, 2);
    if ( created && op_plain_offset((ea_t)slot, 0, 0) )
      ++stats.pointer_offsets_created;
  }
}

void apply_pointer_tables(const ProgramImage &img, const EmuEvents &events,
                          const ViyConfig &cfg, PatchBudget &budget,
                          RuntimeEnrichStats &stats)
{
  if ( !cfg.want_tables )
    return;
  const size_t ptr_size = img.arch == ViyArch::X86_64 || img.arch == ViyArch::ARM64
                       || img.arch == ViyArch::RISCV64 ? 8
                       : img.arch == ViyArch::X86_16 ? 2 : 4;
  const auto all = collect_pointer_evidence(img, events, ptr_size);
  const auto stable = stable_pointers(img, events, ptr_size, all, stats);
  size_t begin = 0;
  while ( begin < stable.size() )
  {
    size_t end = begin + 1;
    while ( end < stable.size()
      && stable[end].evidence.key.slot
          == stable[end - 1].evidence.key.slot + ptr_size )
    {
      ++end;
    }
    if ( end - begin >= 2 )
    {
      std::vector<StablePointer> cluster(stable.begin() + (ptrdiff_t)begin,
                                         stable.begin() + (ptrdiff_t)end);
      apply_pointer_cluster(img, events, cluster, ptr_size, cfg, budget, stats);
    }
    begin = end;
  }
}

struct EdgeKey
{
  uint64_t from = 0;
  uint64_t to = 0;

  bool operator<(const EdgeKey &r) const
  {
    return std::tie(from, to) < std::tie(r.from, r.to);
  }
};

std::map<EdgeKey, std::set<RunKey>> corroborated_edges(const EmuEvents &events)
{
  std::map<EdgeKey, std::set<RunKey>> result;
  for ( const ExecEdge &edge : events.edges )
    result[EdgeKey{ edge.from, edge.to }].insert(run_key(edge));
  return result;
}

bool decode_source(ea_t ea, insn_t *insn, uint32 *features)
{
  const flags64_t f = get_flags(ea);
  if ( !is_head(f) || !is_code(f) || decode_insn(insn, ea) <= 0 )
    return false;
  *features = insn->get_canon_feature(PH);
  return true;
}

bool target_is_guarded_code(const ProgramImage &img, ea_t target)
{
  const SegImage *seg = img.segment_at((uint64_t)target);
  if ( !segment_is_executable(seg) || is_tail(get_flags(target)) )
    return false;
  const flags64_t f = get_flags(target);
  return is_unknown(f) || (is_head(f) && is_code(f));
}

void apply_orphan_functions(const ProgramImage &img, const EmuEvents &events,
                            const std::map<EdgeKey, std::set<RunKey>> &edges,
                            const ViyConfig &cfg, RuntimeEnrichStats &stats)
{
  if ( !cfg.want_function_recovery )
    return;
  for ( const auto &entry : edges )
  {
    const EdgeKey &edge = entry.first;
    const std::set<RunKey> &runs = entry.second;
    if ( runs.size() < 2 )
      continue;
    insn_t insn;
    uint32 features = 0;
    if ( !decode_source((ea_t)edge.from, &insn, &features) || !is_call_insn(insn)
      || !target_is_guarded_code(img, (ea_t)edge.to) || get_func((ea_t)edge.to) != nullptr )
    {
      continue;
    }
    ++stats.orphan_call_candidates;

    flags64_t target_flags = get_flags((ea_t)edge.to);
    if ( is_unknown(target_flags) && create_insn((ea_t)edge.to) <= 0 )
      continue;
    target_flags = get_flags((ea_t)edge.to);
    if ( !is_head(target_flags) || !is_code(target_flags)
      || get_func((ea_t)edge.to) != nullptr )
    {
      continue;
    }
    if ( add_func((ea_t)edge.to, BADADDR) )
    {
      ++stats.functions_promoted;
      plan_ea((ea_t)edge.to);
      if ( cfg.want_comments )
      {
        qstring text;
        text.sprnt("viy: corroborated orphan call target 0x%a promoted to function (%u runs)",
                   (ea_t)edge.to, (unsigned)runs.size());
        account_comment(add_repeatable_comment((ea_t)edge.from, text.c_str()), stats);
      }
    }
  }
}

void apply_tail_candidates(const ProgramImage &img,
                           const std::map<EdgeKey, std::set<RunKey>> &edges,
                           const ViyConfig &cfg, RuntimeEnrichStats &stats)
{
  for ( const auto &entry : edges )
  {
    const EdgeKey &edge = entry.first;
    const std::set<RunKey> &runs = entry.second;
    if ( runs.size() < 2 )
      continue;
    const FuncRange *model_owner = img.function_at(edge.from);
    if ( model_owner == nullptr || model_owner->contains(edge.to) )
      continue;

    insn_t insn;
    uint32 features = 0;
    if ( !decode_source((ea_t)edge.from, &insn, &features) || is_call_insn(insn)
      || (features & CF_STOP) == 0 || !target_is_guarded_code(img, (ea_t)edge.to) )
    {
      continue;
    }

    func_t *target_chunk = get_fchunk((ea_t)edge.to);
    // A jump to another function entry is a tail call, not a missing tail.
    if ( target_chunk != nullptr && !is_func_tail(target_chunk)
      && target_chunk->start_ea == (ea_t)edge.to )
    {
      continue;
    }
    ++stats.tail_candidates;

    if ( cfg.want_comments )
    {
      qstring text;
      text.sprnt("viy: corroborated function-tail candidate -> 0x%a (%u runs)",
                 (ea_t)edge.to, (unsigned)runs.size());
      account_comment(add_repeatable_comment((ea_t)edge.from, text.c_str()), stats);
    }

    if ( !cfg.want_tail_recovery )
      continue;
    // Strict mutation policy: share only an already-defined tail whose exact
    // boundaries are known. Never guess an orphan tail's end in this pass.
    func_t *owner = get_func((ea_t)edge.from);
    if ( owner == nullptr || owner->start_ea != (ea_t)model_owner->start
      || func_contains(owner, (ea_t)edge.to)
      || target_chunk == nullptr || !is_func_tail(target_chunk)
      || target_chunk->start_ea != (ea_t)edge.to
      || target_chunk->end_ea <= target_chunk->start_ea
      || !img.executable((uint64_t)target_chunk->end_ea - 1, true) )
    {
      continue;
    }
    if ( append_func_tail(owner, target_chunk->start_ea, target_chunk->end_ea) )
      ++stats.tails_appended;
  }
}

} // namespace

RuntimeEnrichStats viy_runtime_enrich(const ProgramImage &img,
                                      const EmuEvents &events,
                                      const ViyConfig &cfg)
{
  RuntimeEnrichStats stats;
  PatchBudget budget{ cfg.apply_runtime_bytes ? cfg.max_runtime_bytes : 0 };
  const runtime_core::WriteCollection write_collection =
    runtime_core::collect_write_groups(events.final_writes);
  stats.final_write_observations = write_collection.observations;
  stats.corroborated_write_groups = write_collection.corroborated_groups;
  stats.uncorroborated_write_groups = write_collection.uncorroborated_groups;
  const WriteGroups &writes = write_collection.groups;

  // Count ambiguous final ranges once for summary purposes. Individual mutation
  // helpers still recheck the exact subrange they intend to touch.
  for ( const auto &entry : writes )
    if ( entry.second.runs.size() >= 2
      && range_has_conflict(events, entry.first.addr, entry.first.bytes, entry.first.scope) )
      ++stats.conflicting_write_ranges;

  apply_runtime_strings(img, events, cfg, budget, stats);
  apply_smc(img, events, writes, cfg, budget, stats);
  apply_pointer_tables(img, events, cfg, budget, stats);

  const auto edges = corroborated_edges(events);
  apply_orphan_functions(img, events, edges, cfg, stats);
  apply_tail_candidates(img, edges, cfg, stats);
  return stats;
}

} // namespace viy
