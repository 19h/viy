#include "program_model.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <utility>
#include <vector>

using namespace viy;

namespace {

int failures = 0;

void expect(bool condition, const char *message)
{
  if ( !condition )
  {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

SegImage segment(uint64_t start, std::vector<uint8_t> bytes,
                 std::vector<uint8_t> mask, uint32_t perm = 7,
                 uint8_t bitness = 2)
{
  SegImage result;
  result.start = start;
  result.end = start + static_cast<uint64_t>(bytes.size());
  result.perm = perm;
  result.bitness = bitness;
  result.bytes = std::move(bytes);
  result.mask = std::move(mask);
  return result;
}

ProgramImage hash_image()
{
  ProgramImage img;
  img.arch = ViyArch::X86_64;
  img.lo = 0x1000;
  img.hi = 0x2010;
  img.segs.push_back(segment(
      0x1000,
      {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
       0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00},
      {0xFF, 0xFF}, 5, 2));
  // Repeated bytes ensure moving a tail by one byte changes topology while
  // keeping the bytes covered by that tail identical.
  img.segs.push_back(segment(
      0x2000,
      {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
       0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC},
      {0xFF, 0xFF}, 7, 2));
  return img;
}

FuncRange hash_function()
{
  FuncRange func;
  func.start = 0x1002;
  func.end = 0x1006;
  func.chunks = {{0x1002, 0x1006}, {0x2002, 0x2006}};
  return func;
}

void rebase(ProgramImage &img, FuncRange *func, uint64_t delta)
{
  img.lo += delta;
  img.hi += delta;
  for ( SegImage &seg : img.segs )
  {
    seg.start += delta;
    seg.end += delta;
  }
  for ( FuncRange &entry : img.entries )
  {
    entry.start += delta;
    entry.end += delta;
    for ( FuncChunk &chunk : entry.chunks )
    {
      chunk.start += delta;
      chunk.end += delta;
    }
  }
  if ( func != nullptr )
  {
    func->start += delta;
    func->end += delta;
    for ( FuncChunk &chunk : func->chunks )
    {
      chunk.start += delta;
      chunk.end += delta;
    }
  }
}

void test_segments()
{
  ProgramImage img;
  img.segs.push_back(segment(0x1000, {0xAA, 0xBB, 0xCC, 0xDD}, {0x05}, 5));
  img.segs.push_back(segment(0x2000, {0x11, 0x22}, {}, 0));
  img.segs.push_back(segment(
      0x3000, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, {0x00, 0x02}, 4));

  expect(img.segs[0].contains(0x1000), "segment includes its start");
  expect(img.segs[0].contains(0x1003), "segment includes its final byte");
  expect(!img.segs[0].contains(0x0FFF), "segment excludes addresses below it");
  expect(!img.segs[0].contains(0x1004), "segment excludes its half-open end");
  expect(img.segment_at(0x1000) == &img.segs[0], "segment lookup finds first start");
  expect(img.segment_at(0x1003) == &img.segs[0], "segment lookup finds first end byte");
  expect(img.segment_at(0x1800) == nullptr, "segment lookup rejects mapped gap");
  expect(img.segment_at(0x2001) == &img.segs[1], "segment lookup finds later segment");
  expect(img.segment_at(0x2002) == nullptr, "segment lookup rejects final end");

  expect(img.byte_loaded(0x1000), "loaded bitmap recognizes bit zero");
  expect(!img.byte_loaded(0x1001), "loaded bitmap recognizes clear bit");
  expect(img.byte_loaded(0x1002), "loaded bitmap recognizes later set bit");
  expect(!img.byte_loaded(0x1003), "loaded bitmap recognizes later clear bit");
  expect(!img.byte_loaded(0x2000), "missing mask storage means unloaded");
  expect(img.byte_loaded(0x3009), "loaded bitmap indexes bits beyond its first byte");
  expect(!img.byte_loaded(0x1800), "unmapped byte is not loaded");

  expect(img.readable(0x1000), "read permission is recognized");
  expect(img.executable(0x1000), "execute permission is recognized");
  expect(!img.writable(0x1000), "missing write permission is rejected");
  const ViySegPerm read_exec = static_cast<ViySegPerm>(
      static_cast<uint32_t>(ViySegPerm::READ)
    | static_cast<uint32_t>(ViySegPerm::EXEC));
  expect(img.has_perm(0x1000, read_exec), "combined permissions require every bit");
  expect(!img.readable(0x2000), "unknown permissions fail closed by default");
  expect(img.readable(0x2000, true), "unknown mapped permissions may be allowed explicitly");
  expect(!img.readable(0x1800, true), "allow-unknown never turns an unmapped gap into a segment");
}

void test_functions_and_tails()
{
  FuncRange old_style;
  old_style.start = 0x500;
  old_style.end = 0x510;
  expect(old_style.contains(0x500), "old-style function includes its start");
  expect(old_style.contains(0x50F), "old-style function includes its end byte");
  expect(!old_style.contains(0x510), "old-style function excludes its end");
  expect(old_style.byte_size() == 0x10, "old-style function size uses primary range");

  FuncRange first;
  first.start = 0x100;
  first.end = 0x110;
  first.chunks = {
      {0x100, 0x110}, {0x180, 0x190}, {0x200, 0x205}, {0x300, 0x310}};
  FuncRange second;
  second.start = 0x200;
  second.end = 0x210;
  second.chunks = {{0x200, 0x210}, {0x300, 0x310}};

  expect(first.contains(0x185), "function contains a non-contiguous private tail");
  expect(!first.contains(0x150), "function excludes gaps between chunks");
  expect(first.contains(0x305) && second.contains(0x305),
         "shared tail belongs to every owning function range");
  expect(first.byte_size() == 0x35, "function byte size sums every chunk");

  ProgramImage img;
  img.entries = {first, second};
  expect(img.function_at(0x100) == &img.entries[0], "function lookup finds first entry");
  expect(img.function_at(0x185) == &img.entries[0], "function lookup finds non-contiguous tail");
  expect(img.function_at(0x200) == &img.entries[1],
         "exact entry wins even when an earlier function includes that address");
  expect(img.function_at(0x305) == &img.entries[1],
         "shared-tail lookup deterministically prefers the nearest prior entry");
  expect(img.function_at(0x150) == nullptr, "function lookup rejects inter-chunk gap");

  FuncRange saturating;
  const uint64_t maximum = std::numeric_limits<uint64_t>::max();
  saturating.chunks = {{0, maximum - 4}, {0, 10}};
  expect(saturating.byte_size() == maximum, "function byte size saturates instead of overflowing");
  FuncRange invalid;
  invalid.chunks = {{9, 2}, {4, 4}};
  expect(invalid.byte_size() == 0, "empty or reversed chunks contribute no bytes");
}

void test_function_hash()
{
  const ProgramImage base_img = hash_image();
  const FuncRange base_func = hash_function();
  const uint64_t base = viy_function_byte_hash(base_img, base_func);

  ProgramImage rebased_img = base_img;
  FuncRange rebased_func = base_func;
  rebase(rebased_img, &rebased_func, 0x700000);
  expect(viy_function_byte_hash(rebased_img, rebased_func) == base,
         "function hash is invariant under a uniform rebase");

  ProgramImage changed_byte = base_img;
  changed_byte.segs[0].bytes[3] ^= 0x5A;
  expect(viy_function_byte_hash(changed_byte, base_func) != base,
         "function hash changes when a loaded function byte changes");

  FuncRange changed_topology = base_func;
  ++changed_topology.chunks[1].start;
  ++changed_topology.chunks[1].end;
  expect(viy_function_byte_hash(base_img, changed_topology) != base,
         "function hash changes with relative chunk topology even for identical bytes");

  ProgramImage changed_loaded_state = base_img;
  changed_loaded_state.segs[0].mask[0] &= static_cast<uint8_t>(~uint8_t{1u << 3});
  const uint64_t unloaded = viy_function_byte_hash(changed_loaded_state, base_func);
  expect(unloaded != base, "function hash distinguishes unloaded state from loaded bytes");
  changed_loaded_state.segs[0].bytes[3] ^= 0xFF;
  expect(viy_function_byte_hash(changed_loaded_state, base_func) == unloaded,
         "function hash ignores backing-vector values for unloaded bytes");

  FuncRange old_style;
  old_style.start = 0x1002;
  old_style.end = 0x1006;
  FuncRange explicit_chunk = old_style;
  explicit_chunk.chunks.push_back({old_style.start, old_style.end});
  expect(viy_function_byte_hash(base_img, old_style)
      == viy_function_byte_hash(base_img, explicit_chunk),
      "old-style primary ranges hash like one explicit entry chunk");
}

void test_program_content_hash()
{
  const ProgramImage base_img = hash_image();
  const uint64_t base = viy_program_content_hash(base_img);

  ProgramImage rebased = base_img;
  rebase(rebased, nullptr, 0x900000);
  expect(viy_program_content_hash(rebased) == base,
         "program content hash is invariant under a uniform rebase");

  ProgramImage changed = base_img;
  changed.segs[0].bytes[4] ^= 0xA5;
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with segment bytes");

  changed = base_img;
  changed.segs[0].mask[0] &= static_cast<uint8_t>(~uint8_t{1u << 4});
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with initialized-byte state");

  changed = base_img;
  ++changed.segs[1].start;
  ++changed.segs[1].end;
  ++changed.hi;
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with relative segment topology");

  changed = base_img;
  changed.segs[0].perm ^= static_cast<uint32_t>(ViySegPerm::WRITE);
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with permissions");

  changed = base_img;
  changed.segs[0].bitness = 1;
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with segment bitness");

  changed = base_img;
  changed.arch = ViyArch::ARM64;
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with architecture");

  changed = base_img;
  changed.big_endian = true;
  expect(viy_program_content_hash(changed) != base,
         "program content hash changes with target byte order");

  changed = base_img;
  changed.generation = 999;
  changed.entries.push_back(hash_function());
  expect(viy_program_content_hash(changed) == base,
         "program content hash excludes snapshot generation and function metadata");
}

} // namespace

int main()
{
  test_segments();
  test_functions_and_tails();
  test_function_hash();
  test_program_content_hash();
  if ( failures != 0 )
  {
    std::cerr << failures << " program-model test(s) failed\n";
    return 1;
  }
  std::cout << "program-model tests passed\n";
  return 0;
}
