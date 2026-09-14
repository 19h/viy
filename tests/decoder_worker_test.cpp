#include "emulation_rax_executor.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

using namespace viy;
using namespace std::chrono_literals;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); std::abort(); } } while (false)

namespace {
std::thread::id main_thread;
std::atomic<size_t> analyze_calls{0}, decode_calls{0};
std::atomic<bool> entered{false}, release_call{true};
decltype(&rax_analyze) real_analyze;
decltype(&rax_decode) real_decode;

rax_status analyze(int arch, uint32_t mode, uint64_t pc, const void *bytes,
                   size_t length, rax_analysis *summary, rax_analysis_effect *effects,
                   size_t capacity, size_t *required)
{
  CHECK(std::this_thread::get_id() != main_thread);
  ++analyze_calls;
  entered = true;
  while (!release_call.load()) std::this_thread::yield();
  return real_analyze(arch, mode, pc, bytes, length, summary, effects, capacity, required);
}

rax_status decode(int arch, uint32_t mode, uint64_t pc, const void *bytes,
                  size_t length, rax_decoded *out)
{
  CHECK(std::this_thread::get_id() != main_thread);
  ++decode_calls;
  return real_decode(arch, mode, pc, bytes, length, out);
}

std::shared_ptr<ProgramImage> fixture()
{
  auto image = std::make_shared<ProgramImage>();
  image->arch = ViyArch::X86_64;
  image->lo = 0x100000;
  image->hi = image->lo + 4096;
  SegImage segment;
  segment.start = image->lo;
  segment.end = image->hi;
  segment.perm = 7;
  segment.bitness = 2;
  segment.bytes.assign(4096, 0x90);
  segment.bytes[0] = 0xb8; // mov eax, 1; ret
  segment.bytes[1] = 1;
  segment.bytes[2] = segment.bytes[3] = segment.bytes[4] = 0;
  segment.bytes[5] = 0xc3;
  segment.mask.assign(512, 255);
  image->segs.push_back(std::move(segment));
  FuncRange function;
  function.start = image->lo;
  function.end = image->lo + 6;
  function.generation = 3;
  function.byte_hash = 7;
  image->entries.push_back(function);
  return image;
}

EmulationJob request(const ProgramImage &image)
{
  EmulationJob job;
  job.function = image.entries.front();
  DecoderAuditInput input;
  input.address = job.function.start;
  input.maximum_bytes = 5;
  input.mode = RAX_MODE_64;
  input.mode_known = true;
  input.ida.valid = true;
  input.ida.size = 5;
  input.ida.flow = RAX_FLOW_FALLTHROUGH;
  job.decoder_inputs.push_back(input);
  return job; // Also models a dynamic-cache hit: audit with no emulation runs.
}

void run(bool fallback)
{
  auto image = fixture();
  RaxApi api = *rax_load();
  real_analyze = api.analyze;
  real_decode = api.decode;
  api.analyze = fallback ? nullptr : analyze;
  api.decode = decode;
  RaxWorkerOptions options;
  options.api = &api;
  options.image = image;
  EmulationWorkerPool pool(1, viy_make_rax_worker_factory(options), 2);
  CHECK(pool.wait_for_initialization(10s));
  CHECK(pool.usable());
  auto job = request(*image);
  CHECK(pool.try_submit(job));
  EmulationJobResult result;
  CHECK(pool.wait_take_next(result, 10s));
  CHECK(result.completed() && result.runs.empty());
  CHECK(result.decoder_audit.size() == 1);
  const auto &audit = result.decoder_audit.front();
  CHECK(audit.decoded.status == DecoderDecodeStatus::Valid);
  CHECK(audit.decoded.instruction.flow == RAX_FLOW_FALLTHROUGH);
  CHECK(audit.analyzed == !fallback);
  CHECK(audit.input.maximum_bytes == 5);
  if (!fallback)
  {
    // Compare worker effects to the same stateless operation called directly.
    SmirInstructionAnalysis expected;
    CHECK(viy_analyze_instruction_effects(rax_load(), *image, image->lo,
                                        RAX_MODE_64, expected, 5));
    analysis::EvidenceStore a, b;
    viy_record_smir_analysis(audit.effects, job.function, a);
    viy_record_smir_analysis(expected, job.function, b);
    CHECK(!a.empty());
    CHECK(a.flattened_facts().size() == b.flattened_facts().size());
    std::vector<uint8_t> encoded_a, encoded_b;
    CHECK(a.serialize(encoded_a) && b.serialize(encoded_b));
    CHECK(encoded_a == encoded_b);

    // Cancellation is checked between instructions. No second analyze starts.
    release_call = false;
    entered = false;
    const size_t before = analyze_calls.load();
    job.decoder_inputs.push_back(job.decoder_inputs.front());
    CHECK(pool.try_submit(job));
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (!entered.load() && std::chrono::steady_clock::now() < deadline)
      std::this_thread::yield();
    CHECK(entered.load());
    pool.cancel_pending();
    release_call = true;
    CHECK(pool.wait_take_next(result, 10s));
    CHECK(result.status == EmulationJobStatus::CANCELLED);
    CHECK(result.decoder_audit.empty());
    CHECK(analyze_calls.load() == before + 1);
  }
  job.function.generation++;
  CHECK(pool.try_submit(job));
  CHECK(pool.wait_take_next(result, 10s));
  CHECK(result.status == EmulationJobStatus::FAILED && result.decoder_audit.empty());
}
} // namespace

int main()
{
  main_thread = std::this_thread::get_id();
  CHECK(rax_load() != nullptr);
  run(false);
  CHECK(analyze_calls.load() >= 2 && decode_calls.load() == 0);
  run(true);
  CHECK(decode_calls.load() == 1);
  std::puts("decoder worker regressions passed");
}
