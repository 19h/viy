#include "emulation_workers.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using namespace viy;

#define CHECK(expression)                                                        \
  do                                                                             \
  {                                                                              \
    if ( !(expression) )                                                         \
    {                                                                            \
      std::fprintf(stderr, "CHECK failed at %s:%d: %s\n",                       \
                   __FILE__, __LINE__, #expression);                             \
      std::abort();                                                              \
    }                                                                            \
  } while ( false )

namespace {

struct Gate
{
  std::mutex mutex;
  std::condition_variable cv;
  bool entered = false;
  bool release = false;
};

struct OrderGate
{
  std::mutex mutex;
  std::condition_variable cv;
  size_t later_completed = 0;
  bool release_first = false;
};

class FakeExecutor final : public EmulationExecutor
{
public:
  explicit FakeExecutor(std::shared_ptr<Gate> gate = {}) : gate_(std::move(gate)) {}

  bool available() const noexcept override { return true; }
  std::string unavailable_reason() const override { return {}; }

  EmulationJobResult execute(const EmulationJob &job,
                             const EmulationCancellation &cancel) override
  {
    EmulationJobResult result;
    result.function_start = job.function.start;
    if ( gate_ != nullptr && job.function.start == 0x1000 )
    {
      std::unique_lock<std::mutex> lock(gate_->mutex);
      gate_->entered = true;
      gate_->cv.notify_all();
      gate_->cv.wait(lock, [&] { return gate_->release || cancel.cancelled(); });
    }
    else
    {
      // Model a small, bounded unit of worker work.
      const auto delay = job.function.start == 1 ? 25ms : 1ms;
      std::this_thread::sleep_for(delay);
    }
    result.status = cancel.cancelled() ? EmulationJobStatus::CANCELLED
                                       : EmulationJobStatus::COMPLETED;
    return result;
  }

private:
  std::shared_ptr<Gate> gate_;
};

class OrderedExecutor final : public EmulationExecutor
{
public:
  explicit OrderedExecutor(std::shared_ptr<OrderGate> gate)
    : gate_(std::move(gate))
  {
  }

  bool available() const noexcept override { return true; }
  std::string unavailable_reason() const override { return {}; }
  EmulationJobResult execute(const EmulationJob &job,
                             const EmulationCancellation &cancel) override
  {
    std::unique_lock<std::mutex> lock(gate_->mutex);
    if ( job.function.start == 1 )
      gate_->cv.wait(lock, [&] { return gate_->release_first || cancel.cancelled(); });
    else
    {
      ++gate_->later_completed;
      gate_->cv.notify_all();
    }
    EmulationJobResult result;
    result.function_start = job.function.start;
    result.status = cancel.cancelled() ? EmulationJobStatus::CANCELLED
                                       : EmulationJobStatus::COMPLETED;
    return result;
  }

private:
  std::shared_ptr<OrderGate> gate_;
};

class UnavailableExecutor final : public EmulationExecutor
{
public:
  bool available() const noexcept override { return false; }
  std::string unavailable_reason() const override { return "intentional"; }
  EmulationJobResult execute(const EmulationJob &,
                             const EmulationCancellation &) override
  {
    CHECK(false);
    return {};
  }
};

class CooperativeExecutor final : public EmulationExecutor
{
public:
  explicit CooperativeExecutor(std::shared_ptr<std::atomic<bool>> entered)
    : entered_(std::move(entered))
  {
  }

  bool available() const noexcept override { return true; }
  std::string unavailable_reason() const override { return {}; }
  EmulationJobResult execute(const EmulationJob &job,
                             const EmulationCancellation &cancel) override
  {
    entered_->store(true, std::memory_order_release);
    while ( !cancel.cancelled() )
      std::this_thread::yield();
    EmulationJobResult result;
    result.function_start = job.function.start;
    result.status = EmulationJobStatus::CANCELLED;
    return result;
  }

private:
  std::shared_ptr<std::atomic<bool>> entered_;
};

EmulationJob job(uint64_t start)
{
  EmulationJob j;
  j.function.start = start;
  j.function.end = start + 1;
  return j;
}

void test_ordered_delivery()
{
  auto gate = std::make_shared<OrderGate>();
  EmulationWorkerPool pool(3, [gate](size_t)
  {
    return std::unique_ptr<EmulationExecutor>(new OrderedExecutor(gate));
  });
  CHECK(pool.wait_for_initialization(2s));
  CHECK(pool.usable());

  uint64_t t1 = 0, t2 = 0, t3 = 0;
  CHECK(pool.try_submit(job(1), &t1));
  CHECK(pool.try_submit(job(2), &t2));
  CHECK(pool.try_submit(job(3), &t3));
  CHECK(t1 + 1 == t2 && t2 + 1 == t3);

  EmulationJobResult result;
  {
    std::unique_lock<std::mutex> lock(gate->mutex);
    CHECK(gate->cv.wait_for(lock, 2s, [&] { return gate->later_completed == 2; }));
  }
  // Tickets 2 and 3 are physically complete, but ticket 1 deliberately is not.
  CHECK(!pool.try_take_next(result));
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->release_first = true;
    gate->cv.notify_all();
  }
  CHECK(pool.wait_take_next(result, 2s));
  CHECK(result.ticket == t1 && result.function_start == 1);
  CHECK(pool.wait_take_next(result, 2s));
  CHECK(result.ticket == t2 && result.function_start == 2);
  CHECK(pool.wait_take_next(result, 2s));
  CHECK(result.ticket == t3 && result.function_start == 3);
  CHECK(pool.idle());
  const EmulationWorkerStats stats = pool.stats();
  CHECK(stats.submitted == 3 && stats.settled == 3 && stats.delivered == 3);
}

void test_generation_cancellation()
{
  auto gate = std::make_shared<Gate>();
  EmulationWorkerPool pool(1, [gate](size_t)
  {
    return std::unique_ptr<EmulationExecutor>(new FakeExecutor(gate));
  });
  CHECK(pool.wait_for_initialization(2s));
  uint64_t running = 0, queued = 0;
  CHECK(pool.try_submit(job(0x1000), &running));
  CHECK(pool.try_submit(job(0x2000), &queued));
  {
    std::unique_lock<std::mutex> lock(gate->mutex);
    CHECK(gate->cv.wait_for(lock, 2s, [&] { return gate->entered; }));
  }
  pool.cancel_pending();
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->release = true;
    gate->cv.notify_all();
  }

  EmulationJobResult first, second;
  CHECK(pool.wait_take_next(first, 2s));
  CHECK(pool.wait_take_next(second, 2s));
  CHECK(first.ticket == running && first.status == EmulationJobStatus::CANCELLED);
  CHECK(second.ticket == queued && second.status == EmulationJobStatus::CANCELLED);

  // Cancellation advances a generation; it does not permanently disable the pool.
  uint64_t fresh = 0;
  CHECK(pool.try_submit(job(0x3000), &fresh));
  EmulationJobResult third;
  CHECK(pool.wait_take_next(third, 2s));
  CHECK(third.ticket == fresh && third.status == EmulationJobStatus::COMPLETED);
}

void test_unavailable_and_backpressure()
{
  EmulationWorkerPool unavailable(2, [](size_t)
  {
    return std::unique_ptr<EmulationExecutor>(new UnavailableExecutor);
  });
  CHECK(unavailable.wait_for_initialization(2s));
  CHECK(!unavailable.usable());
  CHECK(unavailable.initialization_diagnostic() == "intentional");
  uint64_t ticket = 0;
  CHECK(unavailable.try_submit(job(9), &ticket));
  EmulationJobResult result;
  CHECK(unavailable.try_take_next(result));
  CHECK(result.ticket == ticket && result.status == EmulationJobStatus::UNAVAILABLE);

  auto gate = std::make_shared<Gate>();
  EmulationWorkerPool bounded(1, [gate](size_t)
  {
    return std::unique_ptr<EmulationExecutor>(new FakeExecutor(gate));
  }, 1);
  CHECK(bounded.wait_for_initialization(2s));
  CHECK(bounded.try_submit(job(0x1000)));
  {
    std::unique_lock<std::mutex> lock(gate->mutex);
    CHECK(gate->cv.wait_for(lock, 2s, [&] { return gate->entered; }));
  }
  CHECK(bounded.try_submit(job(0x2000)));
  CHECK(!bounded.try_submit(job(0x3000)));
  bounded.cancel_pending();
  {
    std::lock_guard<std::mutex> lock(gate->mutex);
    gate->release = true;
    gate->cv.notify_all();
  }
}

void test_cooperative_shutdown()
{
  auto entered = std::make_shared<std::atomic<bool>>(false);
  EmulationWorkerPool pool(1, [entered](size_t)
  {
    return std::unique_ptr<EmulationExecutor>(new CooperativeExecutor(entered));
  });
  CHECK(pool.wait_for_initialization(2s));
  uint64_t running = 0, queued = 0;
  CHECK(pool.try_submit(job(0x4000), &running));
  CHECK(pool.try_submit(job(0x5000), &queued));
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while ( !entered->load(std::memory_order_acquire)
       && std::chrono::steady_clock::now() < deadline )
    std::this_thread::yield();
  CHECK(entered->load(std::memory_order_acquire));

  pool.shutdown();
  CHECK(!pool.try_submit(job(0x6000)));
  EmulationJobResult first, second;
  CHECK(pool.try_take_next(first));
  CHECK(pool.try_take_next(second));
  CHECK(first.ticket == running && first.status == EmulationJobStatus::CANCELLED);
  CHECK(second.ticket == queued && second.status == EmulationJobStatus::CANCELLED);
  CHECK(pool.stats().stopping);
}

} // namespace

int main()
{
  CHECK(viy_resolve_worker_count(1) == 1);
  CHECK(viy_resolve_worker_count(99, 7) == 7);
  CHECK(viy_resolve_worker_count(0, 0) == 0);
  CHECK(viy_resolve_worker_count(0, 64) >= 1);
  CHECK(viy_resolve_worker_count(0, 64) <= 4);
  EmulationJob fingerprint_job = job(0x4000);
  fingerprint_job.function.byte_hash = 0x1234;
  fingerprint_job.function.chunks = {{0x4000, 0x4010}};
  EmulationRunRequest fingerprint_run;
  fingerprint_run.seed = 7;
  fingerprint_run.run_id = 3;
  fingerprint_job.runs.push_back(fingerprint_run);
  const uint64_t first = viy_emulation_job_fingerprint(fingerprint_job, 9, {});
  CHECK(first == viy_emulation_job_fingerprint(fingerprint_job, 9, {}));
  fingerprint_job.config.log_level = ViyLogLevel::TRACE;
  fingerprint_job.config.progress_interval_ms = 60000;
  CHECK(first == viy_emulation_job_fingerprint(fingerprint_job, 9, {}));
  fingerprint_job.runs[0].seed = 8;
  CHECK(first != viy_emulation_job_fingerprint(fingerprint_job, 9, {}));
  fingerprint_job.runs[0].seed = 7;
  CHECK(first != viy_emulation_job_fingerprint(
      fingerprint_job, 10, {{0x5000, EmuSummaryKind::MEMCPY}}));
  test_ordered_delivery();
  test_generation_cancellation();
  test_unavailable_and_backpressure();
  test_cooperative_shutdown();
  return 0;
}
