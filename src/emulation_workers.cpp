#include "emulation_workers.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <utility>

namespace viy {

namespace {

struct CancellationState
{
  std::atomic<uint64_t> generation{ 1 };
};

const CancellationState *as_cancellation_state(const std::shared_ptr<const void> &p)
{
  return static_cast<const CancellationState *>(p.get());
}

EmulationJobResult cancelled_result(uint64_t ticket, uint64_t function_start,
                                    const char *reason)
{
  EmulationJobResult result;
  result.ticket = ticket;
  result.function_start = function_start;
  result.status = EmulationJobStatus::CANCELLED;
  result.diagnostic = reason;
  return result;
}

EmulationJobResult unavailable_result(uint64_t ticket, uint64_t function_start,
                                      const char *reason)
{
  EmulationJobResult result;
  result.ticket = ticket;
  result.function_start = function_start;
  result.status = EmulationJobStatus::UNAVAILABLE;
  result.diagnostic = reason;
  return result;
}

} // namespace

EmulationCancellation::EmulationCancellation(std::shared_ptr<const void> state,
                                             uint64_t generation)
  : state_(std::move(state)), generation_(generation)
{
}

bool EmulationCancellation::cancelled() const noexcept
{
  const CancellationState *state = as_cancellation_state(state_);
  return state == nullptr
      || state->generation.load(std::memory_order_acquire) != generation_;
}

size_t viy_resolve_worker_count(int configured, size_t hard_cap)
{
  if ( hard_cap == 0 )
    return 0;
  if ( configured > 0 )
    return std::min<size_t>(size_t(configured), hard_cap);
  const unsigned reported = std::thread::hardware_concurrency();
  const size_t automatic = reported > 1 ? size_t(reported - 1) : size_t(1);
  constexpr size_t kAutomaticEngineCap = 4;
  return std::min(std::min(automatic, kAutomaticEngineCap), hard_cap);
}

uint64_t viy_emulation_job_fingerprint(
    const EmulationJob &job,
    uint64_t image_content_hash,
    const std::vector<EmuCallSummary> &call_summaries)
{
  constexpr uint64_t offset = UINT64_C(14695981039346656037);
  constexpr uint64_t prime = UINT64_C(1099511628211);
  uint64_t hash = offset;
  auto byte = [&](uint8_t value) { hash = (hash ^ value) * prime; };
  auto u64 = [&](uint64_t value)
  {
    for ( unsigned shift = 0; shift != 64; shift += 8 )
      byte(uint8_t(value >> shift));
  };
  auto boolean = [&](bool value) { byte(value ? uint8_t(1) : uint8_t(0)); };

  u64(UINT64_C(0x5649594a4f424631)); // "VIYJOBF1"
  u64(image_content_hash);
  u64(job.function.start);
  u64(job.function.end);
  u64(job.function.byte_hash);
  u64(uint64_t(job.function.chunks.size()));
  for ( const FuncChunk &chunk : job.function.chunks )
  {
    u64(chunk.start - job.function.start);
    u64(chunk.end > chunk.start ? chunk.end - chunk.start : 0);
  }

  const ViyConfig &cfg = job.config;
  boolean(cfg.enabled); u64(cfg.max_insns); u64(cfg.timeout_ms); u64(cfg.max_funcs);
  u64(uint64_t(cfg.funcs_per_tick)); u64(uint64_t(cfg.tick_ms));
  u64(uint64_t(cfg.max_epochs)); u64(uint64_t(cfg.explore_runs));
  boolean(cfg.make_code); boolean(cfg.want_drefs); boolean(cfg.want_static);
  boolean(cfg.want_native); boolean(cfg.strict_perms);
  boolean(cfg.want_import_summaries); boolean(cfg.want_runtime_strings);
  boolean(cfg.want_unicode_strings); boolean(cfg.want_tables);
  boolean(cfg.want_smc_evidence); boolean(cfg.apply_runtime_bytes);
  u64(cfg.max_runtime_bytes); boolean(cfg.want_switch); boolean(cfg.want_purge);
  boolean(cfg.want_noret); boolean(cfg.set_noret); boolean(cfg.want_argregs);
  boolean(cfg.want_opaque); u64(uint64_t(cfg.opaque_runs));

  u64(uint64_t(call_summaries.size()));
  for ( const EmuCallSummary &summary : call_summaries )
  {
    u64(summary.address);
    byte(uint8_t(summary.kind));
  }

  u64(uint64_t(job.runs.size()));
  for ( const EmulationRunRequest &run : job.runs )
  {
    u64(run.seed); u64(run.run_id); boolean(run.record_pcs); boolean(run.has_input);
    if ( !run.has_input )
      continue;
    const EmuInput &input = run.input;
    u64(input.seed); u64(input.run_id); u64(input.stack_arg_offset);
    u64(uint64_t(input.args.size()));
    for ( uint64_t value : input.args ) u64(value);
    u64(uint64_t(input.arg_overrides.size()));
    for ( const EmuInput::ArgOverride &arg : input.arg_overrides )
    { u64(arg.index); u64(arg.value); }
    u64(uint64_t(input.register_overrides.size()));
    for ( const EmuInput::RegisterOverride &reg : input.register_overrides )
    { u64(uint64_t(uint32_t(reg.reg))); u64(reg.value); }
    u64(uint64_t(input.stack_args.size()));
    for ( uint64_t value : input.stack_args ) u64(value);
  }
  return hash;
}

struct EmulationWorkerPool::Impl
{
  struct QueuedJob
  {
    uint64_t ticket = 0;
    uint64_t generation = 0;
    EmulationJob job;
  };

  explicit Impl(size_t requested, EmulationExecutorFactory f, size_t max_queued)
    : requested_workers(requested), factory(std::move(f)),
      max_queued_jobs(max_queued), cancellation(std::make_shared<CancellationState>())
  {
  }

  ~Impl()
  {
    stop_and_join();
  }

  void settle_locked(EmulationJobResult result)
  {
    // Every accepted ticket settles exactly once. Ignore an executor-supplied
    // duplicate rather than replacing an earlier cancellation result.
    if ( completed.emplace(result.ticket, std::move(result)).second )
    {
      ++settled;
      if ( unsettled != 0 )
        --unsettled;
    }
    cv.notify_all();
  }

  void drain_queued_locked(EmulationJobStatus status, const char *reason)
  {
    while ( !queue.empty() )
    {
      QueuedJob item = std::move(queue.front());
      queue.pop_front();
      EmulationJobResult result = status == EmulationJobStatus::UNAVAILABLE
          ? unavailable_result(item.ticket, item.job.function.start, reason)
          : cancelled_result(item.ticket, item.job.function.start, reason);
      settle_locked(std::move(result));
    }
  }

  void worker_main(size_t worker_index)
  {
    std::unique_ptr<EmulationExecutor> executor;
    std::string initialization_error;
    try
    {
      if ( factory )
        executor = factory(worker_index);
      if ( executor == nullptr )
        initialization_error = "worker executor factory returned null";
      else if ( !executor->available() )
        initialization_error = executor->unavailable_reason();
    }
    catch ( const std::exception &e )
    {
      initialization_error = e.what();
    }
    catch ( ... )
    {
      initialization_error = "worker executor initialization threw";
    }

    const bool available = executor != nullptr && executor->available();
    {
      std::lock_guard<std::mutex> lock(mutex);
      ++initialized_workers;
      if ( available )
        ++available_workers;
      else
      {
        ++unavailable_workers;
        if ( first_unavailable_reason.empty() )
          first_unavailable_reason = initialization_error.empty()
                                   ? "worker executor is unavailable"
                                   : initialization_error;
      }
      if ( initialized_workers == requested_workers && available_workers == 0 )
        drain_queued_locked(EmulationJobStatus::UNAVAILABLE,
                            first_unavailable_reason.c_str());
      cv.notify_all();
    }
    if ( !available )
      return;

    for ( ;; )
    {
      QueuedJob item;
      {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [&] { return stopping || !queue.empty(); });
        if ( stopping )
          return;
        item = std::move(queue.front());
        queue.pop_front();
        ++running;
        cv.notify_all(); // queue capacity may now be available
      }

      EmulationJobResult result;
      const std::shared_ptr<const void> token_state = cancellation;
      const EmulationCancellation token(token_state, item.generation);
      try
      {
        result = executor->execute(item.job, token);
      }
      catch ( const std::exception &e )
      {
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = e.what();
      }
      catch ( ... )
      {
        result.status = EmulationJobStatus::FAILED;
        result.diagnostic = "worker executor threw";
      }
      result.ticket = item.ticket;
      result.function_start = item.job.function.start;

      {
        std::lock_guard<std::mutex> lock(mutex);
        if ( running != 0 )
          --running;
        // The generation is checked under the same lock used by
        // cancel_pending(), closing the completion-vs-cancel race.
        if ( cancellation->generation.load(std::memory_order_acquire) != item.generation
          && result.status != EmulationJobStatus::CANCELLED )
        {
          result.status = EmulationJobStatus::CANCELLED;
          result.diagnostic = "emulation generation cancelled";
        }
        settle_locked(std::move(result));
      }
    }
  }

  void stop_and_join()
  {
    {
      std::lock_guard<std::mutex> lock(mutex);
      if ( !stopping )
      {
        stopping = true;
        cancellation->generation.fetch_add(1, std::memory_order_acq_rel);
        drain_queued_locked(EmulationJobStatus::CANCELLED, "worker pool shut down");
      }
      cv.notify_all();
    }
    for ( std::thread &thread : threads )
      if ( thread.joinable() )
        thread.join();
  }

  mutable std::mutex mutex;
  mutable std::condition_variable cv;
  size_t requested_workers = 0;
  EmulationExecutorFactory factory;
  size_t max_queued_jobs = 0;
  std::shared_ptr<CancellationState> cancellation;
  std::vector<std::thread> threads;
  std::deque<QueuedJob> queue;
  std::map<uint64_t, EmulationJobResult> completed;
  std::string first_unavailable_reason;
  uint64_t next_ticket = 1;
  uint64_t next_delivery = 1;
  uint64_t submitted = 0;
  uint64_t settled = 0;
  uint64_t delivered = 0;
  uint64_t unsettled = 0;
  size_t initialized_workers = 0;
  size_t available_workers = 0;
  size_t unavailable_workers = 0;
  size_t running = 0;
  bool stopping = false;
};

EmulationWorkerPool::EmulationWorkerPool(size_t worker_count,
                                         EmulationExecutorFactory factory,
                                         size_t max_queued_jobs)
{
  worker_count = std::max<size_t>(worker_count, 1);
  impl_.reset(new Impl(worker_count, std::move(factory), max_queued_jobs));
  try
  {
    impl_->threads.reserve(worker_count);
    for ( size_t i = 0; i < worker_count; ++i )
      impl_->threads.emplace_back([this, i] { impl_->worker_main(i); });
  }
  catch ( ... )
  {
    // Thread resource exhaustion degrades to the workers already created. The
    // pool remains usable when at least one exists and reports the actual count.
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->requested_workers = impl_->threads.size();
    if ( impl_->requested_workers == 0 )
    {
      impl_->first_unavailable_reason = "no worker thread could be created";
      impl_->drain_queued_locked(EmulationJobStatus::UNAVAILABLE,
                                 impl_->first_unavailable_reason.c_str());
    }
    impl_->cv.notify_all();
  }
}

EmulationWorkerPool::~EmulationWorkerPool()
{
  shutdown();
}

bool EmulationWorkerPool::try_submit(EmulationJob job, uint64_t *ticket)
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if ( impl_->stopping )
    return false;
  if ( impl_->max_queued_jobs != 0 && impl_->queue.size() >= impl_->max_queued_jobs )
    return false;
  if ( impl_->next_ticket == std::numeric_limits<uint64_t>::max() )
    return false;

  const uint64_t assigned = impl_->next_ticket++;
  ++impl_->submitted;
  ++impl_->unsettled;
  if ( ticket != nullptr )
    *ticket = assigned;

  if ( impl_->initialized_workers == impl_->requested_workers
    && impl_->available_workers == 0 )
  {
    const char *reason = impl_->first_unavailable_reason.empty()
                       ? "no emulation worker is available"
                       : impl_->first_unavailable_reason.c_str();
    impl_->settle_locked(unavailable_result(assigned, job.function.start, reason));
  }
  else
  {
    Impl::QueuedJob queued;
    queued.ticket = assigned;
    queued.generation = impl_->cancellation->generation.load(std::memory_order_acquire);
    queued.job = std::move(job);
    impl_->queue.push_back(std::move(queued));
    impl_->cv.notify_one();
  }
  return true;
}

bool EmulationWorkerPool::try_take_next(EmulationJobResult &out)
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  auto it = impl_->completed.find(impl_->next_delivery);
  if ( it == impl_->completed.end() )
    return false;
  out = std::move(it->second);
  impl_->completed.erase(it);
  ++impl_->next_delivery;
  ++impl_->delivered;
  impl_->cv.notify_all();
  return true;
}

bool EmulationWorkerPool::wait_take_next(EmulationJobResult &out,
                                         std::chrono::milliseconds timeout)
{
  std::unique_lock<std::mutex> lock(impl_->mutex);
  const bool ready = impl_->cv.wait_for(lock, timeout, [&]
  {
    return impl_->completed.find(impl_->next_delivery) != impl_->completed.end();
  });
  if ( !ready )
    return false;
  auto it = impl_->completed.find(impl_->next_delivery);
  out = std::move(it->second);
  impl_->completed.erase(it);
  ++impl_->next_delivery;
  ++impl_->delivered;
  impl_->cv.notify_all();
  return true;
}

std::vector<EmulationJobResult> EmulationWorkerPool::take_ready(size_t maximum)
{
  std::vector<EmulationJobResult> results;
  std::lock_guard<std::mutex> lock(impl_->mutex);
  while ( maximum == 0 || results.size() < maximum )
  {
    auto it = impl_->completed.find(impl_->next_delivery);
    if ( it == impl_->completed.end() )
      break;
    results.push_back(std::move(it->second));
    impl_->completed.erase(it);
    ++impl_->next_delivery;
    ++impl_->delivered;
  }
  if ( !results.empty() )
    impl_->cv.notify_all();
  return results;
}

void EmulationWorkerPool::cancel_pending()
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  if ( impl_->stopping )
    return;
  impl_->cancellation->generation.fetch_add(1, std::memory_order_acq_rel);
  impl_->drain_queued_locked(EmulationJobStatus::CANCELLED,
                             "emulation generation cancelled");
  impl_->cv.notify_all();
}

void EmulationWorkerPool::shutdown()
{
  if ( impl_ != nullptr )
    impl_->stop_and_join();
}

bool EmulationWorkerPool::wait_for_initialization(std::chrono::milliseconds timeout) const
{
  std::unique_lock<std::mutex> lock(impl_->mutex);
  return impl_->cv.wait_for(lock, timeout, [&]
  {
    return impl_->initialized_workers == impl_->requested_workers;
  });
}

bool EmulationWorkerPool::wait_until_idle(std::chrono::milliseconds timeout) const
{
  std::unique_lock<std::mutex> lock(impl_->mutex);
  return impl_->cv.wait_for(lock, timeout, [&] { return impl_->unsettled == 0; });
}

bool EmulationWorkerPool::initialized() const
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->initialized_workers == impl_->requested_workers;
}

bool EmulationWorkerPool::usable() const
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->available_workers != 0;
}

bool EmulationWorkerPool::idle() const
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  return impl_->unsettled == 0;
}

EmulationWorkerStats EmulationWorkerPool::stats() const
{
  std::lock_guard<std::mutex> lock(impl_->mutex);
  EmulationWorkerStats result;
  result.requested_workers = impl_->requested_workers;
  result.initialized_workers = impl_->initialized_workers;
  result.available_workers = impl_->available_workers;
  result.unavailable_workers = impl_->unavailable_workers;
  result.submitted = impl_->submitted;
  result.settled = impl_->settled;
  result.delivered = impl_->delivered;
  result.queued = impl_->queue.size();
  result.running = impl_->running;
  result.ready_in_order_or_later = impl_->completed.size();
  result.stopping = impl_->stopping;
  return result;
}

} // namespace viy
