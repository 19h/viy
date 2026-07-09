#include "hexrays_bridge.hpp"

#include "analysis_facts.hpp"
#include "evidence_store.hpp"

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// A build can explicitly turn the bridge off even when hexrays.hpp is in the
// include path.  Otherwise detect the optional SDK header.
#ifndef VIY_WITH_HEXRAYS_SDK
#  if defined(__has_include)
#    if __has_include(<hexrays.hpp>)
#      define VIY_WITH_HEXRAYS_SDK 1
#    else
#      define VIY_WITH_HEXRAYS_SDK 0
#    endif
#  else
#    define VIY_WITH_HEXRAYS_SDK 0
#  endif
#endif

#if VIY_WITH_HEXRAYS_SDK
#  include <pro.h>
#  include <ida.hpp>
#  include <idp.hpp>
#  include <loader.hpp>
#  include <hexrays.hpp>
#endif

namespace viy {

namespace {

using namespace analysis;

std::string hex_address(uint64_t value)
{
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

std::string bytes_text(const std::vector<uint8_t> &bytes, size_t maximum)
{
  std::ostringstream stream;
  const size_t count = std::min(bytes.size(), maximum);
  stream << std::hex << std::setfill('0');
  for ( size_t index = 0; index < count; ++index )
  {
    if ( index != 0 )
      stream << ' ';
    stream << std::setw(2) << unsigned(bytes[index]);
  }
  if ( count < bytes.size() )
    stream << " ... (" << std::dec << bytes.size() << " bytes)";
  return stream.str();
}

std::string quoted_text(const std::string &value, size_t maximum)
{
  std::string out;
  out.reserve(std::min(value.size(), maximum) + 8);
  out.push_back('"');
  const size_t count = std::min(value.size(), maximum);
  for ( size_t index = 0; index < count; ++index )
  {
    const unsigned char byte = static_cast<unsigned char>(value[index]);
    if ( byte == '\\' || byte == '"' )
    {
      out.push_back('\\');
      out.push_back(static_cast<char>(byte));
    }
    else if ( byte >= 0x20 && byte < 0x7f )
    {
      out.push_back(static_cast<char>(byte));
    }
    else
    {
      static constexpr char digits[] = "0123456789abcdef";
      out.append("\\x");
      out.push_back(digits[byte >> 4]);
      out.push_back(digits[byte & 0xf]);
    }
  }
  if ( count < value.size() )
    out.append("...");
  out.push_back('"');
  return out;
}

const char *target_kind_name(CodeTargetKind kind)
{
  switch ( kind )
  {
    case CodeTargetKind::Call: return "call";
    case CodeTargetKind::Jump: return "jump";
    case CodeTargetKind::Fallthrough: return "fallthrough";
    case CodeTargetKind::Return: return "return";
    case CodeTargetKind::TableEntry: return "table-entry";
    case CodeTargetKind::Exception: return "exception";
    case CodeTargetKind::Unknown: break;
  }
  return "control-flow";
}

const char *access_kind_name(MemoryAccessKind kind)
{
  switch ( kind )
  {
    case MemoryAccessKind::Read: return "read";
    case MemoryAccessKind::Write: return "write";
    case MemoryAccessKind::Execute: return "execute";
    case MemoryAccessKind::ReadWrite: return "read/write";
  }
  return "access";
}

const char *encoding_name(StringEncoding encoding)
{
  switch ( encoding )
  {
    case StringEncoding::Bytes: return "byte";
    case StringEncoding::Ascii: return "ASCII";
    case StringEncoding::Utf8: return "UTF-8";
    case StringEncoding::Utf16LE: return "UTF-16LE";
    case StringEncoding::Utf16BE: return "UTF-16BE";
    case StringEncoding::Utf32LE: return "UTF-32LE";
    case StringEncoding::Utf32BE: return "UTF-32BE";
  }
  return "string";
}

const char *stop_kind_name(FunctionStopKind stop)
{
  switch ( stop )
  {
    case FunctionStopKind::Returned: return "returned";
    case FunctionStopKind::Halted: return "halted";
    case FunctionStopKind::Faulted: return "faulted";
    case FunctionStopKind::TimedOut: return "timed out";
    case FunctionStopKind::BudgetExhausted: return "exhausted the instruction budget";
    case FunctionStopKind::EscapedFunction: return "escaped the function";
    case FunctionStopKind::TerminatedProcess: return "terminated the process";
    case FunctionStopKind::Unknown: break;
  }
  return "has an unknown outcome";
}

const char *call_result_name(CallResult result)
{
  switch ( result )
  {
    case CallResult::Returned: return "returned";
    case CallResult::NoReturn: return "did not return";
    case CallResult::Faulted: return "faulted";
    case CallResult::TimedOut: return "timed out";
    case CallResult::Unknown: break;
  }
  return "has an unknown result";
}

std::string trait_text(const FunctionTraitFact &trait)
{
  std::string name;
  switch ( trait.trait )
  {
    case FunctionTraitKind::Returns: name = "returns"; break;
    case FunctionTraitKind::NoReturn: name = "does not return"; break;
    case FunctionTraitKind::StackDelta: name = "stack delta"; break;
    case FunctionTraitKind::ArgumentRegister: name = "argument register"; break;
    case FunctionTraitKind::ReturnConstant: name = "return constant"; break;
    case FunctionTraitKind::WrapperTarget: name = "wrapper target"; break;
    case FunctionTraitKind::Leaf: name = "leaf function"; break;
    case FunctionTraitKind::Thunk: name = "thunk"; break;
    case FunctionTraitKind::CallingConvention: name = "calling convention"; break;
    case FunctionTraitKind::Other: name = "function trait"; break;
  }

  switch ( trait.value.kind )
  {
    case TraitValueKind::Signed:
      name += " = " + std::to_string(trait.value.signed_value);
      break;
    case TraitValueKind::Unsigned:
      name += " = " + hex_address(trait.value.unsigned_value);
      break;
    case TraitValueKind::Boolean:
      name += trait.value.boolean_value ? " = true" : " = false";
      break;
    case TraitValueKind::Text:
      name += " = " + quoted_text(trait.value.text_value, 80);
      break;
    case TraitValueKind::None:
      break;
  }
  return name;
}

bool trusted_proof(const Evidence &evidence, uint16_t minimum_confidence)
{
  if ( evidence.confidence < minimum_confidence )
    return false;
  return evidence.proof == ProofKind::StaticProof
      || evidence.proof == ProofKind::SymbolicProof
      || evidence.proof == ProofKind::UserAsserted;
}

std::set<std::string> conflict_digests(const EvidenceStore &store)
{
  std::set<std::string> result;
  for ( const EvidenceConflict &conflict : store.detect_conflicts() )
  {
    // Even variations are unsafe as constant-propagation-style hints: showing
    // one concrete value without its competing value would be misleading.
    result.insert(conflict.left.hex());
    result.insert(conflict.right.hex());
  }
  return result;
}

std::string payload_digest(const FactPayload &payload)
{
  FactDigest digest;
  std::string error;
  return stable_digest(payload, digest, &error) ? digest.hex() : std::string();
}

std::vector<uint64_t> function_scopes(const EvidenceRecord &record,
                                      uint16_t minimum_confidence)
{
  std::vector<uint64_t> starts;
  for ( const Evidence &evidence : record.observations )
    if ( evidence.confidence >= minimum_confidence
      && evidence.scope.function_start.has_value() )
      starts.push_back(*evidence.scope.function_start);

  std::visit(
    [&](const auto &payload) {
      using T = std::decay_t<decltype(payload)>;
      if constexpr ( std::is_same_v<T, FunctionCandidateFact> )
        starts.push_back(payload.entry);
      else if constexpr ( std::is_same_v<T, FunctionTraitFact>
                       || std::is_same_v<T, FunctionOutcomeFact> )
        starts.push_back(payload.function);
    },
    record.payload);

  std::sort(starts.begin(), starts.end());
  starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
  return starts;
}

bool make_annotation(const EvidenceRecord &record,
                     const HexRaysBridgeOptions &options,
                     const SupportSummary &support,
                     HexRaysEvidenceAnnotation &out)
{
  out.confidence = support.maximum_confidence;
  out.distinct_runs = support.distinct_run_count;
  out.distinct_producers = support.distinct_producer_count;
  out.function_starts = function_scopes(record, options.minimum_confidence);

  return std::visit(
    [&](const auto &payload) -> bool {
      using T = std::decay_t<decltype(payload)>;
      if constexpr ( std::is_same_v<T, CodeTargetFact> )
      {
        out.address = payload.from;
        out.kind = HexRaysAnnotationKind::ControlFlow;
        out.priority = payload.unique ? 0 : 1;
        out.text = std::string(target_kind_name(payload.kind)) + " target "
                 + hex_address(payload.target);
        if ( payload.unique )
          out.text += " (unique)";
      }
      else if constexpr ( std::is_same_v<T, BranchReachabilityFact> )
      {
        if ( payload.state == Reachability::NotObserved )
          return false; // absence is intentionally not evidence of dead code
        out.address = payload.branch;
        out.kind = HexRaysAnnotationKind::Reachability;
        out.priority = payload.state == Reachability::ProvenUnreachable ? 0 : 2;
        out.text = "successor " + hex_address(payload.successor);
        out.text += payload.state == Reachability::Reached
                  ? " was reached" : " is proven unreachable";
      }
      else if constexpr ( std::is_same_v<T, MemoryAccessFact> )
      {
        out.address = payload.instruction;
        out.kind = HexRaysAnnotationKind::Memory;
        out.priority = 4;
        out.text = std::string(access_kind_name(payload.kind)) + " "
                 + std::to_string(payload.size) + " byte(s) at "
                 + hex_address(payload.address);
      }
      else if constexpr ( std::is_same_v<T, MemoryValueFact> )
      {
        out.address = payload.instruction;
        out.kind = HexRaysAnnotationKind::ConcreteValue;
        out.priority = 2;
        out.text = std::string(access_kind_name(payload.kind)) + " value at "
                 + hex_address(payload.address) + " = "
                 + bytes_text(payload.bytes, options.maximum_value_bytes);
      }
      else if constexpr ( std::is_same_v<T, StringCandidateFact> )
      {
        out.address = payload.address;
        out.kind = HexRaysAnnotationKind::String;
        out.priority = 4;
        out.text = std::string(encoding_name(payload.encoding)) + " string candidate ";
        out.text += payload.decoded.empty()
                  ? bytes_text(payload.bytes, options.maximum_value_bytes)
                  : quoted_text(payload.decoded, 96);
        if ( payload.null_terminated )
          out.text += " (NUL-terminated)";
      }
      else if constexpr ( std::is_same_v<T, FunctionCandidateFact> )
      {
        out.address = payload.entry;
        out.kind = HexRaysAnnotationKind::Function;
        out.priority = 4;
        out.text = "function candidate at " + hex_address(payload.entry);
      }
      else if constexpr ( std::is_same_v<T, FunctionTraitFact> )
      {
        out.address = payload.function;
        out.kind = payload.trait == FunctionTraitKind::ReturnConstant
                 ? HexRaysAnnotationKind::ConcreteValue
                 : HexRaysAnnotationKind::Function;
        out.priority = payload.trait == FunctionTraitKind::NoReturn
                    || payload.trait == FunctionTraitKind::ReturnConstant ? 1 : 3;
        out.text = trait_text(payload);
      }
      else if constexpr ( std::is_same_v<T, CodeRegionFact> )
      {
        // Region classifications are useful to the IDB analysis consumer but
        // too broad/noisy to present as pseudocode-local evidence.
        return false;
      }
      else if constexpr ( std::is_same_v<T, DispatchMapFact> )
      {
        out.address = payload.site;
        out.kind = HexRaysAnnotationKind::Dispatch;
        out.priority = 1;
        out.text = "dispatch map with " + std::to_string(payload.cases.size())
                 + " observed case(s)";
        if ( payload.default_target.has_value() )
          out.text += ", default " + hex_address(*payload.default_target);
        out.text += payload.complete ? " (complete)" : " (incomplete)";
      }
      else if constexpr ( std::is_same_v<T, CfgCandidateFact> )
      {
        if ( payload.state == Reachability::NotObserved )
          return false;
        out.address = payload.from;
        out.kind = HexRaysAnnotationKind::ControlFlow;
        out.priority = 2;
        out.text = "CFG edge to " + hex_address(payload.to);
        if ( payload.state == Reachability::ProvenUnreachable )
          out.text += " is proven unreachable";
        else
          out.text += " was reached";
      }
      else if constexpr ( std::is_same_v<T, FunctionOutcomeFact> )
      {
        out.address = payload.function;
        out.kind = HexRaysAnnotationKind::Function;
        out.priority = payload.stop == FunctionStopKind::TerminatedProcess ? 1 : 3;
        out.text = std::string("function ") + stop_kind_name(payload.stop);
        if ( payload.stop_pc.has_value() )
          out.text += " at " + hex_address(*payload.stop_pc);
        if ( payload.stack_delta.has_value() )
          out.text += ", stack delta " + std::to_string(*payload.stack_delta);
      }
      else if constexpr ( std::is_same_v<T, RegisterValueFact> )
      {
        out.address = payload.instruction;
        out.kind = HexRaysAnnotationKind::ConcreteValue;
        out.priority = 2;
        out.text = payload.register_id + " = "
                 + bytes_text(payload.bytes, options.maximum_value_bytes);
      }
      else if constexpr ( std::is_same_v<T, CallObservationFact> )
      {
        out.address = payload.source;
        out.kind = HexRaysAnnotationKind::Call;
        out.priority = payload.result == CallResult::NoReturn ? 1 : 2;
        out.text = "observed call";
        if ( payload.target.has_value() )
          out.text += " to " + hex_address(*payload.target);
        out.text += ": ";
        out.text += call_result_name(payload.result);
        if ( !payload.arguments.empty() )
          out.text += ", " + std::to_string(payload.arguments.size())
                    + " argument component(s) captured";
      }
      return true;
    },
    record.payload);
}

bool annotation_less(const HexRaysEvidenceAnnotation &left,
                     const HexRaysEvidenceAnnotation &right)
{
  if ( left.address != right.address )
    return left.address < right.address;
  if ( left.priority != right.priority )
    return left.priority < right.priority;
  if ( left.kind != right.kind )
    return left.kind < right.kind;
  return left.text < right.text;
}

HexRaysBridgeOptions safe_options(HexRaysBridgeOptions options)
{
  options.minimum_confidence =
    std::min<uint16_t>(options.minimum_confidence, kMaxConfidence);
  // A one-run "corroboration" setting would turn every concrete observation
  // into a decompiler assertion.  Keep this bridge conservative even if an
  // embedding caller passes an unsafe value.
  options.minimum_distinct_runs =
    std::max<size_t>(2, options.minimum_distinct_runs);
  options.maximum_warnings_per_function =
    std::min<size_t>(64, options.maximum_warnings_per_function);
  options.maximum_hint_lines =
    std::min<size_t>(64, options.maximum_hint_lines);
  options.maximum_value_bytes =
    std::min<size_t>(256, options.maximum_value_bytes);
  return options;
}

} // namespace

std::vector<HexRaysEvidenceAnnotation> viy_build_hexrays_annotations(
    const EvidenceStore &store,
    const HexRaysBridgeOptions &options,
    HexRaysBridgeStats *stats)
{
  const HexRaysBridgeOptions policy = safe_options(options);
  HexRaysBridgeStats local;
  const std::set<std::string> conflicted = conflict_digests(store);
  std::vector<HexRaysEvidenceAnnotation> result;

  for ( const EvidenceRecord &record : store.records() )
  {
    ++local.records_considered;
    const std::string digest = payload_digest(record.payload);
    if ( digest.empty() || conflicted.count(digest) != 0 )
    {
      ++local.records_conflicted;
      continue;
    }

    const bool trusted = std::any_of(
      record.observations.begin(), record.observations.end(),
      [&](const Evidence &evidence) {
        return trusted_proof(evidence, policy.minimum_confidence);
      });
    const bool corroborated = is_corroborated(
      record,
      policy.minimum_distinct_runs,
      1,
      policy.minimum_confidence);
    if ( !trusted && !corroborated )
    {
      ++local.records_below_policy;
      continue;
    }

    HexRaysEvidenceAnnotation annotation;
    if ( !make_annotation(record, policy, summarize_support(record), annotation) )
      continue;
    ++local.records_accepted;
    result.push_back(std::move(annotation));
  }

  std::sort(result.begin(), result.end(), annotation_less);
  local.annotations_built = result.size();
  if ( stats != nullptr )
    *stats = local;
  return result;
}

struct HexRaysRuntimeSnapshot
{
  explicit HexRaysRuntimeSnapshot(std::vector<HexRaysEvidenceAnnotation> source)
    : annotations(std::move(source))
  {
    for ( size_t index = 0; index < annotations.size(); ++index )
    {
      const HexRaysEvidenceAnnotation &annotation = annotations[index];
      by_address[annotation.address].push_back(index);
      if ( annotation.function_starts.empty() )
      {
        unscoped.push_back(index);
      }
      else
      {
        for ( uint64_t function : annotation.function_starts )
          by_function[function].push_back(index);
      }
    }
  }

  std::vector<HexRaysEvidenceAnnotation> annotations;
  std::map<uint64_t, std::vector<size_t>> by_address;
  std::map<uint64_t, std::vector<size_t>> by_function;
  std::vector<size_t> unscoped;
};

struct HexRaysEvidenceBridge::Impl
{
  HexRaysBridgeOptions options;
  std::shared_ptr<const HexRaysRuntimeSnapshot> snapshot =
    std::make_shared<const HexRaysRuntimeSnapshot>(
      std::vector<HexRaysEvidenceAnnotation>{});
  HexRaysBridgeStats build_stats;
  std::atomic<size_t> warning_lines_published{0};
  std::atomic<size_t> hints_published{0};
  std::atomic<size_t> callback_failures{0};
  bool installed = false;

#if VIY_WITH_HEXRAYS_SDK
  static ssize_t idaapi callback(void *user_data,
                                 hexrays_event_t event,
                                 va_list arguments)
  {
    Impl *self = static_cast<Impl *>(user_data);
    if ( self == nullptr )
      return 0;
    // va_list is not a generally copyable value.  In particular, forwarding
    // the callback-owned object through another function on Apple arm64 can
    // advance/read an invalid cursor.  Give dispatch an independent cursor and
    // always release it before crossing the C callback boundary.
    va_list copied_arguments;
    va_copy(copied_arguments, arguments);
    ssize_t result = 0;
    try
    {
      result = self->dispatch(event, copied_arguments);
    }
    catch ( ... )
    {
      self->callback_failures.fetch_add(1, std::memory_order_relaxed);
    }
    va_end(copied_arguments);
    return result;
  }

  static void append_annotation(qstring &out,
                                const HexRaysEvidenceAnnotation &annotation)
  {
    // Do not pass C++ values through IDA's printf-like varargs formatter here.
    // This callback can run inside the decompiler's text builder, and format
    // width/float ABI differences between SDK/runtime versions must not be able
    // to corrupt the warning vector.  Materialize with the standard stream and
    // cross the SDK boundary through qstring::append(const char *) only.
    std::ostringstream rendered;
    rendered << "[viy] 0x" << std::hex << annotation.address << std::dec
             << ": " << annotation.text << " (confidence "
             << std::fixed << std::setprecision(1)
             << (double(annotation.confidence) / 100.0) << '%';
    if ( annotation.distinct_runs != 0 )
      rendered << ", " << annotation.distinct_runs << " runs";
    if ( annotation.distinct_producers > 1 )
      rendered << ", " << annotation.distinct_producers << " producers";
    rendered << ')';
    if ( !out.empty() && out.last() != '\n' )
      out.append('\n');
    const std::string line = rendered.str();
    out.append(line.c_str());
  }

  ssize_t dispatch(hexrays_event_t event, va_list arguments)
  {
    const auto current = std::atomic_load_explicit(&snapshot,
                                                   std::memory_order_acquire);
    if ( current == nullptr || current->annotations.empty() )
      return 0;

    if ( event == hxe_collect_warnings && options.publish_function_warnings )
    {
      qstrvec_t *warnings = va_arg(arguments, qstrvec_t *);
      cfunc_t *function = va_arg(arguments, cfunc_t *);
      if ( warnings == nullptr || function == nullptr )
        return 0;
      if ( options.maximum_warnings_per_function == 0 )
        return 0;

      std::vector<const HexRaysEvidenceAnnotation *> selected;
      const auto scoped = current->by_function.find(uint64_t(function->entry_ea));
      if ( scoped != current->by_function.end() )
      {
        selected.reserve(scoped->second.size() + current->unscoped.size());
        for ( size_t index : scoped->second )
          selected.push_back(&current->annotations[index]);
      }
      if ( function->mba != nullptr )
      {
        for ( size_t index : current->unscoped )
        {
          const HexRaysEvidenceAnnotation &annotation = current->annotations[index];
          if ( function->mba->mbr.range_contains(ea_t(annotation.address)) )
            selected.push_back(&annotation);
        }
      }
      std::sort(selected.begin(), selected.end(),
        [](const auto *left, const auto *right) {
          if ( left->priority != right->priority )
            return left->priority < right->priority;
          return annotation_less(*left, *right);
        });

      const size_t count = std::min(selected.size(),
                                    options.maximum_warnings_per_function);
      for ( size_t index = 0; index < count; ++index )
      {
        // Construct in the destination vector.  This is the SDK's canonical
        // qstrvec_t output pattern and avoids transporting qstring ownership
        // across the decompiler callback boundary.
        qstring &line = warnings->push_back();
        append_annotation(line, *selected[index]);
      }
      if ( count < selected.size() )
      {
        const std::string omitted_text =
          "[viy] " + std::to_string(selected.size() - count)
          + " additional gated evidence item(s) omitted";
        warnings->push_back().append(omitted_text.c_str());
      }
      warning_lines_published.fetch_add(count + (count < selected.size() ? 1 : 0),
                                        std::memory_order_relaxed);
      return 0;
    }

    if ( event == hxe_create_hint && options.publish_cursor_hints )
    {
      vdui_t *view = va_arg(arguments, vdui_t *);
      qstring *hint = va_arg(arguments, qstring *);
      int *important_lines = va_arg(arguments, int *);
      if ( view == nullptr || hint == nullptr )
        return 0;

      ea_t address = view->item.get_ea();
      if ( address == BADADDR && view->cfunc != nullptr
        && view->item.citype == VDI_FUNC )
        address = view->cfunc->entry_ea;
      if ( address == BADADDR )
        return 0;

      if ( options.maximum_hint_lines == 0 )
        return 0;

      size_t count = 0;
      const auto found = current->by_address.find(uint64_t(address));
      if ( found == current->by_address.end() )
        return 0;
      for ( size_t index : found->second )
      {
        const HexRaysEvidenceAnnotation &annotation = current->annotations[index];
        append_annotation(*hint, annotation);
        ++count;
        if ( count == options.maximum_hint_lines )
          break;
      }
      if ( important_lines != nullptr )
        *important_lines += int(count);
      hints_published.fetch_add(count, std::memory_order_relaxed);
      return 0; // allow other decompiler plugins to append their hints
    }
    return 0;
  }
#endif
};

HexRaysEvidenceBridge::HexRaysEvidenceBridge()
  : impl_(new Impl)
{
}

HexRaysEvidenceBridge::~HexRaysEvidenceBridge()
{
  stop();
}

bool HexRaysEvidenceBridge::start(const HexRaysBridgeOptions &options,
                                  std::string *reason)
{
  stop();
  impl_->options = safe_options(options);
#if VIY_WITH_HEXRAYS_SDK
  if ( !init_hexrays_plugin(0) )
  {
    if ( reason != nullptr )
      *reason = "a compatible Hex-Rays decompiler is not available";
    return false;
  }
  if ( !install_hexrays_callback(&Impl::callback, impl_.get()) )
  {
    term_hexrays_plugin();
    if ( reason != nullptr )
      *reason = "Hex-Rays rejected the callback installation";
    return false;
  }
  impl_->installed = true;
  if ( reason != nullptr )
    reason->clear();
  return true;
#else
  if ( reason != nullptr )
    *reason = "viy was built without the optional Hex-Rays SDK header";
  return false;
#endif
}

void HexRaysEvidenceBridge::stop()
{
#if VIY_WITH_HEXRAYS_SDK
  if ( impl_ != nullptr && impl_->installed )
  {
    remove_hexrays_callback(&Impl::callback, impl_.get());
    impl_->installed = false;
    term_hexrays_plugin();
  }
#else
  if ( impl_ != nullptr )
    impl_->installed = false;
#endif
}

void HexRaysEvidenceBridge::publish(const EvidenceStore &store)
{
  HexRaysBridgeStats fresh_stats;
  auto fresh = std::make_shared<const HexRaysRuntimeSnapshot>(
    viy_build_hexrays_annotations(store, impl_->options, &fresh_stats));
  impl_->build_stats = fresh_stats;
  std::atomic_store_explicit(&impl_->snapshot, std::move(fresh),
                             std::memory_order_release);
}

bool HexRaysEvidenceBridge::installed() const
{
  return impl_ != nullptr && impl_->installed;
}

HexRaysBridgeStats HexRaysEvidenceBridge::stats() const
{
  HexRaysBridgeStats result = impl_->build_stats;
  result.warning_lines_published =
    impl_->warning_lines_published.load(std::memory_order_relaxed);
  result.hints_published = impl_->hints_published.load(std::memory_order_relaxed);
  result.callback_failures = impl_->callback_failures.load(std::memory_order_relaxed);
  return result;
}

bool HexRaysEvidenceBridge::compiled_with_hexrays_sdk()
{
#if VIY_WITH_HEXRAYS_SDK
  return true;
#else
  return false;
#endif
}

} // namespace viy
