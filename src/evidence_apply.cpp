#include "evidence_apply.hpp"

#include <string>

#include <pro.h>
#include <auto.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <ua.hpp>

#include "evidence_apply_policy.hpp"

namespace viy {

namespace {

using namespace analysis;

bool executable_target(ea_t ea)
{
  segment_t *segment = getseg(ea);
  return is_mapped(ea) && segment != nullptr
      && (segment->perm == 0 || (segment->perm & SEGPERM_EXEC) != 0)
      && !is_tail(get_flags(ea));
}

bool append_comment(ea_t ea, const std::string &text)
{
  qstring current;
  get_cmt(&current, ea, true);
  if ( current.find(text.c_str()) != qstring::npos )
    return false;
  if ( !current.empty() )
    current.append("\n");
  current.append(text.c_str());
  return set_cmt(ea, current.c_str(), true);
}

} // namespace

EvidenceApplyStats viy_apply_evidence(const EvidenceStore &store,
                                      const ViyConfig &cfg,
                                      const EvidenceApplyProgressCallback &progress)
{
  EvidenceApplyStats stats;
  if ( progress )
  {
    EvidenceApplyProgress event;
    event.records_total = store.record_count();
    event.stage_boundary = true;
    progress(event);
  }
  EvidenceApplyPolicy policy;
  policy.allow_function_recovery = cfg.want_function_recovery;
  policy.allow_unreachable_comments = cfg.want_comments;
  const EvidenceApplyPlan plan = plan_evidence_application(store, policy);
  stats.records_considered = plan.decisions.size();
  stats.records_conflicted = plan.contradiction_suppressed;
  stats.records_below_policy = plan.below_trust_threshold;
  stats.conflict_relations_examined =
      plan.contradiction_scan.candidate_relations_examined;
  stats.conflict_digests_computed =
      plan.contradiction_scan.payload_digests_computed;

  if ( progress )
  {
    EvidenceApplyProgress event;
    event.stage = EvidenceApplyProgressStage::MUTATING;
    event.records_total = plan.decisions.size();
    event.records_conflicted = stats.records_conflicted;
    event.records_below_policy = stats.records_below_policy;
    event.stage_boundary = true;
    progress(event);
  }

  size_t decision_index = 0;
  for ( const EvidenceApplyDecision &decision : plan.decisions )
  {
    switch ( decision.action )
    {
      case EvidenceActionKind::None:
        break;

      case EvidenceActionKind::AddCallReference:
      case EvidenceActionKind::AddJumpReference:
      {
        const auto &target = std::get<CodeTargetFact>(decision.payload);
        const bool call = decision.action == EvidenceActionKind::AddCallReference;
        viy_try_add_cref(target.from, target.target, call, cfg, stats.refs);
        break;
      }

      case EvidenceActionKind::CreateFunction:
      {
        const auto &candidate = std::get<FunctionCandidateFact>(decision.payload);
        const ea_t entry = ea_t(candidate.entry);
        if ( !executable_target(entry) )
          break;
        func_t *owner = get_func(entry);
        if ( owner != nullptr && owner->start_ea == entry )
          break;
        if ( owner != nullptr )
          break; // never split an existing function automatically
        if ( is_unknown(get_flags(entry)) && cfg.make_code )
        {
          auto_make_proc(entry);
          plan_ea(entry);
        }
        if ( add_func(entry, candidate.end.has_value() ? ea_t(*candidate.end) : BADADDR) )
          ++stats.functions_created;
        break;
      }

      case EvidenceActionKind::CommentProvenUnreachable:
      {
        const auto &reach = std::get<BranchReachabilityFact>(decision.payload);
        qstring text;
        text.sprnt("viy: statically proven unreachable successor 0x%a",
                   ea_t(reach.successor));
        if ( append_comment(ea_t(reach.branch), text.c_str()) )
          ++stats.comments_added;
        break;
      }
    }
    ++decision_index;
    if ( progress && (decision_index == plan.decisions.size()
                   || decision_index % size_t(256) == 0) )
    {
      EvidenceApplyProgress event;
      event.stage = EvidenceApplyProgressStage::MUTATING;
      event.records_completed = decision_index;
      event.records_total = plan.decisions.size();
      event.records_conflicted = stats.records_conflicted;
      event.records_below_policy = stats.records_below_policy;
      progress(event);
    }
  }
  if ( progress )
  {
    EvidenceApplyProgress event;
    event.stage = EvidenceApplyProgressStage::COMPLETE;
    event.records_completed = plan.decisions.size();
    event.records_total = plan.decisions.size();
    event.records_conflicted = stats.records_conflicted;
    event.records_below_policy = stats.records_below_policy;
    event.stage_boundary = true;
    progress(event);
  }
  return stats;
}

} // namespace viy
