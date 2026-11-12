//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "handover_source_release.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <utility>

#include "handover_orchestration.hpp"
#include "multiplexer.hpp"
#include "ue_registry.hpp"

namespace lte::enb::s1ap
{
namespace
{

void Log(const char *level, const std::string &message)
{
    std::cout << "[lte-enb] [" << level << "] " << message << std::endl;
}

bool SameUe(const HandoverSourceRecord &record, const EnbUeEntry &entry)
{
    return record.enbUeS1apId == entry.enbUeS1apId && record.mmeUeS1apId == entry.mmeUeS1apId &&
           record.radioUeId == entry.radioUeId;
}

bool HoldsTeid(const std::vector<uint32_t> &teids, uint32_t teid)
{
    return std::find(teids.begin(), teids.end(), teid) != teids.end();
}

} // namespace

const char *ToString(SourceReleaseRefusal refusal)
{
    switch (refusal)
    {
    case SourceReleaseRefusal::LIVE_MODE_DISABLED: return "LIVE_MODE_DISABLED";
    case SourceReleaseRefusal::NOT_A_HANDOVER_RELEASE: return "NOT_A_HANDOVER_RELEASE";
    case SourceReleaseRefusal::NO_PENDING_HANDOVER: return "NO_PENDING_HANDOVER";
    case SourceReleaseRefusal::NO_VERIFIED_DECISION: return "NO_VERIFIED_DECISION";
    case SourceReleaseRefusal::WRONG_UE_CONTEXT: return "WRONG_UE_CONTEXT";
    case SourceReleaseRefusal::IDENTITY_MISMATCH: return "IDENTITY_MISMATCH";
    case SourceReleaseRefusal::SOURCE_GENERATION_CHANGED: return "SOURCE_GENERATION_CHANGED";
    case SourceReleaseRefusal::STALE_ASSOCIATION: return "STALE_ASSOCIATION";
    case SourceReleaseRefusal::CORE_PATH_NOT_CONFIRMED: return "CORE_PATH_NOT_CONFIRMED";
    case SourceReleaseRefusal::TRANSPORT_MISMATCH: return "TRANSPORT_MISMATCH";
    case SourceReleaseRefusal::WRONG_STATE: return "WRONG_STATE";
    case SourceReleaseRefusal::RELEASE_GUARD_NOT_SATISFIED: return "RELEASE_GUARD_NOT_SATISFIED";
    case SourceReleaseRefusal::SOURCE_REFUSED: return "SOURCE_REFUSED";
    case SourceReleaseRefusal::TRANSPORT_FAILED: return "TRANSPORT_FAILED";
    case SourceReleaseRefusal::COMPLETE_MISMATCH: return "COMPLETE_MISMATCH";
    case SourceReleaseRefusal::RELEASE_NOT_CONFIRMED: return "RELEASE_NOT_CONFIRMED";
    case SourceReleaseRefusal::RECONCILIATION_FAILED: return "RECONCILIATION_FAILED";
    }
    return "UNKNOWN_SOURCE_RELEASE_REFUSAL";
}

bool IsSuccessfulHandoverReleaseCause(const UeContextReleaseCommand &command)
{
    return command.causeCategory == "radioNetwork" && command.causeValue == CauseSuccessfulHandover;
}

HandoverSourceReleaseDecision BuildHandoverSourceReleaseDecision(const CoordinationRecord &record,
                                                                 uint64_t corePathGeneration)
{
    // A decision is a statement about a UE that really moved: the transaction
    // must have been notified, its core path must have been read back as
    // installed, and the generation it names must be the one that was confirmed.
    if (!record.complete())
        throw std::logic_error("a source release decision needs a complete coordination record");
    // The decision is built for the release itself and again for a
    // reconciliation of an answer that was never observed, so it stays
    // buildable for the whole release window. It is never buildable before the
    // core update was confirmed, which is the point of the gate.
    if (record.state != OrchestrationState::CORE_PATH_UPDATED &&
        record.state != OrchestrationState::SOURCE_RELEASE_WAIT &&
        record.state != OrchestrationState::SOURCE_RELEASE_COMMAND_SENT &&
        record.state != OrchestrationState::SOURCE_RELEASE_CONFIRMED)
        throw std::logic_error("a source release decision is only built after a confirmed core path update");
    if (!record.corePath.committed || record.corePath.pathGeneration == 0)
        throw std::logic_error("no isolated core path update was confirmed for this transaction");
    if (corePathGeneration == 0 || corePathGeneration != record.corePath.pathGeneration)
        throw std::logic_error("the source release decision names another path generation than the confirmed one");

    HandoverSourceReleaseDecision decision;
    decision.transaction = record.transaction;
    decision.enbUeS1apId = record.source.enbUeS1apId;
    decision.mmeUeS1apId = record.source.mmeUeS1apId;
    decision.radioUeId = record.source.radioUeId;
    decision.accessGeneration = record.source.accessGeneration;
    decision.associationEpoch = record.sourceAssociationEpoch;
    decision.corePathGeneration = corePathGeneration;
    decision.target = record.target;
    decision.targetS1uAddress = record.corePath.request.targetS1uAddress;
    decision.defaultTeid = record.source.defaultLocalTeid;
    decision.dedicatedTeids = record.source.dedicatedLocalTeids;
    decision.m_verified = true;
    return decision;
}

bool VerifyHandoverSourceRelease(const EnbUeEntry &entry, uint64_t liveAssociationEpoch,
                                 const UeContextReleaseCommand &command,
                                 const std::vector<HandoverSourceRecord> &records,
                                 const std::vector<HandoverSourceReleaseDecision> &decisions,
                                 HandoverSourceReleaseDecision *accepted, SourceReleaseRefusalRecord *failure)
{
    auto refuse = [failure](SourceReleaseRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = SourceReleaseRefusalRecord{why, std::move(detail)};
        return false;
    };

    // The cause is a statement, not an authorization. It is still required,
    // because a release that is not stated as a handover release is the
    // ordinary one whatever else is true.
    if (!IsSuccessfulHandoverReleaseCause(command))
        return refuse(SourceReleaseRefusal::NOT_A_HANDOVER_RELEASE,
                      "the release command does not state the successful-handover cause");

    if (UeRegistry::isProvisional(entry) || entry.radioUeId == 0)
        return refuse(SourceReleaseRefusal::WRONG_UE_CONTEXT,
                      "a provisional or unidentified context is not a UE a handover moved");
    if (command.mmeUeS1apId != entry.mmeUeS1apId || entry.mmeUeS1apId == 0 || entry.enbUeS1apId == 0)
        return refuse(SourceReleaseRefusal::IDENTITY_MISMATCH,
                      "the release command names another MME UE identity than the context holds");
    if (command.enbUeS1apId.has_value() && *command.enbUeS1apId != entry.enbUeS1apId)
        return refuse(SourceReleaseRefusal::IDENTITY_MISMATCH,
                      "the release command names another eNB UE identity than the context holds");

    // The source's own record that it commanded this UE into a handover. A
    // cell that never sent a command has none, and no message can supply one.
    const HandoverSourceRecord *pending = nullptr;
    for (const auto &record : records)
    {
        if (SameUe(record, entry))
        {
            pending = &record;
            break;
        }
    }
    if (pending == nullptr)
        return refuse(SourceReleaseRefusal::NO_PENDING_HANDOVER,
                      "this cell holds no record of having commanded the UE into a handover");
    if (pending->accessGeneration != entry.accessGeneration)
        return refuse(SourceReleaseRefusal::SOURCE_GENERATION_CHANGED,
                      "the source access epoch moved since the handover was commanded");
    if (pending->associationEpoch != liveAssociationEpoch)
        return refuse(SourceReleaseRefusal::STALE_ASSOCIATION,
                      "the handover began under another source association epoch");

    // The MME's own verified decision. It exists only after the isolated SGW's
    // installed mapping was read back, so a release cannot precede the update.
    const HandoverSourceReleaseDecision *decision = nullptr;
    for (const auto &candidate : decisions)
    {
        if (candidate.transaction == pending->transaction)
        {
            decision = &candidate;
            break;
        }
    }
    if (decision == nullptr || !decision->isVerified())
        return refuse(SourceReleaseRefusal::NO_VERIFIED_DECISION,
                      "the isolated MME installed no verified release decision for this transaction");
    if (decision->corePathGeneration == 0)
        return refuse(SourceReleaseRefusal::CORE_PATH_NOT_CONFIRMED,
                      "the release decision names no confirmed core path generation");
    if (decision->associationEpoch != liveAssociationEpoch)
        return refuse(SourceReleaseRefusal::STALE_ASSOCIATION,
                      "the release decision was made under another source association epoch");
    if (decision->enbUeS1apId != entry.enbUeS1apId || decision->mmeUeS1apId != entry.mmeUeS1apId)
        return refuse(SourceReleaseRefusal::IDENTITY_MISMATCH,
                      "the release decision names another UE identity pair than the context holds");
    if (decision->radioUeId != entry.radioUeId)
        return refuse(SourceReleaseRefusal::WRONG_UE_CONTEXT,
                      "the release decision names another radio identity than the context holds");
    if (decision->accessGeneration != entry.accessGeneration)
        return refuse(SourceReleaseRefusal::SOURCE_GENERATION_CHANGED,
                      "the release decision was made for another source access epoch");
    if (decision->defaultTeid != entry.bearer.parameters().localTeid)
        return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                      "the release decision names another default-bearer transport");
    if (decision->dedicatedTeids.size() != entry.dedicatedBearers.size())
        return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                      "the release decision names another dedicated-bearer set");
    for (const auto &bearer : entry.dedicatedBearers)
        if (!HoldsTeid(decision->dedicatedTeids, bearer.parameters().localTeid))
            return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                          "the release decision omits a dedicated bearer the context holds");

    if (accepted != nullptr)
        *accepted = *decision;
    return true;
}

HandoverSourceReleaseResult ReleaseHandoverSourceContext(const HandoverSourceReleaseDecision &decision,
                                                         UeRegistry &registry, uint64_t liveAssociationEpoch,
                                                         SourceReleaseRefusalRecord *failure)
{
    auto refuse = [failure](SourceReleaseRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = SourceReleaseRefusalRecord{why, std::move(detail)};
        HandoverSourceReleaseResult result;
        result.refusal = failure != nullptr ? std::optional<SourceReleaseRefusalRecord>(*failure) : std::nullopt;
        return result;
    };

    if (!decision.isVerified())
        return refuse(SourceReleaseRefusal::NO_VERIFIED_DECISION,
                      "a handover release requires a decision the isolated MME built");
    if (decision.corePathGeneration == 0)
        return refuse(SourceReleaseRefusal::CORE_PATH_NOT_CONFIRMED,
                      "a handover release requires a confirmed core path generation");
    if (decision.associationEpoch != liveAssociationEpoch || liveAssociationEpoch == 0)
        return refuse(SourceReleaseRefusal::STALE_ASSOCIATION,
                      "the decision was made under another source association epoch");

    EnbUeEntry *entry = registry.find(decision.radioUeId);
    if (entry == nullptr || UeRegistry::isProvisional(*entry))
        return refuse(SourceReleaseRefusal::WRONG_UE_CONTEXT,
                      "this registry holds no reached UE under the decision's radio identity");
    if (entry->enbUeS1apId != decision.enbUeS1apId || entry->mmeUeS1apId != decision.mmeUeS1apId)
        return refuse(SourceReleaseRefusal::IDENTITY_MISMATCH,
                      "the context no longer carries the identity pair the decision names");
    if (entry->accessGeneration != decision.accessGeneration)
        return refuse(SourceReleaseRefusal::SOURCE_GENERATION_CHANGED,
                      "the context's access epoch moved since the decision was made");
    if (entry->bearer.parameters().localTeid != decision.defaultTeid)
        return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                      "the context's default-bearer transport is not the one the decision names");
    if (entry->dedicatedBearers.size() != decision.dedicatedTeids.size())
        return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                      "the context's dedicated-bearer set is not the one the decision names");
    for (const auto &bearer : entry->dedicatedBearers)
        if (!HoldsTeid(decision.dedicatedTeids, bearer.parameters().localTeid))
            return refuse(SourceReleaseRefusal::TRANSPORT_MISMATCH,
                          "the context holds a dedicated bearer the decision does not name");

    HandoverSourceReleaseResult result;
    result.retiredTeids = decision.dedicatedTeids;
    result.retiredTeids.push_back(decision.defaultTeid);

    // The whole cleanup, in one registry operation: the S1AP identities stop
    // resolving, every bound local TEID is retired through the normal ledger,
    // the bearer contexts are released and the entry, its radio identity and
    // its peer are erased. Nothing is retained, because nothing of this UE is
    // left on this cell.
    const uint32_t radioUeId = entry->radioUeId;
    registry.removeHandoverSource(*entry);
    result.released = true;

    Log("INFO", "Released the source S1 context of LTE UE " + std::to_string(radioUeId) +
                    " for a completed handover (EBI/MME-UE-S1AP-ID=" + std::to_string(decision.mmeUeS1apId) +
                    ", retired-teids=" + std::to_string(result.retiredTeids.size()) +
                    "); no idle-release notification was sent");
    return result;
}

// --- The isolated MME's release steps ------------------------------------

bool EnterSourceReleaseWait(HandoverCoordinator &coordinator, const HandoverTransactionId &transaction,
                            std::chrono::steady_clock::time_point now, std::chrono::milliseconds guard,
                            SourceReleaseRefusalRecord *failure)
{
    auto refuse = [failure](SourceReleaseRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = SourceReleaseRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (!coordinator.enabled())
        return refuse(SourceReleaseRefusal::LIVE_MODE_DISABLED,
                      "an isolated source release is never prepared while attached to a live EPC");
    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(SourceReleaseRefusal::WRONG_STATE, "no open coordination record names this transaction");
    if (record->state != OrchestrationState::CORE_PATH_UPDATED)
        return refuse(SourceReleaseRefusal::WRONG_STATE,
                      "the source-release guard may only be armed after a confirmed core path update");
    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::SOURCE_RELEASE_WAIT, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);
    record->sourceRelease.waitArmed = true;
    record->sourceRelease.notBefore = now + guard;
    Log("INFO", "Source-release guard armed for MME-UE-S1AP-ID=" + std::to_string(transaction.mmeUeS1apId) +
                    " with a " + std::to_string(guard.count()) + "ms bound");
    return true;
}

bool SourceReleaseGuardSatisfied(const CoordinationRecord &record, std::chrono::steady_clock::time_point now)
{
    return record.state == OrchestrationState::SOURCE_RELEASE_WAIT && record.sourceRelease.waitArmed &&
           record.corePath.committed && now >= record.sourceRelease.notBefore;
}

SourceReleaseStepOutcome SendSourceReleaseCommand(HandoverCoordinator &coordinator, EnbMultiplexer &source,
                                                  const HandoverTransactionId &transaction,
                                                  std::chrono::steady_clock::time_point now)
{
    SourceReleaseStepOutcome outcome;
    auto refuse = [&outcome](SourceReleaseRefusal why, std::string detail) {
        outcome.refusal = SourceReleaseRefusalRecord{why, std::move(detail)};
        return outcome;
    };

    if (!coordinator.enabled())
        return refuse(SourceReleaseRefusal::LIVE_MODE_DISABLED,
                      "an isolated source release is never sent while attached to a live EPC");
    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(SourceReleaseRefusal::WRONG_STATE, "no open coordination record names this transaction");
    if (record->state != OrchestrationState::SOURCE_RELEASE_WAIT)
        return refuse(SourceReleaseRefusal::WRONG_STATE,
                      "a source release is only sent while the release guard is running");
    if (!SourceReleaseGuardSatisfied(*record, now))
        return refuse(SourceReleaseRefusal::RELEASE_GUARD_NOT_SATISFIED,
                      "the bounded source-release guard has not elapsed");

    // A decision the MME can only build from a confirmed core path. It is what
    // the source will check the command against, and it names the transport the
    // release is allowed to retire.
    HandoverSourceReleaseDecision decision;
    try
    {
        decision = BuildHandoverSourceReleaseDecision(*record, record->corePath.pathGeneration);
    }
    catch (const std::exception &e)
    {
        return refuse(SourceReleaseRefusal::CORE_PATH_NOT_CONFIRMED, e.what());
    }

    std::vector<uint8_t> pdu;
    try
    {
        pdu = EncodeUeContextReleaseCommand(record->source.mmeUeS1apId, record->source.enbUeS1apId,
                                            "radioNetwork", CauseSuccessfulHandover);
    }
    catch (const std::exception &e)
    {
        return refuse(SourceReleaseRefusal::TRANSPORT_FAILED,
                      std::string("the UE Context Release Command could not be encoded: ") + e.what());
    }

    record->sourceRelease.commandPdu = pdu;
    try
    {
        source.authorizeHandoverSourceRelease(decision);
    }
    catch (const std::exception &e)
    {
        return refuse(SourceReleaseRefusal::TRANSPORT_FAILED,
                      std::string("the source could not take the release decision: ") + e.what());
    }
    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::SOURCE_RELEASE_COMMAND_SENT, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);
    record->sourceRelease.commandSent = true;

    // The production receive path of the source eNB. It decodes the bytes,
    // decides for itself whether this is a handover release, performs the
    // cleanup and answers with a real encoded Complete.
    try
    {
        source.handleS1ap(pdu.data(), pdu.size(), 0);
    }
    catch (const std::exception &e)
    {
        coordinator.advance(transaction, OrchestrationState::SOURCE_RELEASE_FAILED, nullptr);
        outcome.state = OrchestrationState::SOURCE_RELEASE_FAILED;
        return refuse(SourceReleaseRefusal::SOURCE_REFUSED, e.what());
    }

    outcome.sent = true;
    outcome.state = record->state;
    // The source answers on this same thread through the association, and the
    // relay's uplink handler is what decodes and verifies that answer. A send
    // that produced no confirmation therefore reports one honestly: it is not
    // a release.
    outcome.confirmed = record->state == OrchestrationState::SOURCE_RELEASE_CONFIRMED ||
                        record->state == OrchestrationState::ISOLATED_HANDOVER_COMPLETE;
    Log("INFO", "Isolated MME sent a UE Context Release Command (radioNetwork/successful-handover) for MME-UE-S1AP-ID=" +
                    std::to_string(record->source.mmeUeS1apId) + " to the source eNB");
    return outcome;
}

SourceReleaseStepOutcome AcceptSourceReleaseComplete(HandoverCoordinator &coordinator,
                                                     const HandoverTransactionId &transaction,
                                                     const std::vector<uint8_t> &pdu)
{
    SourceReleaseStepOutcome outcome;
    auto refuse = [&outcome](SourceReleaseRefusal why, std::string detail) {
        outcome.refusal = SourceReleaseRefusalRecord{why, std::move(detail)};
        return outcome;
    };

    if (!coordinator.enabled())
        return refuse(SourceReleaseRefusal::LIVE_MODE_DISABLED,
                      "an isolated source release is never confirmed while attached to a live EPC");
    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(SourceReleaseRefusal::WRONG_STATE, "no open coordination record names this transaction");

    UeContextReleaseComplete complete;
    try
    {
        complete = DecodeUeContextReleaseComplete(pdu.data(), pdu.size());
    }
    catch (const std::exception &e)
    {
        return refuse(SourceReleaseRefusal::TRANSPORT_FAILED,
                      std::string("the UE Context Release Complete could not be decoded: ") + e.what());
    }
    if (complete.mmeUeS1apId != record->source.mmeUeS1apId || complete.enbUeS1apId != record->source.enbUeS1apId)
        return refuse(SourceReleaseRefusal::COMPLETE_MISMATCH,
                      "the Release Complete names another UE identity pair than this transaction");

    if (record->state == OrchestrationState::SOURCE_RELEASE_CONFIRMED ||
        record->state == OrchestrationState::ISOLATED_HANDOVER_COMPLETE)
    {
        // A repeat of the same answer is the same event. It is not a second
        // release and it moves nothing.
        outcome.confirmed = true;
        outcome.state = record->state;
        return outcome;
    }
    if (record->state != OrchestrationState::SOURCE_RELEASE_COMMAND_SENT)
        return refuse(SourceReleaseRefusal::WRONG_STATE,
                      "a Release Complete may only confirm a command that was sent");

    record->sourceRelease.completePdu = pdu;
    record->sourceRelease.evidence = SourceReleaseEvidence::RELEASE_COMPLETE;

    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::SOURCE_RELEASE_CONFIRMED, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);
    if (!coordinator.advance(transaction, OrchestrationState::ISOLATED_HANDOVER_COMPLETE, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);

    outcome.confirmed = true;
    outcome.state = OrchestrationState::ISOLATED_HANDOVER_COMPLETE;
    Log("INFO", "Isolated MME verified the UE Context Release Complete of MME-UE-S1AP-ID=" +
                    std::to_string(record->source.mmeUeS1apId) +
                    "; the isolated handover is complete and no core path was created by it");
    return outcome;
}

SourceReleaseStepOutcome ReconcileSourceRelease(HandoverCoordinator &coordinator, EnbMultiplexer &source,
                                                const HandoverTransactionId &transaction,
                                                std::chrono::steady_clock::time_point now)
{
    SourceReleaseStepOutcome outcome;
    auto refuse = [&outcome](SourceReleaseRefusal why, std::string detail) {
        outcome.refusal = SourceReleaseRefusalRecord{why, std::move(detail)};
        return outcome;
    };
    (void)now;

    if (!coordinator.enabled())
        return refuse(SourceReleaseRefusal::LIVE_MODE_DISABLED,
                      "an isolated source release is never reconciled while attached to a live EPC");
    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(SourceReleaseRefusal::WRONG_STATE, "no open coordination record names this transaction");
    if (record->state != OrchestrationState::SOURCE_RELEASE_COMMAND_SENT)
        return refuse(SourceReleaseRefusal::WRONG_STATE,
                      "only a release whose answer was not observed can be reconciled");

    HandoverSourceReleaseDecision decision;
    try
    {
        decision = BuildHandoverSourceReleaseDecision(*record, record->corePath.pathGeneration);
    }
    catch (const std::exception &e)
    {
        return refuse(SourceReleaseRefusal::CORE_PATH_NOT_CONFIRMED, e.what());
    }

    // What the source's own registry says. A release that really happened left
    // no context and no live transport; nothing else counts as evidence.
    const EnbUeEntry *byMme = source.registry().findByMmeUeS1apId(record->source.mmeUeS1apId);
    const EnbUeEntry *byRadio = source.registry().find(record->source.radioUeId);
    if (byMme != nullptr || byRadio != nullptr)
    {
        if (byMme != nullptr && (byMme->enbUeS1apId != decision.enbUeS1apId ||
                                 byMme->mmeUeS1apId != decision.mmeUeS1apId))
            return refuse(SourceReleaseRefusal::RECONCILIATION_FAILED,
                          "the source holds another context under this UE identity");
        // The context is still there, so the cleanup did not happen. It is not
        // repeated here, and the transaction is not reported as confirmed.
        return refuse(SourceReleaseRefusal::RELEASE_NOT_CONFIRMED,
                      "the source still holds the context this release was to remove");
    }
    if (!source.registry().isRetiredTeid(decision.defaultTeid))
        return refuse(SourceReleaseRefusal::RECONCILIATION_FAILED,
                      "the source's default-bearer TEID is not recorded as retired");
    for (uint32_t teid : decision.dedicatedTeids)
        if (!source.registry().isRetiredTeid(teid))
            return refuse(SourceReleaseRefusal::RECONCILIATION_FAILED,
                          "a source dedicated-bearer TEID is not recorded as retired");

    record->sourceRelease.evidence = SourceReleaseEvidence::RECONCILED_REGISTRY;
    record->sourceRelease.retiredTeids = decision.dedicatedTeids;
    record->sourceRelease.retiredTeids.push_back(decision.defaultTeid);

    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::SOURCE_RELEASE_CONFIRMED, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);
    if (!coordinator.advance(transaction, OrchestrationState::ISOLATED_HANDOVER_COMPLETE, &step))
        return refuse(SourceReleaseRefusal::WRONG_STATE, step.detail);

    outcome.confirmed = true;
    outcome.reconciled = true;
    outcome.state = OrchestrationState::ISOLATED_HANDOVER_COMPLETE;
    Log("INFO", "Isolated MME reconciled the source release of MME-UE-S1AP-ID=" +
                    std::to_string(record->source.mmeUeS1apId) +
                    " from the source registry; the Release Complete was never observed and is not claimed");
    return outcome;
}

} // namespace lte::enb::s1ap
