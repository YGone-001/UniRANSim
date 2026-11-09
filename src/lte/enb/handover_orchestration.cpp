//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "handover_orchestration.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include "ue_registry.hpp"

namespace lte::enb::s1ap
{
namespace
{

// The normative comparison for a PLMN anywhere in this handover code: the
// encoded identity, never a string compare and never a substring of one.
bool SamePlmn(const Plmn &a, const Plmn &b)
{
    return EncodePlmn(a) == EncodePlmn(b);
}

bool SameCell(const EnbIdentity &a, const EnbIdentity &b)
{
    return a.enbId == b.enbId && a.tac == b.tac && SamePlmn(a.plmn, b.plmn);
}

// The 20-bit macro eNB identifier followed by the 8-bit local cell identifier,
// exactly as the target's own arrival evidence builds it. Both sides derive it
// the same way so a disagreement is detectable.
EutranCgi CgiOf(const EnbIdentity &identity)
{
    return EutranCgi{identity.plmn, (identity.enbId & 0xFFFFFU) << 8U};
}

std::array<uint8_t, 4> TeidBytes(uint32_t teid)
{
    return {static_cast<uint8_t>(teid >> 24U), static_cast<uint8_t>(teid >> 16U), static_cast<uint8_t>(teid >> 8U),
            static_cast<uint8_t>(teid)};
}

} // namespace

const char *ToString(ExecutionMode mode)
{
    return mode == ExecutionMode::ISOLATED_SIMULATOR ? "ISOLATED_SIMULATOR" : "LIVE_EPC";
}

const char *ToString(CoordinationRefusal refusal)
{
    switch (refusal)
    {
    case CoordinationRefusal::LIVE_MODE_DISABLED: return "LIVE_MODE_DISABLED";
    case CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED: return "SOURCE_PROVENANCE_NOT_ESTABLISHED";
    case CoordinationRefusal::NO_AUTHORIZED_TARGET: return "NO_AUTHORIZED_TARGET";
    case CoordinationRefusal::TARGET_NOT_PERMITTED: return "TARGET_NOT_PERMITTED";
    case CoordinationRefusal::TARGET_NOT_READY: return "TARGET_NOT_READY";
    case CoordinationRefusal::STALE_ASSOCIATION_EPOCH: return "STALE_ASSOCIATION_EPOCH";
    case CoordinationRefusal::CONFLICTING_HANDOVER_PENDING: return "CONFLICTING_HANDOVER_PENDING";
    case CoordinationRefusal::WRONG_TRANSACTION_STATE: return "WRONG_TRANSACTION_STATE";
    case CoordinationRefusal::TRANSACTION_EXPIRED: return "TRANSACTION_EXPIRED";
    case CoordinationRefusal::TRANSACTION_CANCELLED: return "TRANSACTION_CANCELLED";
    case CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD: return "INCOMPLETE_COORDINATION_RECORD";
    }
    return "UNKNOWN_COORDINATION_REFUSAL";
}

const char *ToString(OrchestrationState state)
{
    switch (state)
    {
    case OrchestrationState::SOURCE_CONNECTED: return "SOURCE_CONNECTED";
    case OrchestrationState::HANDOVER_PREPARING: return "HANDOVER_PREPARING";
    case OrchestrationState::TARGET_PREPARED: return "TARGET_PREPARED";
    case OrchestrationState::SOURCE_COMMAND_PENDING: return "SOURCE_COMMAND_PENDING";
    case OrchestrationState::UE_RELOCATION_PENDING: return "UE_RELOCATION_PENDING";
    case OrchestrationState::TARGET_ARRIVAL_CONFIRMED: return "TARGET_ARRIVAL_CONFIRMED";
    case OrchestrationState::HANDOVER_NOTIFY_SENT: return "HANDOVER_NOTIFY_SENT";
    case OrchestrationState::AWAITING_CORE_PATH_UPDATE: return "AWAITING_CORE_PATH_UPDATE";
    case OrchestrationState::PREPARATION_FAILED: return "PREPARATION_FAILED";
    case OrchestrationState::EXECUTION_FAILED: return "EXECUTION_FAILED";
    case OrchestrationState::CANCELLED: return "CANCELLED";
    }
    return "UNKNOWN_ORCHESTRATION_STATE";
}

bool IsTerminal(OrchestrationState state)
{
    return state == OrchestrationState::AWAITING_CORE_PATH_UPDATE || state == OrchestrationState::PREPARATION_FAILED ||
           state == OrchestrationState::EXECUTION_FAILED || state == OrchestrationState::CANCELLED;
}

std::optional<OrchestrationState> ApplyOrchestrationEvent(OrchestrationState state, OrchestrationState event)
{
    // A repeat of the state a transaction is already in changes nothing. This
    // is what makes a duplicated event idempotent rather than a second step.
    if (event == state)
        return state;
    // A terminal transaction never moves again. Reopening one would let a
    // cancelled or failed handover start authorizing things after the fact.
    if (IsTerminal(state))
        return std::nullopt;
    // The three failure and cancellation outcomes are reachable from every
    // non-terminal state: an attempt that cannot continue is refused and
    // recorded, not left half-alive waiting for an event that will not come.
    if (event == OrchestrationState::PREPARATION_FAILED || event == OrchestrationState::EXECUTION_FAILED ||
        event == OrchestrationState::CANCELLED)
        return event;

    switch (state)
    {
    case OrchestrationState::SOURCE_CONNECTED:
        return event == OrchestrationState::HANDOVER_PREPARING ? std::optional<OrchestrationState>(event) : std::nullopt;
    case OrchestrationState::HANDOVER_PREPARING:
        return event == OrchestrationState::TARGET_PREPARED ? std::optional<OrchestrationState>(event) : std::nullopt;
    case OrchestrationState::TARGET_PREPARED:
        return event == OrchestrationState::SOURCE_COMMAND_PENDING ? std::optional<OrchestrationState>(event)
                                                                   : std::nullopt;
    case OrchestrationState::SOURCE_COMMAND_PENDING:
        return event == OrchestrationState::UE_RELOCATION_PENDING ? std::optional<OrchestrationState>(event)
                                                                  : std::nullopt;
    case OrchestrationState::UE_RELOCATION_PENDING:
        return event == OrchestrationState::TARGET_ARRIVAL_CONFIRMED ? std::optional<OrchestrationState>(event)
                                                                     : std::nullopt;
    case OrchestrationState::TARGET_ARRIVAL_CONFIRMED:
        return event == OrchestrationState::HANDOVER_NOTIFY_SENT ? std::optional<OrchestrationState>(event) : std::nullopt;
    case OrchestrationState::HANDOVER_NOTIFY_SENT:
        // The last step this phase takes. It is deliberately not a completion:
        // the MME-controlled downlink bearer path update and the source context
        // release are later work and nothing here performs or reports them.
        return event == OrchestrationState::AWAITING_CORE_PATH_UPDATE ? std::optional<OrchestrationState>(event)
                                                                      : std::nullopt;
    default:
        break;
    }
    return std::nullopt;
}

SourceSession ExtractSourceSession(const EnbUeEntry &entry, const EnbIdentity &sourceCell, EutranCgi sourceCgi,
                                   uint64_t associationEpoch)
{
    // This function is the whole of the source-provenance contract. It reads a
    // live registry entry and nothing else, and every fact it cannot establish
    // is a refusal rather than a blank field: a target treats a `SourceSession`
    // as verified, so a partial one is worse than none.
    if (sourceCell.enbId == 0 || sourceCell.tac == 0 ||
        (sourceCell.plmn.mcc.empty() && sourceCell.plmn.mnc.empty()))
        throw SourceProvenanceError("the source cell identity is not a complete Global eNB ID");
    if (!SamePlmn(sourceCgi.plmn, sourceCell.plmn) || sourceCgi.cellId != CgiOf(sourceCell).cellId)
        throw SourceProvenanceError("the source E-UTRAN CGI does not agree with the source cell identity");
    if (associationEpoch == 0)
        throw SourceProvenanceError("the source S1-MME association epoch is not established");
    // A provisional target context is a UE that has not arrived. It has no
    // radio identity and is not a source for anything.
    if (UeRegistry::isProvisional(entry))
        throw SourceProvenanceError("the source entry is a provisional context and serves no UE");
    if (entry.radioUeId == 0)
        throw SourceProvenanceError("the source entry has no registered simulated radio identity");
    if (entry.peer == InetAddress{})
        throw SourceProvenanceError("the source entry has no radio endpoint");
    if (!entry.s1Active())
        throw SourceProvenanceError("the source UE holds no active S1 connection");
    if (entry.mmeUeS1apId == 0 || entry.enbUeS1apId == 0)
        throw SourceProvenanceError("the source S1AP identity pair is incomplete");
    // The access generation is recorded whatever it is. Zero is the first
    // access epoch of a cell — the one an Attach opens and no generation-bound
    // message is sent on — and refusing it would refuse every source whose UE
    // has never been released and reselected.
    if (!entry.bearer.signalingEstablished() || entry.bearer.parameters().erabId == 0)
        throw SourceProvenanceError("the source holds no default EPS bearer");
    if (entry.bearer.ueIpv4() == std::array<uint8_t, 4>{})
        throw SourceProvenanceError("the source EPS session has no network-confirmed PDN address");
    if (!entry.ueAmbr.has_value())
        throw SourceProvenanceError("the source session has no negotiated UE aggregate maximum bitrate");
    // Every dedicated bearer names the default bearer of its own PDN
    // connection. A dedicated bearer that does not is not part of a session
    // anyone can describe, so the whole record is refused rather than
    // transmitted with an unexplained link in it.
    const uint8_t defaultEbi = entry.bearer.parameters().erabId;
    for (const auto &bearer : entry.dedicatedBearers)
    {
        if (!bearer.signalingEstablished() || bearer.parameters().erabId == 0)
            throw SourceProvenanceError("a dedicated EPS bearer is not established");
        if (bearer.parameters().linkedDefaultEbi != defaultEbi)
            throw SourceProvenanceError("a dedicated EPS bearer is not linked to the default bearer of the session");
    }

    SourceSession session;
    session.sourceCell = sourceCell;
    session.sourceCgi = sourceCgi;
    session.associationEpoch = associationEpoch;
    session.mmeUeS1apId = entry.mmeUeS1apId;
    session.enbUeS1apId = entry.enbUeS1apId;
    session.radioUeId = entry.radioUeId;
    session.radioPeer = entry.peer;
    session.defaultEbi = defaultEbi;
    session.ueIpv4 = entry.bearer.ueIpv4();
    session.accessGeneration = entry.accessGeneration;
    session.ueAmbr = *entry.ueAmbr;

    // Roles come from the registry's own classification of each bearer, which
    // is the network's statement of the EPS session. Neither QCI nor the order
    // an E-RAB list happens to be in decides anything here, so a deliberately
    // reordered list of E-RABs yields exactly the same roles.
    //
    // The output order is canonical — the default bearer first, then the
    // dedicated ones by ascending E-RAB identity — so two records of the same
    // session compare equal whatever order the registry holds them in.
    auto add = [&](const BearerContext &bearer, BearerRole role, std::optional<uint8_t> linked) {
        const auto &p = bearer.parameters();
        BearerRoleBinding binding;
        binding.erabId = p.erabId;
        binding.role = role;
        binding.linkedDefaultErabId = linked;
        // QCI and ARP are read together from the one bearer context, so the
        // NAS and S1AP statements of a bearer's QoS cannot come apart here.
        binding.qci = p.qci;
        binding.priorityLevel = p.qos.priorityLevel;
        binding.preemptionCapability = p.qos.preemptionCapability;
        binding.preemptionVulnerability = p.qos.preemptionVulnerability;
        session.roles.push_back(binding);

        ErabToBeSetupItemHoReq erab;
        erab.erabId = p.erabId;
        erab.sgwAddress = p.sgwAddress;
        erab.sgwTeid = TeidBytes(p.sgwTeid);
        erab.qos = p.qos;
        session.erabs.push_back(erab);
    };

    add(entry.bearer, BearerRole::DEFAULT, std::nullopt);
    std::vector<const BearerContext *> dedicated;
    dedicated.reserve(entry.dedicatedBearers.size());
    for (const auto &bearer : entry.dedicatedBearers)
        dedicated.push_back(&bearer);
    std::sort(dedicated.begin(), dedicated.end(),
              [](const BearerContext *a, const BearerContext *b) {
                  return a->parameters().erabId < b->parameters().erabId;
              });
    for (const BearerContext *bearer : dedicated)
        add(*bearer, BearerRole::DEDICATED, bearer->parameters().linkedDefaultEbi);

    session.verified = true;
    return session;
}

bool CoordinationRecord::complete() const
{
    // All nine bindings. A record with a hole in it authorizes nothing at all,
    // which is why every step asks this before it acts.
    return source.verified && source.mmeUeS1apId != 0 && source.enbUeS1apId != 0 && source.radioUeId != 0 &&
           source.associationEpoch != 0 && target.enbId != 0 && target.tac != 0 && transaction.mmeUeS1apId != 0 &&
           transaction.associationEpoch != 0 && mmeUeS1apId != 0 && arrivalToken != 0 && sourceAssociationEpoch != 0 &&
           targetAssociationEpoch != 0 && targetRadioEndpoint != InetAddress{} && pdnAddress != std::array<uint8_t, 4>{} &&
           !cancelled;
}

bool CoordinationRecord::completeForPreparation() const
{
    // Everything a preparation hop needs to build a Handover Request, and
    // nothing that hop produces. The arrival token and the preparation's own
    // transaction identity are deliberately absent: binding them is what the
    // hop does, so a record that already carried one could not be the record a
    // preparation is being made for. Everything after the preparation still
    // asks for the whole record.
    return source.verified && source.mmeUeS1apId != 0 && source.enbUeS1apId != 0 && source.radioUeId != 0 &&
           source.associationEpoch != 0 && target.enbId != 0 && target.tac != 0 && transaction.mmeUeS1apId != 0 &&
           transaction.associationEpoch != 0 && mmeUeS1apId != 0 && sourceAssociationEpoch != 0 &&
           targetAssociationEpoch != 0 && targetRadioEndpoint != InetAddress{} &&
           pdnAddress != std::array<uint8_t, 4>{} && !cancelled;
}

HandoverCoordinator::HandoverCoordinator(ExecutionMode mode) : m_mode(mode) {}

bool HandoverCoordinator::openTransaction(const SourceSession &source, const HandoverTargetBinding &target,
                                          uint32_t mmeUeS1apId, uint64_t sourceAssociationEpoch,
                                          uint64_t targetAssociationEpoch, std::chrono::steady_clock::duration lifetime,
                                          CoordinationRecord *record, CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };

    // The mode gate is first and unconditional. A process attached to a real
    // EPC never opens a simulated coordination transaction, and nothing about a
    // message it could not decode moves it into the simulator mode.
    if (!enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED,
                      "a handover coordination transaction is refused while attached to a live EPC");
    if (!source.isVerified())
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the source session is not one ExtractSourceSession verified");
    if (mmeUeS1apId == 0)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the coordination record must name the MME's identity for this UE");
    if (mmeUeS1apId != source.mmeUeS1apId)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the coordination record names another MME UE identity than the source session holds");
    if (sourceAssociationEpoch == 0 || sourceAssociationEpoch != source.associationEpoch)
        return refuse(CoordinationRefusal::STALE_ASSOCIATION_EPOCH,
                      "the source association epoch is not the one this session was established under");
    if (targetAssociationEpoch == 0 || targetAssociationEpoch != target.associationEpoch)
        return refuse(CoordinationRefusal::STALE_ASSOCIATION_EPOCH,
                      "the target association epoch is not the one the target binding names");
    if (!SameCell(target.permittedSource, source.sourceCell))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "this target is not permitted for the source cell asking for it");
    if (!target.ready)
        return refuse(CoordinationRefusal::TARGET_NOT_READY, "the named target is not ready to be selected");
    if (SameCell(target.identity, source.sourceCell))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED, "the source cell cannot hand a UE over to itself");
    const auto existing = m_records.find(mmeUeS1apId);
    if (existing != m_records.end())
    {
        const bool dead =
            existing->second.cancelled || existing->second.expiresAt <= std::chrono::steady_clock::now();
        if (!dead)
            return refuse(CoordinationRefusal::CONFLICTING_HANDOVER_PENDING,
                          "a handover transaction for this UE session is already open");
        // A record that is already cancelled or expired authorizes nothing and
        // is never revived, so the next attempt is a fresh transaction in its
        // place rather than a continuation of the dead one. That also keeps this
        // table bounded by the number of UE sessions rather than by the number
        // of handovers ever attempted.
        m_records.erase(existing);
    }
    // The provisional sequence is spent once and never reissued, exactly as the
    // S1-U TEID allocator behaves. Rolling over would hand out a transaction
    // identity an earlier record already carried, and a caller holding the
    // earlier one would then address this record by mistake.
    if (m_sequence == std::numeric_limits<uint32_t>::max())
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "the coordinator has exhausted its transaction sequence and will not reissue one");

    CoordinationRecord opened;
    opened.transaction = HandoverTransactionId{mmeUeS1apId, sourceAssociationEpoch, ++m_sequence};
    opened.source = source;
    opened.target = target.identity;
    opened.mmeUeS1apId = mmeUeS1apId;
    opened.sourceAssociationEpoch = sourceAssociationEpoch;
    opened.targetAssociationEpoch = targetAssociationEpoch;
    opened.targetRadioEndpoint = target.radioEndpoint;
    opened.pdnAddress = source.ueIpv4;
    opened.expiresAt = std::chrono::steady_clock::now() + lifetime;
    opened.state = OrchestrationState::SOURCE_CONNECTED;

    if (record != nullptr)
        *record = opened;
    m_records.emplace(mmeUeS1apId, std::move(opened));
    return true;
}

bool HandoverCoordinator::bindPreparation(const HandoverTransactionId &transaction, uint32_t arrivalToken,
                                          CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (!enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED, "coordination is refused while attached to a live EPC");

    // The record is addressed by the MME's identity for the UE, which is the
    // one key both halves of the binding already agree on and the key this
    // table is indexed by. It cannot be addressed by the whole transaction
    // identifier, because the coordinator's provisional identifier carries the
    // source association epoch and the target preparation's carries its own:
    // the two never compare equal, so a lookup by the full identifier would
    // never find the record that is about to be rebound to the preparation's.
    const auto existing = m_records.find(transaction.mmeUeS1apId);
    if (existing == m_records.end())
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "no open coordination record names this UE session");
    CoordinationRecord *found = &existing->second;
    if (found->cancelled)
        return refuse(CoordinationRefusal::TRANSACTION_CANCELLED, "the coordination record has been cancelled");
    if (found->expiresAt <= std::chrono::steady_clock::now())
        return refuse(CoordinationRefusal::TRANSACTION_EXPIRED, "the coordination record has expired");
    if (arrivalToken == 0)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the preparation must bind a non-zero arrival token");
    if (transaction.associationEpoch != found->targetAssociationEpoch)
        return refuse(CoordinationRefusal::STALE_ASSOCIATION_EPOCH,
                      "the preparation was made under another target association epoch");
    // A record that has already been bound to a preparation is that
    // preparation. A repeat under the same identity is one transaction and
    // binds nothing a second time; one that disagrees with it is a conflicting
    // duplicate and is refused rather than allowed to re-point a live record at
    // another preparation.
    if (found->arrivalToken != 0 && !(found->transaction == transaction))
        return refuse(CoordinationRefusal::CONFLICTING_HANDOVER_PENDING,
                      "this record is already bound to another preparation");
    if (found->arrivalToken != 0 && found->arrivalToken != arrivalToken)
        return refuse(CoordinationRefusal::CONFLICTING_HANDOVER_PENDING,
                      "this record is already bound to another arrival token");

    // The target's own transaction identity replaces the coordinator's
    // provisional one, so every later step addresses the record by the
    // identifier the rest of the system is holding.
    found->transaction = transaction;
    found->arrivalToken = arrivalToken;
    return true;
}

bool HandoverCoordinator::advance(const HandoverTransactionId &transaction, OrchestrationState event,
                                  CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (!enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED, "coordination is refused while attached to a live EPC");

    CoordinationRecord *found = findMutable(transaction);
    if (found == nullptr)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE, "no open coordination record names this transaction");
    if (found->cancelled)
        return refuse(CoordinationRefusal::TRANSACTION_CANCELLED, "the coordination record has been cancelled");
    if (found->expiresAt <= std::chrono::steady_clock::now())
        return refuse(CoordinationRefusal::TRANSACTION_EXPIRED, "the coordination record has expired");
    if (event != OrchestrationState::CANCELLED && event != OrchestrationState::PREPARATION_FAILED &&
        event != OrchestrationState::EXECUTION_FAILED)
    {
        // Preparing is the one step that completes the record: it is what binds
        // the arrival token and the target's transaction identity, so it is the
        // one step that may act on a record without them. Every step after it
        // needs the record whole, and a failure or cancellation may name a
        // record in any condition at all.
        const bool needsWholeRecord = event != OrchestrationState::HANDOVER_PREPARING;
        if (needsWholeRecord ? !found->complete() : !found->completeForPreparation())
            return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                          "the coordination record does not bind everything a handover step needs");
    }

    const auto next = ApplyOrchestrationEvent(found->state, event);
    if (!next.has_value())
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      std::string("a transaction that is ") + ToString(found->state) + " cannot become " +
                          ToString(event));
    found->state = *next;
    return true;
}

CoordinationRecord *HandoverCoordinator::findMutable(const HandoverTransactionId &transaction)
{
    // The raw lookup. It is what the mutating entry points use so they can name
    // the exact reason a record is unusable instead of reporting every dead
    // record as an absent one.
    for (auto &item : m_records)
    {
        if (item.second.transaction == transaction)
            return &item.second;
    }
    return nullptr;
}

const CoordinationRecord *HandoverCoordinator::find(const HandoverTransactionId &transaction) const
{
    const CoordinationRecord *record = const_cast<HandoverCoordinator *>(this)->findMutable(transaction);
    // A cancelled or expired record authorizes nothing and is never handed out
    // as if it did, exactly as a retired TEID is never revived.
    if (record == nullptr || record->cancelled || record->expiresAt <= std::chrono::steady_clock::now())
        return nullptr;
    return record;
}

const CoordinationRecord *HandoverCoordinator::findByMmeUeS1apId(uint32_t mmeUeS1apId) const
{
    const auto it = m_records.find(mmeUeS1apId);
    if (it == m_records.end())
        return nullptr;
    const CoordinationRecord &record = it->second;
    if (record.cancelled || record.expiresAt <= std::chrono::steady_clock::now())
        return nullptr;
    return &record;
}

bool HandoverCoordinator::cancel(const HandoverTransactionId &transaction, CoordinationRefusalRecord *failure)
{
    if (!enabled())
    {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{CoordinationRefusal::LIVE_MODE_DISABLED,
                                                 "coordination is refused while attached to a live EPC"};
        return false;
    }
    for (auto &item : m_records)
    {
        CoordinationRecord &record = item.second;
        if (!(record.transaction == transaction))
            continue;
        // Idempotent. A record is cancelled once and stays cancelled; there is
        // no path that withdraws the cancellation and no path that revives it.
        record.cancelled = true;
        if (!IsTerminal(record.state))
            record.state = OrchestrationState::CANCELLED;
        return true;
    }
    if (failure != nullptr)
        *failure = CoordinationRefusalRecord{CoordinationRefusal::WRONG_TRANSACTION_STATE,
                                             "no open coordination record names this transaction"};
    return false;
}

size_t HandoverCoordinator::expireDue(std::chrono::steady_clock::time_point now)
{
    size_t moved = 0;
    for (auto &item : m_records)
    {
        CoordinationRecord &record = item.second;
        if (record.cancelled || IsTerminal(record.state) || record.expiresAt > now)
            continue;
        // Expiry stops a record from authorizing anything. It is not itself an
        // authorization, and it never releases anything on either eNB.
        record.cancelled = true;
        record.state = OrchestrationState::CANCELLED;
        ++moved;
    }
    return moved;
}

bool HandoverCoordinator::SelectTarget(const SourceSession &source, const std::vector<HandoverTargetBinding> &inventory,
                                       uint32_t targetEnbId, const HandoverTargetBinding *&selected,
                                       CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };
    selected = nullptr;
    if (!source.isVerified())
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the source session is not one ExtractSourceSession verified");
    // Selection names a target explicitly. There is no discovery here: nothing
    // is scanned, no address a UE supplied is consulted, and no target is taken
    // because it happened to be first.
    if (targetEnbId == 0)
        return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET,
                      "a target must be named explicitly; none is selected by default");

    for (const HandoverTargetBinding &candidate : inventory)
    {
        if (candidate.identity.enbId != targetEnbId || !SamePlmn(candidate.identity.plmn, source.sourceCell.plmn))
            continue;
        if (!SameCell(candidate.permittedSource, source.sourceCell))
            return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                          "the named target is not permitted for the source cell asking for it");
        if (SameCell(candidate.identity, source.sourceCell))
            return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED, "the source cell cannot hand a UE over to itself");
        if (!candidate.ready)
            return refuse(CoordinationRefusal::TARGET_NOT_READY, "the named target is not ready to be selected");
        // The binding must state a coherent cell: an identity that names two
        // networks is refused rather than half-used.
        if (!SamePlmn(candidate.cgi.plmn, candidate.identity.plmn) ||
            candidate.cgi.cellId != CgiOf(candidate.identity).cellId)
            return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET,
                          "the named target's E-UTRAN CGI does not agree with its identity");
        if (!SamePlmn(candidate.tai.plmn, candidate.identity.plmn) || candidate.tai.tac != candidate.identity.tac)
            return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET,
                          "the named target's tracking area identity does not agree with its identity");
        if (candidate.radioEndpoint == InetAddress{} || candidate.s1uAddress == std::array<uint8_t, 4>{} ||
            candidate.associationEpoch == 0)
            return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET,
                          "the named target binding is incomplete and cannot direct a UE anywhere");
        selected = &candidate;
        return true;
    }
    return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET,
                  "no configured target names the eNB this source asked for");
}

// --- Source-side Handover Command handling --------------------------------

const char *ToString(CommandRefusal refusal)
{
    switch (refusal)
    {
    case CommandRefusal::LIVE_MODE_DISABLED: return "LIVE_MODE_DISABLED";
    case CommandRefusal::NOT_A_REACHED_UE: return "NOT_A_REACHED_UE";
    case CommandRefusal::UE_NOT_CONNECTED: return "UE_NOT_CONNECTED";
    case CommandRefusal::WRONG_COMMAND_UE_IDENTITY: return "WRONG_COMMAND_UE_IDENTITY";
    case CommandRefusal::S1AP_IDENTITY_CHANGED: return "S1AP_IDENTITY_CHANGED";
    case CommandRefusal::SESSION_CHANGED: return "SESSION_CHANGED";
    case CommandRefusal::ASSOCIATION_EPOCH_CHANGED: return "ASSOCIATION_EPOCH_CHANGED";
    case CommandRefusal::TARGET_NOT_APPROVED: return "TARGET_NOT_APPROVED";
    case CommandRefusal::ARRIVAL_TOKEN_MISSING: return "ARRIVAL_TOKEN_MISSING";
    case CommandRefusal::NO_COMMITTED_RESOURCES: return "NO_COMMITTED_RESOURCES";
    case CommandRefusal::TARGET_ENDPOINT_UNAVAILABLE: return "TARGET_ENDPOINT_UNAVAILABLE";
    case CommandRefusal::HANDOVER_ALREADY_EXECUTING: return "HANDOVER_ALREADY_EXECUTING";
    case CommandRefusal::WRONG_TRANSACTION_STATE: return "WRONG_TRANSACTION_STATE";
    case CommandRefusal::TRANSACTION_EXPIRED: return "TRANSACTION_EXPIRED";
    case CommandRefusal::TRANSACTION_CANCELLED: return "TRANSACTION_CANCELLED";
    case CommandRefusal::INCOMPLETE_COORDINATION_RECORD: return "INCOMPLETE_COORDINATION_RECORD";
    }
    return "UNKNOWN_COMMAND_REFUSAL";
}

CommandDelivery DeliverHandoverCommand(EnbMultiplexer &source, EnbUeEntry &entry, HandoverCoordinator &coordinator,
                                       const HandoverTransactionId &transaction, const HandoverCommand &command,
                                       const HandoverTargetBinding &targetBinding)
{
    CommandDelivery outcome;
    auto refuse = [&](CommandRefusal why, std::string detail) {
        CoordinationRefusalRecord record;
        // The refusal codes the coordination layer already owns are reused so a
        // caller reports one vocabulary; the rest are named in the detail, which
        // is where the source-side reasons live.
        switch (why)
        {
        case CommandRefusal::LIVE_MODE_DISABLED:
            record.refusal = CoordinationRefusal::LIVE_MODE_DISABLED;
            break;
        case CommandRefusal::ASSOCIATION_EPOCH_CHANGED:
            record.refusal = CoordinationRefusal::STALE_ASSOCIATION_EPOCH;
            break;
        case CommandRefusal::TARGET_NOT_APPROVED:
            record.refusal = CoordinationRefusal::TARGET_NOT_PERMITTED;
            break;
        case CommandRefusal::TARGET_ENDPOINT_UNAVAILABLE:
            record.refusal = CoordinationRefusal::TARGET_NOT_READY;
            break;
        case CommandRefusal::HANDOVER_ALREADY_EXECUTING:
            record.refusal = CoordinationRefusal::CONFLICTING_HANDOVER_PENDING;
            break;
        case CommandRefusal::TRANSACTION_EXPIRED:
            record.refusal = CoordinationRefusal::TRANSACTION_EXPIRED;
            break;
        case CommandRefusal::TRANSACTION_CANCELLED:
            record.refusal = CoordinationRefusal::TRANSACTION_CANCELLED;
            break;
        case CommandRefusal::WRONG_TRANSACTION_STATE:
            record.refusal = CoordinationRefusal::WRONG_TRANSACTION_STATE;
            break;
        default: record.refusal = CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD; break;
        }
        record.detail = std::string(ToString(why)) + ": " + std::move(detail);
        outcome.refusal = std::move(record);
        return outcome;
    };

    if (!coordinator.enabled())
        return refuse(CommandRefusal::LIVE_MODE_DISABLED,
                      "a simulated handover command is never produced while attached to a live EPC");

    // A command goes to a reached UE this eNB already serves. A provisional
    // target context, and an entry with no simulated radio identity, are not
    // that and are never commanded.
    if (entry.radioUeId == 0 || UeRegistry::isProvisional(entry))
        return refuse(CommandRefusal::NOT_A_REACHED_UE,
                      "no reached UE is registered on the source entry this command names");
    if (!entry.s1Active() || !entry.bearer.signalingEstablished())
        return refuse(CommandRefusal::UE_NOT_CONNECTED, "the source UE holds no S1 connection that could carry a move");

    CoordinationRecord *record = coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(CommandRefusal::WRONG_TRANSACTION_STATE,
                      "no open coordination record names this transaction");
    if (record->cancelled)
        return refuse(CommandRefusal::TRANSACTION_CANCELLED, "the coordination record has been cancelled");
    if (record->expiresAt <= std::chrono::steady_clock::now())
        return refuse(CommandRefusal::TRANSACTION_EXPIRED, "the coordination record has expired");

    // The command must name exactly the UE the record is about and exactly the
    // UE this entry serves. Neither agreement is taken on the strength of the
    // message restating it.
    if (command.mmeUeS1apId != record->mmeUeS1apId || command.enbUeS1apId != record->source.enbUeS1apId)
        return refuse(CommandRefusal::WRONG_COMMAND_UE_IDENTITY,
                      "the Handover Command names a different UE than the source is serving");
    if (entry.mmeUeS1apId != record->mmeUeS1apId || entry.enbUeS1apId != record->source.enbUeS1apId)
        return refuse(CommandRefusal::S1AP_IDENTITY_CHANGED,
                      "the source entry no longer holds the S1AP identifiers the preparation was made for");
    if (entry.accessGeneration != record->source.accessGeneration)
        return refuse(CommandRefusal::SESSION_CHANGED,
                      "the source access epoch moved on since this preparation was made");
    if (source.associationEpoch() != record->sourceAssociationEpoch)
        return refuse(CommandRefusal::ASSOCIATION_EPOCH_CHANGED,
                      "the source S1-MME association is no longer the one this record names");

    // The target must still be the approved one, still permitted for this
    // source, and still able to receive a UE on a real radio endpoint.
    if (!SameCell(targetBinding.identity, record->target) ||
        !SameCell(targetBinding.permittedSource, record->source.sourceCell))
        return refuse(CommandRefusal::TARGET_NOT_APPROVED, "the target is no longer the approved one for this source");
    if (record->targetRadioEndpoint == InetAddress{})
        return refuse(CommandRefusal::TARGET_ENDPOINT_UNAVAILABLE, "the target has no radio endpoint to redirect to");
    if (record->arrivalToken == 0)
        return refuse(CommandRefusal::ARRIVAL_TOKEN_MISSING,
                      "the record binds no arrival token, so the move cannot be correlated at the target");
    if (!record->complete())
        return refuse(CommandRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the coordination record does not bind what a move needs");

    // What the preparation has actually reached. Before a commit there are no
    // target resources behind this transaction; after the command has gone out
    // the UE is already executing one and a second is refused rather than
    // stacked onto a half-finished move.
    if (record->state == OrchestrationState::SOURCE_CONNECTED ||
        record->state == OrchestrationState::HANDOVER_PREPARING)
        return refuse(CommandRefusal::NO_COMMITTED_RESOURCES,
                      "the target has established no committed resources for this transaction");
    if (record->state != OrchestrationState::TARGET_PREPARED)
        return refuse(CommandRefusal::HANDOVER_ALREADY_EXECUTING,
                      "the source UE is already executing a connected-mode handover");

    // The frame is built entirely from the coordination record: the authorized
    // target identity, the arrival token, the MME's identity for this UE and
    // the network-confirmed PDN address. Nothing is taken from the Handover
    // Command beyond the identity pair checked above, and no address a frame
    // names is ever used to direct the UE.
    lte::ue::link::SimulatedHandoverCommand frame;
    frame.targetPlmn = EncodePlmn(record->target.plmn);
    frame.targetEnbId = record->target.enbId;
    frame.targetTac = record->target.tac;
    frame.arrivalToken = record->arrivalToken;
    frame.mmeUeS1apId = record->mmeUeS1apId;
    frame.ueIpv4 = record->pdnAddress;
    outcome.command = frame;

    CoordinationRefusalRecord step;
    if (!coordinator.advance(transaction, OrchestrationState::SOURCE_COMMAND_PENDING, &step))
        return refuse(CommandRefusal::WRONG_TRANSACTION_STATE, step.detail);

    // Over the source's existing production radio sender, and nothing else. A
    // throw here leaves the transaction where this step put it and is reported
    // as a refusal rather than swallowed into a success.
    try
    {
        source.sendHandoverCommand(entry, frame);
    }
    catch (const std::exception &e)
    {
        return refuse(CommandRefusal::WRONG_TRANSACTION_STATE,
                      std::string("the source could not hand the command to its UE: ") + e.what());
    }

    // Two events, both about the command that was just delivered. The frame is
    // the one that redirects the UE's radio transport, so the relocation is
    // pending from the moment it reaches the UE; what proves the redirect
    // happened is the arrival at the target, which is a separate event of its
    // own. Nothing here reports a handover as finished.
    if (!coordinator.advance(transaction, OrchestrationState::UE_RELOCATION_PENDING, &step))
        return refuse(CommandRefusal::WRONG_TRANSACTION_STATE, step.detail);

    outcome.delivered = true;
    return outcome;
}

// --- Simulator-only handover containers ------------------------------------

TransparentContainer BuildSimulatedSourceToTarget(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                  const std::array<uint8_t, 4> &ueIpv4)
{
    // A container that names no session is refused rather than built: an empty
    // one is refused by the codec anyway, and a labelled one that names nobody
    // is not a better answer.
    if (mmeUeS1apId == 0 || enbUeS1apId == 0 || ueIpv4 == std::array<uint8_t, 4>{})
        throw std::invalid_argument("a simulated handover container must name the session it belongs to");

    TransparentContainer container;
    container.reserve(SimulatedContainerLabel.size() + 12);
    container.insert(container.end(), SimulatedContainerLabel.begin(), SimulatedContainerLabel.end());
    // The session identity in network order and the PDN address, and nothing
    // else. An opaque container is not authority to invent security or RRC
    // content, so there is none in here.
    for (int shift = 24; shift >= 0; shift -= 8)
        container.push_back(static_cast<uint8_t>(mmeUeS1apId >> shift));
    for (int shift = 24; shift >= 0; shift -= 8)
        container.push_back(static_cast<uint8_t>(enbUeS1apId >> shift));
    container.insert(container.end(), ueIpv4.begin(), ueIpv4.end());
    return container;
}

bool IsSimulatedContainer(const TransparentContainer &container)
{
    return container.size() >= SimulatedContainerLabel.size() &&
           std::equal(SimulatedContainerLabel.begin(), SimulatedContainerLabel.end(), container.begin());
}

// --- Source-side generation -----------------------------------------------

bool BuildHandoverRequired(const SourceSession &session, const EnbIdentity &target, const std::string &causeCategory,
                           int causeValue, HandoverRequired *required, CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };

    if (!session.isVerified())
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "a Handover Required may only be built from a verified source session");
    if (target.enbId == 0 || target.tac == 0)
        return refuse(CoordinationRefusal::NO_AUTHORIZED_TARGET, "the named target is not a complete cell identity");
    if (SameCell(target, session.sourceCell))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED, "the source cell cannot hand a UE over to itself");
    if (session.mmeUeS1apId == 0 || session.enbUeS1apId == 0)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the source S1AP identity pair is incomplete");
    // The cause is the source's own reason for asking. It is a decision, so it
    // is stated by the caller and never filled in here.
    if (causeCategory.empty() || causeValue < 0)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "a Handover Required must state the source's own reason for the move");

    HandoverRequired message;
    message.mmeUeS1apId = session.mmeUeS1apId;
    message.enbUeS1apId = session.enbUeS1apId;
    message.handoverType = HandoverType::INTRA_LTE;
    message.causeCategory = causeCategory;
    message.causeValue = causeValue;
    message.target = target;
    // Indirect GTP-U forwarding is not implemented in this repository. A flag
    // that claimed a direct forwarding path existed would promise the source a
    // transport this system does not have.
    message.directForwardingPathAvailable = false;
    message.sourceToTarget = BuildSimulatedSourceToTarget(session.mmeUeS1apId, session.enbUeS1apId, session.ueIpv4);

    if (required != nullptr)
        *required = message;
    return true;
}

// --- The isolated MME simulator -------------------------------------------

IsolatedMmeRelay::IsolatedMmeRelay(HandoverCoordinator &coordinator) : m_coordinator(coordinator) {}

IsolatedMmeRelay::Endpoint::Endpoint(IsolatedMmeRelay &relay, bool targetSide)
    : m_relay(relay), m_targetSide(targetSide)
{
}

void IsolatedMmeRelay::Endpoint::sendS1ap(uint16_t /*stream*/, const std::vector<uint8_t> &pdu)
{
    // Real bytes from a real sender. They are recorded and then given to the
    // relay to be read with the production codec, exactly as a real MME would
    // read what arrives on its association.
    m_received.push_back(pdu);
    CoordinationRefusalRecord refusal;
    m_relay.onUplink(m_targetSide, pdu, &refusal);
}

void IsolatedMmeRelay::onUplink(bool fromTarget, const std::vector<uint8_t> &pdu,
                                CoordinationRefusalRecord *failure)
{
    m_lastRefusal.reset();
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        m_lastRefusal = CoordinationRefusalRecord{why, std::move(detail)};
        if (failure != nullptr)
            *failure = *m_lastRefusal;
    };

    if (!m_coordinator.enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED,
                      "the isolated MME simulator refuses to act while attached to a live EPC");

    // The only uplink this stage understands is the target's Handover Notify.
    // Everything else is refused rather than guessed at, and a Notify from the
    // source side is refused for the same reason a Notify from anywhere else
    // would be: this message is the target's to send.
    HandoverNotify notify;
    try
    {
        notify = DecodeHandoverNotify(pdu.data(), pdu.size());
    }
    catch (const std::exception &e)
    {
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the isolated MME simulator carries no such uplink message: ") + e.what());
    }
    if (!fromTarget)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "a Handover Notify is the target's message and is refused from the source side");

    const CoordinationRecord *record = m_coordinator.findByMmeUeS1apId(notify.mmeUeS1apId);
    if (record == nullptr)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "the Handover Notify names no open handover transaction");
    if (!acceptHandoverNotify(pdu, record->transaction, failure))
    {
        m_lastRefusal = CoordinationRefusalRecord{CoordinationRefusal::WRONG_TRANSACTION_STATE,
                                                  "the Handover Notify was refused"};
        if (failure != nullptr && failure->detail.empty())
            *failure = *m_lastRefusal;
    }
}

PreparationHop IsolatedMmeRelay::relayPreparation(const std::vector<uint8_t> &requiredPdu,
                                                  const HandoverTransactionId &transaction,
                                                  const HandoverTargetBinding &targetBinding,
                                                  const IsolatedUeSecurity &security, EnbMultiplexer &target,
                                                  uint64_t targetAssociationEpoch)
{
    PreparationHop hop;
    hop.transaction = transaction;
    hop.requiredPdu = requiredPdu;

    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        hop.coordinationFailure = CoordinationRefusalRecord{why, std::move(detail)};
        return hop;
    };

    if (!m_coordinator.enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED,
                      "the isolated MME simulator refuses to act while attached to a live EPC");

    const CoordinationRecord *record = m_coordinator.find(transaction);
    if (record == nullptr)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "no live coordination record names this transaction");
    if (!record->completeForPreparation())
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the coordination record does not bind what a preparation needs");
    if (targetAssociationEpoch != record->targetAssociationEpoch)
        return refuse(CoordinationRefusal::STALE_ASSOCIATION_EPOCH,
                      "the target association epoch is no longer the one the record names");
    if (!SameCell(targetBinding.identity, record->target))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "the target being relayed to is not the one this record names");

    // The source's own message, read with the production codec. The relay never
    // carries a structure across a hop: it carries bytes and reads them again.
    HandoverRequired required;
    try
    {
        required = DecodeHandoverRequired(requiredPdu.data(), requiredPdu.size());
    }
    catch (const std::exception &e)
    {
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the Handover Required could not be decoded: ") + e.what());
    }

    // The message must name exactly the UE and exactly the target the record
    // authorizes. Neither is taken on the strength of the message restating it.
    if (required.mmeUeS1apId != record->mmeUeS1apId || required.enbUeS1apId != record->source.enbUeS1apId)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the Handover Required names a different UE than the coordination record holds");
    if (!SameCell(required.target, record->target))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "the Handover Required names a target this coordinator did not authorize");
    if (required.handoverType != HandoverType::INTRA_LTE)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "only an intra-LTE handover is carried by this relay");

    // The hop is now genuinely under way, and that is the authoritative event
    // for HANDOVER_PREPARING: a Handover Required has been read out of the
    // source's own message and accepted against this record. A refusal before
    // this point is a message that is not for this transaction and moves
    // nothing; a refusal after it is a preparation that started and did not
    // finish, and is recorded as one.
    {
        CoordinationRefusalRecord stateFailure;
        if (!m_coordinator.advance(transaction, OrchestrationState::HANDOVER_PREPARING, &stateFailure))
            return refuse(stateFailure.refusal, stateFailure.detail);
    }

    // The target-side view of the source comes from the record, which is the
    // one `ExtractSourceSession` established out of the source's own registry.
    // It is never derived from the association, from a TAC or PLMN match, and
    // never from anything the Handover Required merely restated.
    SourceContext sourceContext;
    sourceContext.identity = record->source.sourceCell;
    sourceContext.identityKnown = record->source.isVerified();

    TargetContext targetContext;
    targetContext.identity = targetBinding.identity;
    targetContext.s1uAddress = targetBinding.s1uAddress;
    targetContext.encryptionAlgorithms = targetBinding.encryptionAlgorithms;
    targetContext.integrityAlgorithms = targetBinding.integrityAlgorithms;

    // The Handover Request the MME would send. The bearer inventory and the
    // UE-AMBR are the verified source session's; the security material is MME
    // signalling content that is carried through and never derived.
    HandoverRequest request;
    request.mmeUeS1apId = record->mmeUeS1apId;
    request.handoverType = HandoverType::INTRA_LTE;
    request.causeCategory = required.causeCategory;
    request.causeValue = required.causeValue;
    request.ueAmbr = record->source.ueAmbr;
    request.erabs = record->source.erabs;
    request.sourceToTarget = required.sourceToTarget;
    request.encryptionAlgorithms = security.encryptionAlgorithms;
    request.integrityAlgorithms = security.integrityAlgorithms;
    request.securityContext = security.context;

    HandoverRequest decodedRequest;
    try
    {
        hop.requestPdu = EncodeHandoverRequest(request);
        decodedRequest = DecodeHandoverRequest(hop.requestPdu.data(), hop.requestPdu.size());
    }
    catch (const std::exception &e)
    {
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the Handover Request could not be carried: ") + e.what());
    }

    // The target's preparation entry point, not its raw S1AP dispatcher. That
    // dispatcher deliberately still fails closed on a Handover Request: it has
    // no way to establish this source. What authorizes this call is the record
    // above, which only `ExtractSourceSession` could have produced.
    EnbMultiplexer::PreparedHandover prepared;
    CommitRefusalRecord commitFailure;
    const HandoverTransactionId requested{record->mmeUeS1apId, targetAssociationEpoch, 0};
    if (!target.prepareHandover(requested, decodedRequest, sourceContext, targetContext, record->source.roles,
                                &prepared, &commitFailure))
    {
        hop.targetFailure = commitFailure;
        // A preparation that started and was refused is recorded as one. The
        // record does not sit in HANDOVER_PREPARING waiting for an event that
        // is now never going to arrive.
        m_coordinator.advance(transaction, OrchestrationState::PREPARATION_FAILED, nullptr);
        // A refusal with no standard Cause on the wire has no conformant
        // failure message to send, so none is invented: the refusal is reported
        // and nothing goes out.
        if (commitFailure.causeValue >= 0 && !commitFailure.causeCategory.empty())
        {
            HandoverPreparationFailure failure;
            failure.mmeUeS1apId = record->mmeUeS1apId;
            failure.enbUeS1apId = record->source.enbUeS1apId;
            failure.causeCategory = commitFailure.causeCategory;
            failure.causeValue = commitFailure.causeValue;
            try
            {
                hop.failurePdu = EncodeHandoverPreparationFailure(failure);
            }
            catch (const std::exception &)
            {
                hop.failurePdu.clear();
            }
        }
        return hop;
    }

    // The target's transaction identity and its arrival token are learned here
    // and bound into the record by the component that actually learned them.
    CoordinationRefusalRecord bindFailure;
    if (!m_coordinator.bindPreparation(prepared.transaction, prepared.arrivalToken, &bindFailure))
    {
        // The target has committed resources this record will not be told
        // about. That is still a preparation that did not finish, and it is
        // recorded as one rather than left for a caller to infer.
        m_coordinator.advance(transaction, OrchestrationState::PREPARATION_FAILED, nullptr);
        hop.coordinationFailure = bindFailure;
        return hop;
    }

    HandoverRequestAcknowledge decodedAcknowledge;
    try
    {
        hop.acknowledgePdu = EncodeHandoverRequestAcknowledge(prepared.acknowledge);
        decodedAcknowledge = DecodeHandoverRequestAcknowledge(hop.acknowledgePdu.data(), hop.acknowledgePdu.size());
    }
    catch (const std::exception &e)
    {
        m_coordinator.advance(prepared.transaction, OrchestrationState::PREPARATION_FAILED, nullptr);
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the Handover Request Acknowledge could not be carried: ") + e.what());
    }

    // The Handover Command the source is to execute. Its transparent container
    // is the target's, preserved byte for byte and never parsed here. The
    // E-RABSubjecttoDataForwardingList is deliberately empty: indirect GTP-U
    // forwarding is not implemented, so no bearer is offered a forwarding path
    // this system does not have.
    HandoverCommand command;
    command.mmeUeS1apId = record->mmeUeS1apId;
    command.enbUeS1apId = record->source.enbUeS1apId;
    command.handoverType = HandoverType::INTRA_LTE;
    command.targetToSource = decodedAcknowledge.targetToSource;

    try
    {
        hop.commandPdu = EncodeHandoverCommand(command);
    }
    catch (const std::exception &e)
    {
        m_coordinator.advance(prepared.transaction, OrchestrationState::PREPARATION_FAILED, nullptr);
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the Handover Command could not be built: ") + e.what());
    }

    // The authoritative event for TARGET_PREPARED: the target admitted and
    // committed real transport, and both messages that carry the result were
    // built. It is deliberately last, because a hop that cannot finish must not
    // leave the record claiming that a target is ready for a UE that will never
    // be told to go there.
    {
        CoordinationRefusalRecord stateFailure;
        if (!m_coordinator.advance(prepared.transaction, OrchestrationState::TARGET_PREPARED, &stateFailure))
        {
            hop.coordinationFailure = stateFailure;
            return hop;
        }
    }

    hop.transaction = prepared.transaction;
    hop.arrivalToken = prepared.arrivalToken;
    hop.delivered = true;
    return hop;
}

bool IsolatedMmeRelay::confirmTargetArrival(EnbMultiplexer &target, CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (!m_coordinator.enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED,
                      "the isolated MME simulator refuses to act while attached to a live EPC");

    // The evidence comes out of the target. A caller cannot hand this relay an
    // arrival, so the only way a transaction is confirmed is by one the
    // target's own production radio receive path accepted.
    const std::optional<s1ap::VerifiedTargetArrival> &accepted = target.lastVerifiedArrival();
    if (!accepted.has_value())
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "this target has not accepted a handover arrival to report");

    CoordinationRecord *record = m_coordinator.findMutable(accepted->transaction);
    if (record == nullptr)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "the accepted arrival names no live coordination record");
    if (record->cancelled)
        return refuse(CoordinationRefusal::TRANSACTION_CANCELLED, "the coordination record has been cancelled");
    if (record->expiresAt <= std::chrono::steady_clock::now())
        return refuse(CoordinationRefusal::TRANSACTION_EXPIRED, "the coordination record has expired");
    if (accepted->transaction.associationEpoch != record->targetAssociationEpoch)
        return refuse(CoordinationRefusal::STALE_ASSOCIATION_EPOCH,
                      "the accepted arrival was made under another target association epoch");

    // What the arrival gate produced is checked against what this record
    // already binds. Neither half is taken on the strength of the other
    // restating it, and an address mismatch stops the confirmation rather than
    // becoming the authority for a forwardable bearer.
    if (accepted->arrivalToken == 0 || accepted->arrivalToken != record->arrivalToken)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the accepted arrival does not present the token this record bound");
    if (accepted->radioUeId == 0)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the accepted arrival names no radio identity");
    if (!SameCell(accepted->source, record->source.sourceCell))
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the accepted arrival names another source cell than the one this record was made for");
    if (!SameCell(accepted->target, record->target))
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "the accepted arrival names another target cell than this transaction moved to");
    if (accepted->ueIpv4 != record->pdnAddress)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the accepted arrival names another PDN address than this session holds");

    // The advance itself refuses anything that is not a commanded, relocated
    // UE, so this cannot be used to skip a step. A repeat of the same
    // confirmation is the same event and moves nothing.
    return m_coordinator.advance(accepted->transaction, OrchestrationState::TARGET_ARRIVAL_CONFIRMED, failure);
}

bool IsolatedMmeRelay::acceptHandoverNotify(const std::vector<uint8_t> &notifyPdu,
                                            const HandoverTransactionId &transaction,
                                            CoordinationRefusalRecord *failure)
{
    auto refuse = [&](CoordinationRefusal why, std::string detail) {
        if (failure != nullptr)
            *failure = CoordinationRefusalRecord{why, std::move(detail)};
        return false;
    };
    if (!m_coordinator.enabled())
        return refuse(CoordinationRefusal::LIVE_MODE_DISABLED,
                      "the isolated MME simulator refuses to act while attached to a live EPC");

    CoordinationRecord *record = m_coordinator.findMutable(transaction);
    if (record == nullptr)
        return refuse(CoordinationRefusal::WRONG_TRANSACTION_STATE,
                      "no live coordination record names this transaction");

    HandoverNotify notify;
    try
    {
        notify = DecodeHandoverNotify(notifyPdu.data(), notifyPdu.size());
    }
    catch (const std::exception &e)
    {
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      std::string("the Handover Notify could not be decoded: ") + e.what());
    }

    // What the message must agree with is what the coordinator already holds.
    // The eNB-UE-S1AP-ID is the target's own, allocated when it took the
    // context on, so it is only required to be bound rather than compared
    // against a source identifier it is not.
    if (notify.mmeUeS1apId != record->mmeUeS1apId)
        return refuse(CoordinationRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED,
                      "the Handover Notify names another MME UE identity than the record holds");
    if (notify.enbUeS1apId == 0)
        return refuse(CoordinationRefusal::INCOMPLETE_COORDINATION_RECORD,
                      "the Handover Notify names no target-side S1AP identity");
    if (!SamePlmn(notify.cgi.plmn, record->target.plmn) || notify.cgi.cellId != CgiOf(record->target).cellId)
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "the Handover Notify names another target cell than this transaction moved to");
    if (!SamePlmn(notify.tai.plmn, record->target.plmn) || notify.tai.tac != record->target.tac)
        return refuse(CoordinationRefusal::TARGET_NOT_PERMITTED,
                      "the Handover Notify names another tracking area than this transaction moved to");

    // A repeat notification for a transaction that has already been notified is
    // the same event, not a second one. Nothing moves and nothing is refused.
    if (record->state == OrchestrationState::AWAITING_CORE_PATH_UPDATE ||
        record->state == OrchestrationState::HANDOVER_NOTIFY_SENT)
    {
        m_lastNotifiedMmeUeS1apId = record->mmeUeS1apId;
        return true;
    }

    CoordinationRefusalRecord step;
    if (!m_coordinator.advance(transaction, OrchestrationState::HANDOVER_NOTIFY_SENT, &step))
        return refuse(step.refusal, step.detail);
    if (!m_coordinator.advance(transaction, OrchestrationState::AWAITING_CORE_PATH_UPDATE, &step))
        return refuse(step.refusal, step.detail);

    // AWAITING_CORE_PATH_UPDATE is where this phase stops, and it is named for
    // what has not happened rather than for what has: the MME-controlled
    // downlink bearer path update and the source context release are later work
    // and nothing here performs or reports them.
    m_lastNotifiedMmeUeS1apId = record->mmeUeS1apId;
    return true;
}

} // namespace lte::enb::s1ap
