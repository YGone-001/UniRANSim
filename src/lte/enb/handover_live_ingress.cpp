//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "handover_live_ingress.hpp"

#include <algorithm>
#include <array>
#include <set>
#include <stdexcept>
#include <utility>

#include "multiplexer.hpp"

namespace lte::enb::s1ap
{
namespace
{

CapabilityAssessment Assess(HandoverCapability capability, bool available, std::string evidence)
{
    return CapabilityAssessment{capability, available, std::move(evidence)};
}

// TS 36.413 §9.2.2.3 gives the algorithm bitmaps as two octets per direction.
// A pair that is all zero states that no algorithm is accepted, which is not a
// security context a target may act on.
bool HasAnyAlgorithm(const std::array<uint8_t, 2> &algorithms)
{
    return algorithms[0] != 0 || algorithms[1] != 0;
}

bool IsAllZero(const std::array<uint8_t, 32> &value)
{
    return std::all_of(value.begin(), value.end(), [](uint8_t octet) { return octet == 0; });
}

// The codec's typed refusal, restated in the ingress vocabulary. A message the
// codec refused for a specific reason is reported for that reason rather than
// as a generic decode failure.
HandoverIngressRefusal MapCodecRefusal(HandoverRefusal refusal)
{
    switch (refusal)
    {
    case HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE: return HandoverIngressRefusal::UNSUPPORTED_HANDOVER_TYPE;
    case HandoverRefusal::INVALID_TRANSPARENT_CONTAINER:
        return HandoverIngressRefusal::TRANSPARENT_CONTAINER_INVALID;
    case HandoverRefusal::UNSUPPORTED_ERAB_LIST: return HandoverIngressRefusal::ERAB_INVENTORY_INVALID;
    case HandoverRefusal::INVALID_CONTEXT_IDENTITY: return HandoverIngressRefusal::IDENTITY_MISMATCH;
    case HandoverRefusal::MISSING_MANDATORY_IE: return HandoverIngressRefusal::MALFORMED_PDU;
    }
    return HandoverIngressRefusal::MALFORMED_PDU;
}

// The E-RAB set a target is asked to prepare, checked for the properties the
// target itself owns: at least one bearer, no duplicate identity, an identity
// the E-RAB-ID type admits, and a QoS a bearer can carry.
bool ValidateErabInventory(const std::vector<ErabToBeSetupItemHoReq> &erabs, std::string *detail)
{
    if (erabs.empty())
    {
        *detail = "the Handover Request names no E-RAB";
        return false;
    }
    std::set<uint8_t> seen;
    for (const auto &erab : erabs)
    {
        if (erab.erabId < 1 || erab.erabId > 15)
        {
            *detail = "an E-RAB identity is outside the E-RAB-ID range";
            return false;
        }
        if (!seen.insert(erab.erabId).second)
        {
            *detail = "the Handover Request names the same E-RAB twice";
            return false;
        }
        if (erab.qos.qci == 0)
        {
            *detail = "an E-RAB carries no QCI";
            return false;
        }
        if (erab.sgwTeid == std::array<uint8_t, 4>{})
        {
            *detail = "an E-RAB names no SGW-side tunnel identity";
            return false;
        }
    }
    return true;
}

// The safety net for a refused message: a standards-valid Handover Failure that
// names the UE and the standard cause, and nothing else. A failure that cannot
// be built leaves the response empty; it never turns a refusal into an
// acknowledgement.
std::vector<uint8_t> BuildRefusalResponse(uint32_t mmeUeS1apId, std::string *why)
{
    HandoverFailure failure;
    failure.mmeUeS1apId = mmeUeS1apId;
    failure.causeCategory = "radioNetwork";
    failure.causeValue = CauseHoFailureInTargetEnbOrTargetSystem;
    try
    {
        return EncodeHandoverFailure(failure);
    }
    catch (const std::exception &e)
    {
        if (why != nullptr)
            *why = e.what();
        return {};
    }
}

} // namespace

const char *ToString(HandoverCapability capability)
{
    switch (capability)
    {
    case HandoverCapability::ISOLATED_SIMULATOR_READY: return "ISOLATED_SIMULATOR_READY";
    case HandoverCapability::S1AP_CODEC_READY: return "S1AP_CODEC_READY";
    case HandoverCapability::S1AP_RUNTIME_INGRESS_READY: return "S1AP_RUNTIME_INGRESS_READY";
    case HandoverCapability::SOURCE_PROVENANCE_READY: return "SOURCE_PROVENANCE_READY";
    case HandoverCapability::TARGET_CONTEXT_READY: return "TARGET_CONTEXT_READY";
    case HandoverCapability::RRC_CONTAINER_READY: return "RRC_CONTAINER_READY";
    case HandoverCapability::HANDOVER_SECURITY_READY: return "HANDOVER_SECURITY_READY";
    case HandoverCapability::UE_RADIO_EXECUTION_READY: return "UE_RADIO_EXECUTION_READY";
    case HandoverCapability::MME_PATH_UPDATE_OBSERVABLE: return "MME_PATH_UPDATE_OBSERVABLE";
    case HandoverCapability::LIVE_HANDOVER_EXECUTION_READY: return "LIVE_HANDOVER_EXECUTION_READY";
    }
    return "UNKNOWN_HANDOVER_CAPABILITY";
}

const char *ToString(LiveHandoverMessage message)
{
    switch (message)
    {
    case LiveHandoverMessage::NONE: return "NONE";
    case LiveHandoverMessage::HANDOVER_REQUEST: return "HANDOVER_REQUEST";
    case LiveHandoverMessage::HANDOVER_COMMAND: return "HANDOVER_COMMAND";
    case LiveHandoverMessage::HANDOVER_PREPARATION_FAILURE: return "HANDOVER_PREPARATION_FAILURE";
    case LiveHandoverMessage::HANDOVER_CANCEL: return "HANDOVER_CANCEL";
    }
    return "UNKNOWN_LIVE_HANDOVER_MESSAGE";
}

const char *ToString(LiveHandoverDisposition disposition)
{
    switch (disposition)
    {
    case LiveHandoverDisposition::NOT_A_HANDOVER_MESSAGE: return "NOT_A_HANDOVER_MESSAGE";
    case LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE: return "RECOGNIZED_BUT_NOT_EXECUTABLE";
    case LiveHandoverDisposition::REJECTED: return "REJECTED";
    case LiveHandoverDisposition::EXECUTED: return "EXECUTED";
    }
    return "UNKNOWN_LIVE_HANDOVER_DISPOSITION";
}

const char *ToString(HandoverIngressRefusal refusal)
{
    switch (refusal)
    {
    case HandoverIngressRefusal::NONE: return "NONE";
    case HandoverIngressRefusal::NOT_A_HANDOVER_MESSAGE: return "NOT_A_HANDOVER_MESSAGE";
    case HandoverIngressRefusal::MALFORMED_PDU: return "MALFORMED_PDU";
    case HandoverIngressRefusal::UNSUPPORTED_HANDOVER_TYPE: return "UNSUPPORTED_HANDOVER_TYPE";
    case HandoverIngressRefusal::UNSUPPORTED_PROCEDURE: return "UNSUPPORTED_PROCEDURE";
    case HandoverIngressRefusal::STALE_ASSOCIATION: return "STALE_ASSOCIATION";
    case HandoverIngressRefusal::UNKNOWN_UE_CONTEXT: return "UNKNOWN_UE_CONTEXT";
    case HandoverIngressRefusal::IDENTITY_MISMATCH: return "IDENTITY_MISMATCH";
    case HandoverIngressRefusal::UE_NOT_CONNECTED: return "UE_NOT_CONNECTED";
    case HandoverIngressRefusal::NO_PENDING_HANDOVER: return "NO_PENDING_HANDOVER";
    case HandoverIngressRefusal::ERAB_INVENTORY_INVALID: return "ERAB_INVENTORY_INVALID";
    case HandoverIngressRefusal::TRANSPARENT_CONTAINER_INVALID: return "TRANSPARENT_CONTAINER_INVALID";
    case HandoverIngressRefusal::SECURITY_CONTEXT_INVALID: return "SECURITY_CONTEXT_INVALID";
    case HandoverIngressRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED: return "SOURCE_PROVENANCE_NOT_ESTABLISHED";
    case HandoverIngressRefusal::RRC_CONTAINER_NOT_READY: return "RRC_CONTAINER_NOT_READY";
    case HandoverIngressRefusal::HANDOVER_SECURITY_NOT_READY: return "HANDOVER_SECURITY_NOT_READY";
    case HandoverIngressRefusal::UE_RADIO_EXECUTION_NOT_READY: return "UE_RADIO_EXECUTION_NOT_READY";
    case HandoverIngressRefusal::CAPABILITY_NOT_READY: return "CAPABILITY_NOT_READY";
    case HandoverIngressRefusal::RESPONSE_NOT_SENDABLE: return "RESPONSE_NOT_SENDABLE";
    }
    return "UNKNOWN_HANDOVER_INGRESS_REFUSAL";
}

bool LiveHandoverReadiness::available(HandoverCapability capability) const
{
    for (const auto &assessment : assessments)
        if (assessment.capability == capability)
            return assessment.available;
    return false;
}

std::vector<HandoverCapability> LiveHandoverReadiness::missing() const
{
    std::vector<HandoverCapability> out;
    for (const auto &assessment : assessments)
    {
        // The aggregate is derived from the entries before it and is not
        // itself a mandatory capability a caller could satisfy.
        if (assessment.capability == HandoverCapability::LIVE_HANDOVER_EXECUTION_READY)
            continue;
        if (!assessment.available)
            out.push_back(assessment.capability);
    }
    return out;
}

LiveHandoverReadiness AssessLiveHandoverCapabilities()
{
    // Each entry is a statement about this build with the fact it rests on. None
    // of them is a switch: the two that are true are true because the code and
    // its tests exist, and the ones that are false are false because the code
    // they would need does not exist.
    LiveHandoverReadiness readiness;
    readiness.assessments = {
        Assess(HandoverCapability::ISOLATED_SIMULATOR_READY, true,
               "the isolated coordinator, SGW map and source release are implemented and exercised by the "
               "Phase 18-D and 18-E acceptance cases"),
        Assess(HandoverCapability::S1AP_CODEC_READY, true,
               "Requires/Request/Acknowledge/Command/PreparationFailure/Notify/Failure are encoded and decoded by "
               "codecs pinned against tshark-verified APER vectors"),
        Assess(HandoverCapability::S1AP_RUNTIME_INGRESS_READY, true,
               "the live dispatcher classifies the handover family and refuses it without side effects; see the "
               "lte/handover/live cases"),
        Assess(HandoverCapability::SOURCE_PROVENANCE_READY, false,
               "a target receives no standards-compliant source eNB identity: Handover Request carries none, and "
               "this repository refuses to derive one from the MME peer, TAC, PLMN, EBI or the opaque container"),
        Assess(HandoverCapability::TARGET_CONTEXT_READY, false,
               "a provisional target context is created only from a SourceSession that ExtractSourceSession read "
               "out of the source's own live registry, which a target eNB does not hold"),
        Assess(HandoverCapability::RRC_CONTAINER_READY, false,
               "the RRC payload codec now exists (src/lte/rrc, UPER, TS 36.331 V15.6.0), but the S1AP container "
               "that carries it is the 36.413 SourceeNB-ToTargeteNB-TransparentContainer SEQUENCE, which this "
               "repository does not encode yet; a payload alone is not a container"),
        Assess(HandoverCapability::HANDOVER_SECURITY_READY, false,
               "lte::ue::SecurityContext holds KASME, CK, IK and the NAS keys only: there is no KeNB, no NH "
               "handling and no RRC/UP key derivation, so the nextHopParameter the MME sends cannot be applied"),
        Assess(HandoverCapability::UE_RADIO_EXECUTION_READY, false,
               "the UE runtime executes the SIMULATED_HANDOVER_COMMAND control frame, not an "
               "RRCConnectionReconfiguration carrying a mobilityControlInfo"),
        Assess(HandoverCapability::MME_PATH_UPDATE_OBSERVABLE, false,
               "an eNB observes only its own S1AP exchange; the SGW's downlink map is changed by the MME's S11 "
               "Modify Bearer Request through the SGW-C, which this eNB cannot see"),
    };
    readiness.assessments.push_back(Assess(HandoverCapability::LIVE_HANDOVER_EXECUTION_READY,
                                           readiness.missing().empty(),
                                           "derived: true only when every mandatory capability above is available"));
    return readiness;
}

LiveHandoverMessage ClassifyHandoverMessage(const S1apPdu &probe)
{
    // TS 36.413 §9.1.3.1. Handover Preparation is procedure 0, Handover
    // Resource Allocation is 1 and Handover Cancel is 4. A message is only the
    // procedure it claims when its PDU category is the one that procedure uses
    // in this direction.
    constexpr uint16_t ProcedureHandoverPreparation = 0;
    constexpr uint16_t ProcedureHandoverResourceAllocation = 1;
    constexpr uint16_t ProcedureHandoverCancel = 4;

    using Kind = S1apPdu::Kind;
    if (probe.kind == Kind::INITIATING && probe.procedureCode == ProcedureHandoverResourceAllocation)
        return LiveHandoverMessage::HANDOVER_REQUEST;
    if (probe.kind == Kind::SUCCESSFUL_OUTCOME && probe.procedureCode == ProcedureHandoverPreparation)
        return LiveHandoverMessage::HANDOVER_COMMAND;
    if (probe.kind == Kind::UNSUCCESSFUL_OUTCOME && probe.procedureCode == ProcedureHandoverPreparation)
        return LiveHandoverMessage::HANDOVER_PREPARATION_FAILURE;
    if (probe.kind == Kind::INITIATING && probe.procedureCode == ProcedureHandoverCancel)
        return LiveHandoverMessage::HANDOVER_CANCEL;
    return LiveHandoverMessage::NONE;
}

bool ValidateHandoverRequestForTarget(const HandoverRequest &request, HandoverIngressRefusal *refusal,
                                      std::string *detail)
{
    auto fail = [refusal, detail](HandoverIngressRefusal why, std::string text) {
        if (refusal != nullptr)
            *refusal = why;
        if (detail != nullptr)
            *detail = std::move(text);
        return false;
    };

    if (request.mmeUeS1apId == 0)
        return fail(HandoverIngressRefusal::IDENTITY_MISMATCH,
                    "the Handover Request names no MME-UE-S1AP-ID");
    if (request.handoverType != HandoverType::INTRA_LTE)
        return fail(HandoverIngressRefusal::UNSUPPORTED_HANDOVER_TYPE,
                    "only an intra-LTE handover can be prepared by this cell");
    if (request.sourceToTarget.empty() || request.sourceToTarget.size() > MaxTransparentContainerSize)
        return fail(HandoverIngressRefusal::TRANSPARENT_CONTAINER_INVALID,
                    "the Source-ToTarget container is empty or larger than this receiver accepts");
    std::string erabDetail;
    if (!ValidateErabInventory(request.erabs, &erabDetail))
        return fail(HandoverIngressRefusal::ERAB_INVENTORY_INVALID, erabDetail);
    // The security context the MME sends is the only AS material that reaches
    // this cell. A context that states no algorithm or carries an all-zero NH is
    // not something a target may act on, and it is refused rather than accepted
    // with fabricated keys.
    if (!HasAnyAlgorithm(request.encryptionAlgorithms) || !HasAnyAlgorithm(request.integrityAlgorithms))
        return fail(HandoverIngressRefusal::SECURITY_CONTEXT_INVALID,
                    "the Handover Request names no encryption or integrity algorithm this cell could apply");
    if (IsAllZero(request.securityContext.nextHopParameter))
        return fail(HandoverIngressRefusal::SECURITY_CONTEXT_INVALID,
                    "the Handover Request carries an all-zero next hop parameter");
    if (refusal != nullptr)
        *refusal = HandoverIngressRefusal::NONE;
    return true;
}

namespace
{

// A Handover Request at a target eNB. Everything a target may legitimately
// check is checked; everything it may not decide is refused rather than
// guessed, and the refusal is signalled with the standard cause.
LiveHandoverOutcome RefuseHandoverRequest(const uint8_t *data, size_t size, const LiveHandoverOutcome &base)
{
    LiveHandoverOutcome outcome = base;

    HandoverRequest request;
    try
    {
        request = DecodeHandoverRequest(data, size);
    }
    catch (const HandoverRefused &e)
    {
        // A well-formed message the codec refuses for a stated reason. The
        // decode stopped before an MME-UE-S1AP-ID was read, so no Handover
        // Failure can be addressed; the refusal is recorded and no response is
        // invented.
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = MapCodecRefusal(e.refusal());
        outcome.detail = e.what();
        return outcome;
    }
    catch (const std::exception &e)
    {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = HandoverIngressRefusal::MALFORMED_PDU;
        outcome.detail = e.what();
        return outcome;
    }

    outcome.mmeUeS1apId = request.mmeUeS1apId;

    auto reject = [&outcome](HandoverIngressRefusal refusal, std::string detail) {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = refusal;
        outcome.detail = std::move(detail);
        std::string why;
        outcome.responsePdu = BuildRefusalResponse(outcome.mmeUeS1apId, &why);
        if (outcome.responsePdu.empty() && !why.empty())
            outcome.detail += "; the refusal could not be encoded: " + why;
        return outcome;
    };

    HandoverIngressRefusal refusal = HandoverIngressRefusal::NONE;
    std::string detail;
    if (!ValidateHandoverRequestForTarget(request, &refusal, &detail))
        return reject(refusal, detail);

    // Everything a target can check has passed. What it cannot do is prepare:
    // the source identity is unavailable, no RRC container can be produced, and
    // the UE runtime cannot apply the security material. The message is
    // recognised and refused, never acknowledged.
    const LiveHandoverReadiness readiness = AssessLiveHandoverCapabilities();
    outcome.missing = readiness.missing();
    outcome.disposition = LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE;
    outcome.refusal = HandoverIngressRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED;
    outcome.detail =
        "the target cannot establish the source eNB identity from standards-compliant signalling, and this build "
        "lacks the RRC and AS-security prerequisites of a real preparation";
    std::string why;
    outcome.responsePdu = BuildRefusalResponse(outcome.mmeUeS1apId, &why);
    if (outcome.responsePdu.empty())
        outcome.detail += "; the Handover Failure could not be encoded: " + why;
    return outcome;
}

LiveHandoverOutcome RefuseHandoverCommand(const uint8_t *data, size_t size, const LiveHandoverContext &context,
                                          const LiveHandoverOutcome &base)
{
    LiveHandoverOutcome outcome = base;

    HandoverCommand command;
    try
    {
        command = DecodeHandoverCommand(data, size);
    }
    catch (const std::exception &e)
    {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = HandoverIngressRefusal::MALFORMED_PDU;
        outcome.detail = e.what();
        return outcome;
    }

    outcome.mmeUeS1apId = command.mmeUeS1apId;

    auto reject = [&outcome](HandoverIngressRefusal refusal, std::string detail) {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = refusal;
        outcome.detail = std::move(detail);
        return outcome;
    };

    if (context.registry == nullptr)
        return reject(HandoverIngressRefusal::UNKNOWN_UE_CONTEXT, "no registry is bound to this association");
    const EnbUeEntry *entry = context.registry->findByEnbUeS1apId(command.enbUeS1apId);
    if (entry == nullptr)
        return reject(HandoverIngressRefusal::UNKNOWN_UE_CONTEXT,
                      "the Handover Command names an eNB-UE-S1AP-ID this cell does not hold");
    if (entry->mmeUeS1apId != command.mmeUeS1apId)
        return reject(HandoverIngressRefusal::IDENTITY_MISMATCH,
                      "the Handover Command names another MME-UE-S1AP-ID than the context holds");
    if (!entry->s1Active())
        return reject(HandoverIngressRefusal::UE_NOT_CONNECTED,
                      "the UE holds no S1 connection that a handover command could move");
    if (command.targetToSource.empty() || command.targetToSource.size() > MaxTransparentContainerSize)
        return reject(HandoverIngressRefusal::TRANSPARENT_CONTAINER_INVALID,
                      "the Target-ToSource container is empty or larger than this receiver accepts");

    // The source's own record that it asked for this handover. Without one, the
    // command is about a transaction this cell never started, and no amount of
    // decoding makes it executable.
    const HandoverSourceRecord *pending = nullptr;
    if (context.sourceRecords != nullptr)
        for (const auto &record : *context.sourceRecords)
            if (record.enbUeS1apId == command.enbUeS1apId && record.mmeUeS1apId == command.mmeUeS1apId)
                pending = &record;
    if (pending == nullptr)
        return reject(HandoverIngressRefusal::NO_PENDING_HANDOVER,
                      "this cell holds no record of having asked for a handover of this UE");
    if (pending->associationEpoch != context.associationEpoch)
        return reject(HandoverIngressRefusal::STALE_ASSOCIATION,
                      "the handover began under another source S1 association epoch");

    // A real command carries an RRC container the UE must execute. This build
    // can neither verify it nor turn it into a radio reconfiguration, and it
    // refuses to translate opaque bytes into a simulator command.
    const LiveHandoverReadiness readiness = AssessLiveHandoverCapabilities();
    outcome.missing = readiness.missing();
    outcome.disposition = LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE;
    outcome.refusal = HandoverIngressRefusal::RRC_CONTAINER_NOT_READY;
    outcome.detail =
        "the command is recognised, but no LTE RRC container can be consumed and the UE runtime cannot execute an "
        "RRC reconfiguration";
    return outcome;
}

LiveHandoverOutcome RefusePreparationFailure(const uint8_t *data, size_t size, const LiveHandoverContext &context,
                                             const LiveHandoverOutcome &base)
{
    LiveHandoverOutcome outcome = base;

    HandoverPreparationFailure failure;
    try
    {
        failure = DecodeHandoverPreparationFailure(data, size);
    }
    catch (const std::exception &e)
    {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = HandoverIngressRefusal::MALFORMED_PDU;
        outcome.detail = e.what();
        return outcome;
    }

    outcome.mmeUeS1apId = failure.mmeUeS1apId;

    auto reject = [&outcome](HandoverIngressRefusal refusal, std::string detail) {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = refusal;
        outcome.detail = std::move(detail);
        return outcome;
    };

    if (context.registry == nullptr)
        return reject(HandoverIngressRefusal::UNKNOWN_UE_CONTEXT, "no registry is bound to this association");
    const EnbUeEntry *entry = context.registry->findByEnbUeS1apId(failure.enbUeS1apId);
    if (entry == nullptr)
        return reject(HandoverIngressRefusal::UNKNOWN_UE_CONTEXT,
                      "the Handover Preparation Failure names an eNB-UE-S1AP-ID this cell does not hold");
    if (entry->mmeUeS1apId != failure.mmeUeS1apId)
        return reject(HandoverIngressRefusal::IDENTITY_MISMATCH,
                      "the Handover Preparation Failure names another MME-UE-S1AP-ID than the context holds");

    // There is no live handover transaction this cell could cancel, and the
    // source keeps its UE exactly as it was. The message changes nothing.
    outcome.disposition = LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE;
    outcome.refusal = HandoverIngressRefusal::NO_PENDING_HANDOVER;
    outcome.detail = "no live handover preparation exists for this UE; the source keeps its context and nothing moves";
    return outcome;
}

} // namespace

LiveHandoverOutcome HandleLiveHandoverPdu(const S1apPdu &probe, const uint8_t *data, size_t size,
                                          const LiveHandoverContext &context)
{
    LiveHandoverOutcome outcome;
    outcome.message = ClassifyHandoverMessage(probe);
    if (outcome.message == LiveHandoverMessage::NONE)
    {
        outcome.disposition = LiveHandoverDisposition::NOT_A_HANDOVER_MESSAGE;
        outcome.refusal = HandoverIngressRefusal::NOT_A_HANDOVER_MESSAGE;
        return outcome;
    }

    // A handover message is UE-associated. One that arrives with no association
    // bound cannot be answered and must not be acted on.
    if (!context.associationBound)
    {
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = HandoverIngressRefusal::STALE_ASSOCIATION;
        outcome.detail = "no S1 association is bound, so no handover procedure can be executed";
        return outcome;
    }

    switch (outcome.message)
    {
    case LiveHandoverMessage::HANDOVER_REQUEST: return RefuseHandoverRequest(data, size, outcome);
    case LiveHandoverMessage::HANDOVER_COMMAND: return RefuseHandoverCommand(data, size, context, outcome);
    case LiveHandoverMessage::HANDOVER_PREPARATION_FAILURE:
        return RefusePreparationFailure(data, size, context, outcome);
    case LiveHandoverMessage::HANDOVER_CANCEL:
        // Recognised by procedure code, with no codec here and no live
        // transaction to cancel. It is refused deliberately and no response is
        // invented: a Handover Cancel Acknowledge is a message this build
        // cannot encode.
        outcome.disposition = LiveHandoverDisposition::REJECTED;
        outcome.refusal = HandoverIngressRefusal::UNSUPPORTED_PROCEDURE;
        outcome.detail = "Handover Cancel is recognised but has no codec in this build and no live transaction";
        return outcome;
    default: break;
    }
    outcome.disposition = LiveHandoverDisposition::REJECTED;
    outcome.refusal = HandoverIngressRefusal::UNSUPPORTED_PROCEDURE;
    return outcome;
}

} // namespace lte::enb::s1ap
