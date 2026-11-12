//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-A: what a live S1 association may do with a handover message.
//
// The accepted handover implementation is an isolated simulator. Its server
// side is a coordinator between two eNBs the simulator owns, and its target
// side reaches a committed preparation through a path the raw S1AP dispatcher
// deliberately does not offer. A real MME sends Handover Request and Handover
// Command down the raw association, and until this phase the dispatcher
// answered both with a generic "unexpected procedure code" rejection.
//
// This module is the boundary those messages now reach. It classifies them,
// validates what can be validated, and then refuses them: every mandatory
// prerequisite for executing a real handover is absent, and each absence is
// named by a capability assessment rather than hidden behind a flag. Nothing
// here allocates a TEID, creates a target context, moves a UE or sends a
// Notify, and nothing here can be turned on by asking for it.
//
// The capability list is the whole point. A caller may not set any of it; the
// assessment is computed on every call from facts about this build and this
// process, and each entry names the evidence for its answer.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "codec.hpp"
#include "handover_source_release.hpp"
#include "ue_registry.hpp"

namespace lte::enb
{
class EnbMultiplexer;
}

namespace lte::enb::s1ap
{

// --- Capability model ------------------------------------------------------

// The runtime capabilities a standards-compatible live S1 handover needs. They
// are assessments of this build, not switches: no command-line option, message
// field or API call sets one.
enum class HandoverCapability : uint8_t
{
    // The isolated two-eNB handover, its SGW map and its source release exist
    // and are accepted.
    ISOLATED_SIMULATOR_READY,
    // The S1AP handover codecs encode and decode the byte-pinned vectors.
    S1AP_CODEC_READY,
    // The live dispatcher recognises the handover family and classifies it
    // without side effects.
    S1AP_RUNTIME_INGRESS_READY,
    // A target can establish which eNB the source was, from standards-compliant
    // signalling, before it prepares anything.
    SOURCE_PROVENANCE_READY,
    // A target can hold a provisional context for a UE that has not arrived.
    TARGET_CONTEXT_READY,
    // The TS 36.331 RRC (UPER) codec encodes and decodes the handover
    // messages: HandoverPreparationInformation and the HandoverCommand payload.
    LTE_RRC_UPER_CODEC_READY,
    // The TS 36.413 transparent-container SEQUENCEs wrap and unwrap those
    // messages, so the S1AP octet string carries a complete container.
    S1AP_TRANSPARENT_CONTAINER_CODEC_READY,
    // The AS-Config the source would send is complete for the supported
    // profile. It is not: the measurement and dedicated-radio contents have no
    // runtime source in this simulated radio, and the codec encodes them as
    // legal empty structures.
    RRC_CONFIGURATION_COMPLETE,
    // The runtime supplies the handover inputs from its own state: the UE's
    // serving-cell history and a verified target-cell identity, both from
    // components that own them. This is simulator runtime evidence, not
    // real-RF evidence.
    RRC_RUNTIME_INPUT_AVAILABLE,
    // The UE runtime can derive and apply AS handover security (KeNB, NH, and
    // the RRC/UP keys) from the SecurityContext the MME sends.
    HANDOVER_SECURITY_READY,
    // The UE runtime can execute an RRC reconfiguration and move its radio
    // access to the target cell.
    UE_RADIO_EXECUTION_READY,
    // The eNB can observe that the MME actually moved the core's downlink path.
    // This is external acceptance evidence, not an execution prerequisite: a
    // target eNB never reads the SGW's forwarding map to perform a handover. It
    // is reported separately and a future live campaign must obtain it from the
    // core side.
    MME_PATH_UPDATE_OBSERVABLE,
    // The conjunction of the execution prerequisites above. It is derived and
    // never set.
    LIVE_HANDOVER_EXECUTION_READY
};

const char *ToString(HandoverCapability capability);

// One capability and the fact that decides it. `evidence` names the code, the
// test or the standard that the answer rests on, so a reader can check it
// instead of trusting it.
struct CapabilityAssessment
{
    HandoverCapability capability{HandoverCapability::ISOLATED_SIMULATOR_READY};
    bool available{};
    std::string evidence;
};

// The whole assessment for one call.
struct LiveHandoverReadiness
{
    std::vector<CapabilityAssessment> assessments;

    [[nodiscard]] bool available(HandoverCapability capability) const;
    // Every execution prerequisite that is missing, in the order above. These
    // are what a running eNB needs before it may execute a handover.
    [[nodiscard]] std::vector<HandoverCapability> missing() const;
    // What a future live acceptance campaign must obtain elsewhere. It is not
    // an execution prerequisite and no eNB is required to satisfy it.
    [[nodiscard]] std::vector<HandoverCapability> externalEvidenceGaps() const;
    // True only when every execution prerequisite is available. Nothing in this
    // repository can make it true today, and that is the honest answer.
    [[nodiscard]] bool liveExecutionReady() const { return missing().empty(); }
};

// Assesses this build. It reads no configuration and takes no argument that
// could assert a capability into existence.
LiveHandoverReadiness AssessLiveHandoverCapabilities();

// --- Ingress classification ------------------------------------------------

// Which handover procedure an inbound PDU is, if any.
//
// HandoverPreparation (0) arrives at a source eNB as a successful outcome (the
// Handover Command) or as an unsuccessful one (Handover Preparation Failure).
// HandoverResourceAllocation (1) arrives at a target eNB as an initiating
// message (the Handover Request). HandoverNotification (2) and
// HandoverResourceAllocation's successful outcome are eNB-to-MME messages and
// are never accepted from the MME.
enum class LiveHandoverMessage : uint8_t
{
    NONE,
    HANDOVER_REQUEST,
    HANDOVER_COMMAND,
    HANDOVER_PREPARATION_FAILURE,
    // Recognised by procedure code, with no codec in this repository. It is
    // classified so it can be refused deliberately rather than as an unknown
    // procedure.
    HANDOVER_CANCEL
};

const char *ToString(LiveHandoverMessage message);

LiveHandoverMessage ClassifyHandoverMessage(const S1apPdu &probe);

// What happened to one inbound handover PDU.
enum class LiveHandoverDisposition : uint8_t
{
    // Not a handover message: the ordinary dispatcher handles it.
    NOT_A_HANDOVER_MESSAGE,
    // Understood, validated, and refused because a required runtime capability
    // does not exist. This is the only disposition a live handover message can
    // reach in this build.
    RECOGNIZED_BUT_NOT_EXECUTABLE,
    // Not understood or not acceptable: malformed, unsupported, or about a UE
    // this eNB does not hold.
    REJECTED,
    // Executed. Unreachable while any mandatory capability is missing.
    EXECUTED
};

const char *ToString(LiveHandoverDisposition disposition);

// Why a live handover message was refused. Each value is a condition checked
// before anything moves.
enum class HandoverIngressRefusal : uint8_t
{
    NONE,
    NOT_A_HANDOVER_MESSAGE,
    // The PDU does not decode, or its envelope is not the one its procedure
    // requires.
    MALFORMED_PDU,
    // A handover type other than intra-LTE.
    UNSUPPORTED_HANDOVER_TYPE,
    // A handover procedure with no codec here.
    UNSUPPORTED_PROCEDURE,
    // The association the message arrived on is not the bound one.
    STALE_ASSOCIATION,
    // The source-side UE the message names is not held by this eNB.
    UNKNOWN_UE_CONTEXT,
    // The identity pair disagrees with the context it names.
    IDENTITY_MISMATCH,
    // The source UE holds no S1 connection that could be handed over.
    UE_NOT_CONNECTED,
    // This cell holds no record of having commanded this UE into a handover.
    NO_PENDING_HANDOVER,
    // The E-RAB list is empty, duplicated, out of range or otherwise not a
    // bearer set a target could answer for.
    ERAB_INVENTORY_INVALID,
    // A transparent container is empty or larger than this receiver accepts.
    TRANSPARENT_CONTAINER_INVALID,
    // The security material is absent or not usable: a zero NH, no algorithm,
    // or a context this build cannot apply.
    SECURITY_CONTEXT_INVALID,
    // The target cannot establish which eNB the source was.
    SOURCE_PROVENANCE_NOT_ESTABLISHED,
    // No LTE RRC container can be produced or consumed.
    RRC_CONTAINER_NOT_READY,
    // The UE runtime cannot derive or apply AS handover security.
    HANDOVER_SECURITY_NOT_READY,
    // The UE runtime cannot execute the RRC reconfiguration.
    UE_RADIO_EXECUTION_NOT_READY,
    // A required capability is missing and none of the specific refusals above
    // names it.
    CAPABILITY_NOT_READY,
    // The refusal could not be signalled: the response did not encode or the
    // association could not carry it. The message is still refused.
    RESPONSE_NOT_SENDABLE
};

const char *ToString(HandoverIngressRefusal refusal);

// Everything one inbound handover PDU did.
struct LiveHandoverOutcome
{
    LiveHandoverMessage message{LiveHandoverMessage::NONE};
    LiveHandoverDisposition disposition{LiveHandoverDisposition::NOT_A_HANDOVER_MESSAGE};
    HandoverIngressRefusal refusal{HandoverIngressRefusal::NOT_A_HANDOVER_MESSAGE};
    std::string detail;
    uint32_t mmeUeS1apId{};
    // The standards-valid Handover Failure this refusal produced, when one could
    // be built. Empty when no response is owed.
    std::vector<uint8_t> responsePdu;
    // Every mandatory capability that is missing, so a caller can report the
    // whole gap rather than only the first one.
    std::vector<HandoverCapability> missing;
    // Whether this path allocated target transport, created a target context,
    // moved a UE, sent a Notify or released a source. It is always false here;
    // it exists so a test can assert the invariant rather than assume it.
    bool mutatedState{false};
};

// What the ingress may read. It is deliberately narrow: the registry the eNB
// already owns, the source records it already holds, and the association the
// message arrived on. Nothing here can be supplied by a message.
struct LiveHandoverContext
{
    const UeRegistry *registry{};
    const std::vector<HandoverSourceRecord> *sourceRecords{};
    uint64_t associationEpoch{};
    bool associationBound{};
};

// Handles one S1AP PDU that `ClassifyHandoverMessage` called a handover
// message. A refusal never throws and never mutates anything; a message that
// is not a handover message is returned as NOT_A_HANDOVER_MESSAGE so the
// caller can fall through to its ordinary dispatch.
LiveHandoverOutcome HandleLiveHandoverPdu(const S1apPdu &probe, const uint8_t *data, size_t size,
                                          const LiveHandoverContext &context);

// The checks a target eNB owns over a decoded Handover Request, without the
// capability gate: the handover type, the container bound, the E-RAB set and
// the security material. It is exposed so each check can be driven directly
// with a decoded message rather than only through a hand-built frame, and so a
// caller can report the same verdict the ingress would.
bool ValidateHandoverRequestForTarget(const HandoverRequest &request, HandoverIngressRefusal *refusal,
                                      std::string *detail);

// The cause a target states when it cannot prepare the requested resources.
// TS 36.413 §9.2.1.3, radioNetwork cause 6. It is the standard answer to a
// Handover Request the target cannot honour, and it carries no invented
// reason of its own.
constexpr int CauseHoFailureInTargetEnbOrTargetSystem = 6;

} // namespace lte::enb::s1ap
