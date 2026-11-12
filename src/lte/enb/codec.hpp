//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"
#include <lte/qos.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace lte::enb::s1ap
{

class CodecError : public std::runtime_error
{
  public:
    explicit CodecError(const std::string &message) : std::runtime_error(message)
    {
    }
};

std::array<uint8_t, 3> EncodePlmn(const Plmn &plmn);
Plmn DecodePlmn(const uint8_t *data, size_t length);

std::vector<uint8_t> EncodeS1SetupRequest(const EnbConfig &config);

struct DecodedSetupRequest
{
    Plmn plmn;
    uint32_t enbId{};
    uint16_t tac{};
    std::vector<Plmn> broadcastPlmns;
    int pagingDrx{};
    std::optional<std::string> enbName;
};

DecodedSetupRequest DecodeS1SetupRequest(const uint8_t *data, size_t length);

// One-UE Phase 1 S1AP NAS transport. These routines intentionally expose only the
// message subset used by the LTE UE vertical slice.
struct UeContext
{
    uint32_t enbUeS1apId{};
    std::optional<uint32_t> mmeUeS1apId;
};

struct STmsi
{
    uint8_t mmeCode{};
    uint32_t mTmsi{};
};

std::vector<uint8_t> EncodeInitialUeMessage(const EnbConfig &config, uint32_t enbUeS1apId,
                                            const std::vector<uint8_t> &nasPdu,
                                            std::optional<STmsi> sTmsi = std::nullopt);
std::vector<uint8_t> EncodeUplinkNasTransport(const EnbConfig &config, const UeContext &context,
                                              const std::vector<uint8_t> &nasPdu);
struct DownlinkNasTransport
{
    uint32_t enbUeS1apId{};
    uint32_t mmeUeS1apId{};
    std::vector<uint8_t> nasPdu;
};
DownlinkNasTransport DecodeDownlinkNasTransport(const uint8_t *data, size_t length);
// Encoder used by the automated tests and for offline fixture generation.
std::vector<uint8_t> EncodeDownlinkNasTransport(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                const std::vector<uint8_t> &nasPdu);

// The NAS payload of an uplink S1AP message and the UE it belongs to. It
// accepts the two messages an eNB sends a UE's NAS uplink in — an Initial UE
// Message and an Uplink NAS Transport — and returns their content without
// interpreting it. The NAS belongs to the UE and to its MME; this codec only
// carries it, exactly as it carries an opaque handover container.
struct UplinkNas
{
    uint32_t enbUeS1apId{};
    // Absent on an Initial UE Message, which is what starts the association
    // and is sent before the MME has named the UE.
    std::optional<uint32_t> mmeUeS1apId;
    std::vector<uint8_t> nasPdu;
};

UplinkNas DecodeUplinkNas(const uint8_t *data, size_t length);

struct ServedGummei
{
    std::vector<Plmn> plmns;
    std::vector<uint16_t> groupIds;
    std::vector<uint8_t> mmeCodes;
};

enum class OutcomeType
{
    RESPONSE,
    FAILURE
};

struct SetupOutcome
{
    OutcomeType type{};
    std::optional<std::string> mmeName;
    std::vector<ServedGummei> servedGummeis;
    std::optional<uint8_t> relativeMmeCapacity;
    std::string causeCategory;
    int causeValue{-1};
    std::string causeText;
    std::optional<int> timeToWaitSeconds;
    bool diagnosticsPresent{};
};

SetupOutcome DecodeS1SetupOutcome(const uint8_t *data, size_t length);

// --- Phase 2: Initial Context Setup and UE Context Release -------------------

// Minimal PDU probe so the eNB dispatcher can route an inbound S1AP message
// before a full decode.
struct S1apPdu
{
    enum class Kind
    {
        INITIATING,
        SUCCESSFUL_OUTCOME,
        UNSUCCESSFUL_OUTCOME
    };

    Kind kind{};
    uint16_t procedureCode{};
};

S1apPdu ProbeS1apPdu(const uint8_t *data, size_t length);

// One E-RAB item of the Initial Context Setup Request (TS 36.413 9.1.4.2).
// The transport address and TEID identify the SGW S1-U endpoint; when the MME
// embeds a NAS-PDU it carries the protected EPS Attach Accept.
struct ErabToBeSetupItem
{
    uint8_t erabId{};
    uint8_t qci{};
    uint8_t priorityLevel{15};
    bool preemptionCapability{};
    bool preemptionVulnerability{};
    std::optional<GbrQos> gbr;
    std::array<uint8_t, 4> transportLayerAddress{};
    std::array<uint8_t, 4> gtpTeid{};
    bool ipv4Transport{true};
    bool nasPduPresent{};
    std::vector<uint8_t> nasPdu;
};

struct InitialContextSetupRequest
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    uint64_t ueAmbrUl{};
    uint64_t ueAmbrDl{};
    std::vector<ErabToBeSetupItem> erabs;
    std::array<uint8_t, 2> encryptionAlgorithms{};
    std::array<uint8_t, 2> integrityAlgorithms{};
    std::array<uint8_t, 32> securityKey{};
};

InitialContextSetupRequest DecodeInitialContextSetupRequest(const uint8_t *data, size_t length);
// Encoder used by the automated tests and for offline fixture generation.
std::vector<uint8_t> EncodeInitialContextSetupRequest(const InitialContextSetupRequest &request);

// E-RAB successfully established by the eNB, including the locally owned S1-U
// GTP-U endpoint that will receive the downlink user plane.
struct ErabSetupItem
{
    uint8_t erabId{};
    std::array<uint8_t, 4> transportLayerAddress{};
    std::array<uint8_t, 4> gtpTeid{};
};

// Per-E-RAB failure, shared by Initial Context Setup and E-RAB management.
struct ErabFailedItem
{
    uint8_t erabId{};
    std::string causeCategory{"radioNetwork"};
    int causeValue{};
};

std::vector<uint8_t> EncodeInitialContextSetupResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                       const std::vector<ErabSetupItem> &erabs,
                                                       const std::vector<ErabFailedItem> &failed = {});
std::vector<uint8_t> EncodeInitialContextSetupFailure(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                      const std::string &causeCategory, int causeValue);

struct UeContextReleaseCommand
{
    uint32_t mmeUeS1apId{};
    std::optional<uint32_t> enbUeS1apId;
    std::string causeCategory;
    int causeValue{-1};
};

UeContextReleaseCommand DecodeUeContextReleaseCommand(const uint8_t *data, size_t length);
// Encoder used by the automated tests and for offline fixture generation.
std::vector<uint8_t> EncodeUeContextReleaseCommand(uint32_t mmeUeS1apId, std::optional<uint32_t> enbUeS1apId,
                                                   const std::string &causeCategory, int causeValue);
std::vector<uint8_t> EncodeUeContextReleaseComplete(uint32_t mmeUeS1apId, uint32_t enbUeS1apId);

// The source eNB's answer to a UE Context Release Command. Both identifiers
// are mandatory and neither may be zero: the pair is what an MME correlates the
// answer with, and an answer that named no UE would correlate with everything.
struct UeContextReleaseComplete
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
};

UeContextReleaseComplete DecodeUeContextReleaseComplete(const uint8_t *data, size_t length);

struct UeContextReleaseRequest
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    std::string causeCategory;
    int causeValue{-1};
};

// TS 36.413 UE Context Release Request, procedure code 18. The default cause
// used by the runtime is radioNetwork/user-inactivity (20).
std::vector<uint8_t> EncodeUeContextReleaseRequest(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                   const std::string &causeCategory = "radioNetwork",
                                                   int causeValue = 20);
UeContextReleaseRequest DecodeUeContextReleaseRequest(const uint8_t *data, size_t length);

// --- Phase 7: S1AP E-RAB management (TS 36.413, procedures 5 and 7) ---------

// The common field storage is shared with Initial Context Setup, but the
// BearerSUReq wire layout has mandatory NAS and its own decoder.
struct ErabSetupRequest
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    std::vector<ErabToBeSetupItem> erabs;
};

// The MME sends this on an existing UE-associated S1 connection when it adds a
// dedicated bearer, so it must not be confused with Initial Context Setup.
ErabSetupRequest DecodeErabSetupRequest(const uint8_t *data, size_t length);
// Encoder used by the automated tests and for offline fixture generation.
std::vector<uint8_t> EncodeErabSetupRequest(const ErabSetupRequest &request);

struct ErabTransport
{
    std::array<uint8_t, 4> address{};
    uint32_t teid{};
    // Non-IPv4 root BIT STRINGs are decoded so the eNB can report a
    // per-E-RAB transport failure instead of timing out the whole request.
    bool ipv4{true};
};

struct ErabToBeModifiedItem
{
    uint8_t erabId{};
    ErabQos qos;
    std::vector<uint8_t> nasPdu;
    std::optional<ErabTransport> transport;
};

struct ErabModifyRequest
{
    uint32_t mmeUeS1apId{}, enbUeS1apId{};
    std::optional<UeAmbr> ueAmbr;
    std::vector<ErabToBeModifiedItem> erabs;
};

ErabModifyRequest DecodeErabModifyRequest(const uint8_t *data, size_t length);
// Offline fixture helper; independent ASN.1 fixtures also exercise the decoder.
std::vector<uint8_t> EncodeErabModifyRequest(const ErabModifyRequest &request);
std::vector<uint8_t> EncodeErabModifyResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                              const std::vector<uint8_t> &modified,
                                              const std::vector<ErabFailedItem> &failed);

std::vector<uint8_t> EncodeErabSetupResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                             const std::vector<ErabSetupItem> &established,
                                             const std::vector<ErabFailedItem> &failed);

struct ErabReleaseCommand
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    std::vector<uint8_t> erabIds;
    std::string causeCategory;
    int causeValue{-1};
    // The MME carries the NAS deactivation in the same message. It must be
    // forwarded to the UE unchanged; the eNB holds no NAS keys.
    bool nasPduPresent{false};
    std::vector<uint8_t> nasPdu;
};

ErabReleaseCommand DecodeErabReleaseCommand(const uint8_t *data, size_t length);
// Encoder used by the automated tests and for offline fixture generation.
std::vector<uint8_t> EncodeErabReleaseCommand(const ErabReleaseCommand &command);

// Per-E-RAB outcome of a release. The eNB reports every requested E-RAB.
std::vector<uint8_t> EncodeErabReleaseResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                               const std::vector<uint8_t> &releasedErabIds);

// --- Phase 6: S1AP Paging (TS 36.413, procedure code 10) --------------------

// One tracking area of a Paging TAI list: PLMN identity and 16-bit TAC.
struct Tai
{
    Plmn plmn;
    uint16_t tac{};
};

// Decoded S1AP Paging message. Paging is a non-UE-associated procedure, so no
// field here identifies an S1 UE context.
struct PagingMessage
{
    enum class Identity
    {
        S_TMSI,
        IMSI
    };

    // TS 36.413 UEIdentityIndexValue ::= INTEGER (0..1023). It is a DRX paging
    // frame input, never a substitute for the paging identity.
    uint16_t ueIdentityIndexValue{};
    Identity identity{Identity::S_TMSI};
    STmsi sTmsi{};
    // Raw TBCD octets when the network pages by IMSI; unsupported by this phase.
    std::vector<uint8_t> imsi;
    // 0 = ps-domain, 1 = cs-domain.
    uint8_t cnDomain{};
    // 1..16 tracking areas the MME is paging in.
    std::vector<Tai> taiList;
    // PagingDRX index: 0..3 meaning v32, v64, v128, v256.
    std::optional<uint8_t> pagingDrx;
};

// Decodes and fully validates a Paging initiating message. Throws CodecError on
// a wrong procedure code, non-initiating PDU kind, missing/duplicate mandatory
// IE, unexpected criticality, malformed S-TMSI/TAI/IMSI encoding, oversized
// collections or trailing APER bits.
PagingMessage DecodePaging(const uint8_t *data, size_t length);

// Minimal standards-valid Paging encoder for automated fixtures and offline
// captures. It must never be used to impersonate a real MME on the live S1
// interface.
std::vector<uint8_t> EncodePaging(const PagingMessage &message);

// --- Phase 18-A: S1-based connected-mode handover ---------------------------
//
// TS 36.413 V16.4.0 §9.1.3.1 defines three S1-based handover elementary
// procedures:
//
//   id-HandoverPreparation        (0)  HandoverRequired (initiating),
//                                      HandoverCommand (successful outcome),
//                                      HandoverPreparationFailure
//                                      (unsuccessful outcome)
//                                      procedure criticality reject
//   id-HandoverResourceAllocation (1)  HandoverRequest (initiating),
//                                      HandoverRequestAcknowledge
//                                      (successful outcome),
//                                      HandoverFailure (unsuccessful outcome)
//                                      procedure criticality reject
//   id-HandoverNotification       (2)  HandoverNotify (initiating)
//                                      procedure criticality ignore
//
// id-PathSwitchRequest (3) is the X2-based bearer path update. It is not
// modelled here and must never be substituted for Handover Notify or for the
// MME-controlled bearer path update.
//
// Every procedure code, IE identifier, criticality and presence value below is
// transcribed from the reference ASN.1 module (36413-g40.asn). Nothing is
// invented. In particular id-SourceID (3) is declared in that module but is
// referenced by no handover IE set, so no message here emits or requires it.

// HandoverType ::= ENUMERATED { intralte, ltetoutran, ltetogeran, utrantolte,
//                               gerantolte, ..., eps-to-5gs, fivegs-to-eps }.
// Only the intra-LTE root value is implemented; every other value is refused
// rather than encoded by guesswork.
enum class HandoverType : uint8_t
{
    INTRA_LTE = 0,
    LTE_TO_UTRAN = 1,
    LTE_TO_GERAN = 2,
    UTRAN_TO_LTE = 3,
    GERAN_TO_LTE = 4,
    EPS_TO_5GS = 5,
    FIVEGS_TO_EPS = 6
};

const char *ToString(HandoverType type);

// Global eNB identity and selected tracking area, exactly as Global-ENB-ID and
// TAI carry them. It names one eNB cell-side identity; the 20-bit macro eNB
// identifier is the only ENB-ID choice this codec supports.
struct EnbIdentity
{
    Plmn plmn;
    uint32_t enbId{};
    uint16_t tac{};
};

// EUTRAN-CGI ::= SEQUENCE { pLMNidentity, cell-ID E-UTRAN-CGI }, where the cell
// identifier is the 20-bit macro eNB identifier followed by an 8-bit local cell
// identifier.
struct EutranCgi
{
    Plmn plmn;
    uint32_t cellId{};
};

// A handover transparent container. Source-ToTarget-TransparentContainer and
// Target-ToSource-TransparentContainer are plain OCTET STRING whose contents
// are "coded according to the specifications of the target system". The eNB
// carries them byte-for-byte and never parses, trims or rewrites them, so no
// RRC or security field can be read out of, or written into, one here.
using TransparentContainer = std::vector<uint8_t>;

// Largest container this receiver accepts. It is a receiver bound, not a
// protocol limit: a longer container is refused as an invalid container rather
// than truncated, so a caller can never lose octets without being told.
constexpr size_t MaxTransparentContainerSize = 4096;

// E-RABToBeSetupItemHOReq ::= SEQUENCE {
//     e-RAB-ID E-RAB-ID,
//     transportLayerAddress TransportLayerAddress,
//     gTP-TEID GTP-TEID,
//     e-RABlevelQosParameters E-RABLevelQoSParameters,
//     iE-Extensions ... OPTIONAL, ... }
//
// The transport address precedes the QoS here, which is the reverse of both
// E-RABToBeSetupItemCtxtSUReq and E-RABToBeSetupItemBearerSUReq. This shape
// therefore has its own encoder and its own decoder and shares neither.
struct ErabToBeSetupItemHoReq
{
    uint8_t erabId{};
    // The SGW-side downlink endpoint this bearer will use at the target.
    std::array<uint8_t, 4> sgwAddress{};
    std::array<uint8_t, 4> sgwTeid{};
    ErabQos qos;
};

// E-RABAdmittedItem ::= SEQUENCE {
//     e-RAB-ID E-RAB-ID,
//     transportLayerAddress TransportLayerAddress,
//     gTP-TEID GTP-TEID,
//     dL-transportLayerAddress TransportLayerAddress OPTIONAL,
//     dL-gTP-TEID GTP-TEID OPTIONAL,
//     uL-TransportLayerAddress TransportLayerAddress OPTIONAL,
//     uL-GTP-TEID GTP-TEID OPTIONAL,
//     iE-Extensions ... OPTIONAL, ... }
//
// The mandatory pair is the target eNB's own transport endpoint. The optional
// pairs are forwarding endpoints the target offers the source; they are not
// bearer transport and establishing one is not done by decoding them.
struct ErabAdmittedItem
{
    uint8_t erabId{};
    std::array<uint8_t, 4> transportLayerAddress{};
    std::array<uint8_t, 4> gtpTeid{};
    bool dlForwardingPresent{false};
    std::array<uint8_t, 4> dlTransportLayerAddress{};
    std::array<uint8_t, 4> dlGtpTeid{};
    bool ulForwardingPresent{false};
    std::array<uint8_t, 4> ulTransportLayerAddress{};
    std::array<uint8_t, 4> ulGtpTeid{};
};

// E-RABFailedToSetupItemHOReqAck ::= SEQUENCE {
//     e-RAB-ID E-RAB-ID, cause Cause, iE-Extensions ... OPTIONAL, ... }
struct ErabFailedItemHoReqAck
{
    uint8_t erabId{};
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
};

// E-RABDataForwardingItem ::= SEQUENCE {
//     e-RAB-ID E-RAB-ID,
//     dL-transportLayerAddress OPTIONAL, dL-gTP-TEID OPTIONAL,
//     uL-TransportLayerAddress OPTIONAL, uL-GTP-TEID OPTIONAL,
//     iE-Extensions ... OPTIONAL, ... }
struct ErabDataForwardingItem
{
    uint8_t erabId{};
    bool dlForwardingPresent{false};
    std::array<uint8_t, 4> dlTransportLayerAddress{};
    std::array<uint8_t, 4> dlGtpTeid{};
    bool ulForwardingPresent{false};
    std::array<uint8_t, 4> ulTransportLayerAddress{};
    std::array<uint8_t, 4> ulGtpTeid{};
};

// SecurityContext ::= SEQUENCE {
//     nextHopChainingCount INTEGER (0..7),
//     nextHopParameter SecurityKey,
//     iE-Extensions ... OPTIONAL, ... }, SecurityKey ::= BIT STRING (SIZE(256)).
//
// This is handover security material. It is decoded from the MME's own
// signalling and it is never generated, never defaulted and never logged: an
// implementation that cannot obtain it refuses the message instead of
// substituting a plausible key.
struct SecurityContext
{
    uint8_t nextHopChainingCount{};
    std::array<uint8_t, 32> nextHopParameter{};
};

// --- Handover messages -----------------------------------------------------

// Handover Required: source eNB to MME, procedure 0 initiating message.
struct HandoverRequired
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    HandoverType handoverType{HandoverType::INTRA_LTE};
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
    // TargetID, restricted to the targeteNB-ID choice.
    EnbIdentity target;
    // Direct-Forwarding-Path-Availability, optional on the wire.
    bool directForwardingPathAvailable{false};
    // Source-ToTarget-TransparentContainer, mandatory and non-empty.
    TransparentContainer sourceToTarget;
};

// Handover Command: MME to source eNB, procedure 0 successful outcome.
struct HandoverCommand
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    HandoverType handoverType{HandoverType::INTRA_LTE};
    // Optional E-RABSubjecttoDataForwardingList. An admitted bearer without a
    // forwarding entry is one the source simply stops serving.
    std::vector<ErabDataForwardingItem> dataForwarding;
    // Target-ToSource-TransparentContainer, mandatory and non-empty.
    TransparentContainer targetToSource;
};

// Handover Preparation Failure: MME to source eNB, procedure 0 unsuccessful
// outcome. Note that it carries no eNB-UE-S1AP-ID beyond the pair, and its
// criticality is ignore throughout.
struct HandoverPreparationFailure
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
};

// Handover Request: MME to target eNB, procedure 1 initiating message.
struct HandoverRequest
{
    uint32_t mmeUeS1apId{};
    HandoverType handoverType{HandoverType::INTRA_LTE};
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
    UeAmbr ueAmbr;
    std::vector<ErabToBeSetupItemHoReq> erabs;
    // Source-ToTarget-TransparentContainer, mandatory and non-empty.
    TransparentContainer sourceToTarget;
    std::array<uint8_t, 2> encryptionAlgorithms{};
    std::array<uint8_t, 2> integrityAlgorithms{};
    // SecurityContext, mandatory. The next hop parameter is the MME's, never
    // one this code produced.
    SecurityContext securityContext;
};

// Handover Request Acknowledge: target eNB to MME, procedure 1 successful
// outcome. E-RABAdmittedList is mandatory and may not be empty.
struct HandoverRequestAcknowledge
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    std::vector<ErabAdmittedItem> admitted;
    std::vector<ErabFailedItemHoReqAck> failed;
    // Target-ToSource-TransparentContainer, mandatory and non-empty.
    TransparentContainer targetToSource;
};

// Handover Failure: target eNB to MME, procedure 1 unsuccessful outcome. It
// carries no eNB-UE-S1AP-ID, because the target has not yet bound one.
struct HandoverFailure
{
    uint32_t mmeUeS1apId{};
    std::string causeCategory{"radioNetwork"};
    int causeValue{-1};
};

// Handover Notify: target eNB to MME, procedure 2 initiating message. It
// reports where the UE actually arrived and is the trigger for the
// MME-controlled bearer path update. It carries no CriticalityDiagnostics.
struct HandoverNotify
{
    uint32_t mmeUeS1apId{};
    uint32_t enbUeS1apId{};
    EutranCgi cgi;
    Tai tai;
};

// --- Fail-closed refusals --------------------------------------------------
//
// The two wire failures above are what a conformant peer is told. These are
// what this implementation refuses internally, before anything is adopted. A
// refusal leaves every field of the caller's structures untouched and moves no
// state at all.
enum class HandoverRefusal
{
    // HandoverType names something this codec does not implement, or is a
    // reserved or extended value.
    UNSUPPORTED_HANDOVER_TYPE,
    // A transparent container is empty, oversized, or truncated.
    INVALID_TRANSPARENT_CONTAINER,
    // A mandatory information element is absent, duplicated, carries the wrong
    // criticality, is present when its condition forbids it, or appears where
    // the message's IE set does not include it. The class is the standard's
    // requirement that a message carry exactly the IE set it is defined with.
    MISSING_MANDATORY_IE,
    // An E-RAB list is empty, oversized, names an unexpected item type, has a
    // duplicate E-RAB identity, or carries QoS this implementation rejects.
    UNSUPPORTED_ERAB_LIST,
    // A UE-associated S1AP identity is zero or out of its range, or a TargetID
    // names something other than a target eNB.
    INVALID_CONTEXT_IDENTITY
};

const char *ToString(HandoverRefusal refusal);

class HandoverRefused : public CodecError
{
  public:
    HandoverRefused(HandoverRefusal refusal, const std::string &message)
        : CodecError(message), m_refusal(refusal)
    {
    }

    [[nodiscard]] HandoverRefusal refusal() const { return m_refusal; }

  private:
    HandoverRefusal m_refusal;
};

// --- Encoders ---------------------------------------------------------------
//
// Each encoder builds exactly the message a conformant peer expects and refuses
// anything this implementation would not accept itself. The tests and the
// offline fixture generators use these; they must never be used to impersonate
// a real MME or a real peer eNB on the live S1 interface.

std::vector<uint8_t> EncodeHandoverRequired(const HandoverRequired &message);
std::vector<uint8_t> EncodeHandoverCommand(const HandoverCommand &message);
std::vector<uint8_t> EncodeHandoverPreparationFailure(const HandoverPreparationFailure &message);
std::vector<uint8_t> EncodeHandoverRequest(const HandoverRequest &message);
std::vector<uint8_t> EncodeHandoverRequestAcknowledge(const HandoverRequestAcknowledge &message);
std::vector<uint8_t> EncodeHandoverFailure(const HandoverFailure &message);
std::vector<uint8_t> EncodeHandoverNotify(const HandoverNotify &message);

// --- Decoders ---------------------------------------------------------------
//
// Each decoder validates the PDU kind, the procedure code, the procedure
// criticality, every information element it understands, and every mandatory
// presence condition. A malformed, truncated, duplicated or unsupported message
// is refused rather than partially decoded.

HandoverRequired DecodeHandoverRequired(const uint8_t *data, size_t length);
HandoverCommand DecodeHandoverCommand(const uint8_t *data, size_t length);
HandoverPreparationFailure DecodeHandoverPreparationFailure(const uint8_t *data, size_t length);
HandoverRequest DecodeHandoverRequest(const uint8_t *data, size_t length);
HandoverRequestAcknowledge DecodeHandoverRequestAcknowledge(const uint8_t *data, size_t length);
HandoverFailure DecodeHandoverFailure(const uint8_t *data, size_t length);
HandoverNotify DecodeHandoverNotify(const uint8_t *data, size_t length);

} // namespace lte::enb::s1ap
