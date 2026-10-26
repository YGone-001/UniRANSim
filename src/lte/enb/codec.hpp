//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

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
    uint8_t priorityLevel{};
    bool preemptionCapability{};
    bool preemptionVulnerability{};
    std::array<uint8_t, 4> transportLayerAddress{};
    std::array<uint8_t, 4> gtpTeid{};
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

std::vector<uint8_t> EncodeInitialContextSetupResponse(uint32_t mmeUeS1apId, uint32_t enbUeS1apId,
                                                       const std::vector<ErabSetupItem> &erabs);

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

// One E-RAB item of an MME-initiated E-RAB Setup Request. The item layout is
// identical to the Initial Context Setup variant, which is why the same
// structure and decoder serve both.
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

// An E-RAB the eNB could not establish, reported per item so one failure cannot
// be mistaken for a success.
struct ErabFailedItem
{
    uint8_t erabId{};
    std::string causeCategory{"radioNetwork"};
    int causeValue{};
};

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

} // namespace lte::enb::s1ap
