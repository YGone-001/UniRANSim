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

std::vector<uint8_t> EncodeInitialUeMessage(const EnbConfig &config, uint32_t enbUeS1apId,
                                            const std::vector<uint8_t> &nasPdu);
std::vector<uint8_t> EncodeUplinkNasTransport(const EnbConfig &config, const UeContext &context,
                                              const std::vector<uint8_t> &nasPdu);
struct DownlinkNasTransport
{
    uint32_t enbUeS1apId{};
    uint32_t mmeUeS1apId{};
    std::vector<uint8_t> nasPdu;
};
DownlinkNasTransport DecodeDownlinkNasTransport(const uint8_t *data, size_t length);

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

} // namespace lte::enb::s1ap
