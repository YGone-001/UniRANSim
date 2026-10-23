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

} // namespace lte::enb::s1ap
