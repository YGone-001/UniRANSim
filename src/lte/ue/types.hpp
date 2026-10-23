//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <lte/enb/types.hpp>

namespace lte::ue
{

enum class State
{
    DISCONNECTED,
    CONNECTED_TO_ENB,
    ATTACH_REQUEST_SENT,
    AUTHENTICATION_PENDING,
    AUTHENTICATION_REQUEST_RECEIVED,
    AUTHENTICATION_RESPONSE_SENT,
    EPS_AKA_ACCEPTED,
    AUTHENTICATION_FAILED
};

const char *ToString(State state);

struct LinkConfig
{
    std::string localAddress;
    uint16_t localPort{};
    std::string enbAddress;
    uint16_t enbPort{};
    int timeoutMs{15000};
};

struct Config
{
    std::string imsi;
    enb::Plmn plmn;
    std::array<uint8_t, 16> key{};
    std::optional<std::array<uint8_t, 16>> op;
    std::optional<std::array<uint8_t, 16>> opc;
    std::array<uint8_t, 2> amf{};
    std::array<uint8_t, 6> initialSqn{};
    std::string pdnType{"IPv4"};
    std::optional<std::string> apn;
    std::array<uint8_t, 2> networkCapability{{0xE0, 0xE0}};
    LinkConfig link;
};

struct SecurityContext
{
    std::array<uint8_t, 32> kasme{};
    std::array<uint8_t, 16> ck{};
    std::array<uint8_t, 16> ik{};
    std::array<uint8_t, 6> sqn{};
    bool valid{};
};

} // namespace lte::ue
