//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// EPS NAS primitives used by the Phase 1 LTE UE only.
#pragma once

#include "types.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace lte::ue::nas
{

class DecodeError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

struct AuthenticationRequest
{
    uint8_t ksi{};
    std::array<uint8_t, 16> rand{};
    std::array<uint8_t, 16> autn{};
};

enum class AkaFailure
{
    NONE,
    MALFORMED,
    MAC_FAILURE,
    SYNCHRONIZATION_FAILURE
};

struct AkaResult
{
    AkaFailure failure{AkaFailure::MALFORMED};
    std::array<uint8_t, 8> res{};
    SecurityContext context{};
};

std::vector<uint8_t> EncodeImsi(const std::string &imsi);
std::vector<uint8_t> EncodeAttachRequest(const Config &config);
AuthenticationRequest DecodeAuthenticationRequest(const uint8_t *data, size_t size);
std::vector<uint8_t> EncodeAuthenticationResponse(const std::array<uint8_t, 8> &res);
std::vector<uint8_t> EncodeAuthenticationFailureMac();
bool IsSecurityModeCommand(const uint8_t *data, size_t size);
AkaResult Authenticate(const Config &config, const AuthenticationRequest &request);

} // namespace lte::ue::nas
