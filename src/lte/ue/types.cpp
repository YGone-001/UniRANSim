//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "types.hpp"

namespace lte::ue
{

const char *ToString(State state)
{
    switch (state)
    {
    case State::DISCONNECTED: return "UE_DISCONNECTED";
    case State::CONNECTED_TO_ENB: return "UE_CONNECTED_TO_ENB";
    case State::ATTACH_REQUEST_SENT: return "ATTACH_REQUEST_SENT";
    case State::AUTHENTICATION_PENDING: return "AUTHENTICATION_PENDING";
    case State::AUTHENTICATION_REQUEST_RECEIVED: return "AUTHENTICATION_REQUEST_RECEIVED";
    case State::AUTHENTICATION_RESPONSE_SENT: return "AUTHENTICATION_RESPONSE_SENT";
    case State::EPS_AKA_ACCEPTED: return "EPS_AKA_ACCEPTED";
    case State::AUTHENTICATION_FAILED: return "AUTHENTICATION_FAILED";
    case State::SECURITY_MODE_COMMAND_RECEIVED: return "SECURITY_MODE_COMMAND_RECEIVED";
    case State::NAS_SECURITY_ACTIVE: return "NAS_SECURITY_ACTIVE";
    case State::SECURITY_MODE_COMPLETE_SENT: return "SECURITY_MODE_COMPLETE_SENT";
    case State::ESM_INFORMATION_REQUEST_RECEIVED: return "ESM_INFORMATION_REQUEST_RECEIVED";
    case State::ESM_INFORMATION_RESPONSE_SENT: return "ESM_INFORMATION_RESPONSE_SENT";
    case State::ATTACH_ACCEPT_RECEIVED: return "ATTACH_ACCEPT_RECEIVED";
    case State::DEFAULT_BEARER_PENDING: return "DEFAULT_BEARER_PENDING";
    case State::ATTACH_COMPLETE_SENT: return "ATTACH_COMPLETE_SENT";
    case State::EPS_REGISTERED: return "EPS_REGISTERED";
    case State::DEFAULT_BEARER_SIGNALING_COMPLETE: return "DEFAULT_BEARER_SIGNALING_COMPLETE";
    case State::TUN_READY: return "TUN_READY";
    case State::USER_PLANE_ACTIVE: return "USER_PLANE_ACTIVE";
    case State::PROCEDURE_FAILED: return "PROCEDURE_FAILED";
    }
    return "UNKNOWN";
}

const char *ToString(BearerStatus status)
{
    switch (status)
    {
    case BearerStatus::NOT_CREATED: return "BEARER_NOT_CREATED";
    case BearerStatus::SETUP_PENDING: return "BEARER_SETUP_PENDING";
    case BearerStatus::SIGNALING_ESTABLISHED: return "BEARER_SIGNALING_ESTABLISHED";
    case BearerStatus::FAILED: return "BEARER_FAILED";
    case BearerStatus::RELEASED: return "BEARER_RELEASED";
    }
    return "BEARER_UNKNOWN";
}

} // namespace lte::ue
