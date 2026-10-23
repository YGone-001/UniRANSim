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
    }
    return "UNKNOWN";
}

} // namespace lte::ue
