//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "types.hpp"

namespace lte::enb
{

const char *ToString(ConnectionState state)
{
    switch (state)
    {
    case ConnectionState::DISCONNECTED:
        return "DISCONNECTED";
    case ConnectionState::SCTP_CONNECTING:
        return "SCTP_CONNECTING";
    case ConnectionState::SCTP_ASSOCIATED:
        return "SCTP_ASSOCIATED";
    case ConnectionState::S1_SETUP_PENDING:
        return "S1_SETUP_PENDING";
    case ConnectionState::S1_SETUP_ESTABLISHED:
        return "S1_SETUP_ESTABLISHED";
    case ConnectionState::S1_SETUP_FAILED:
        return "S1_SETUP_FAILED";
    }
    return "UNKNOWN";
}

bool ConnectionStateMachine::transition(ConnectionEvent event)
{
    if (event == ConnectionEvent::CONNECTION_LOST)
    {
        m_state = ConnectionState::DISCONNECTED;
        return true;
    }

    switch (m_state)
    {
    case ConnectionState::DISCONNECTED:
    case ConnectionState::S1_SETUP_FAILED:
        if (event == ConnectionEvent::CONNECT_STARTED)
        {
            m_state = ConnectionState::SCTP_CONNECTING;
            return true;
        }
        break;
    case ConnectionState::SCTP_CONNECTING:
        if (event == ConnectionEvent::SCTP_CONNECTED)
        {
            m_state = ConnectionState::SCTP_ASSOCIATED;
            return true;
        }
        break;
    case ConnectionState::SCTP_ASSOCIATED:
        if (event == ConnectionEvent::SETUP_REQUEST_SENT)
        {
            m_state = ConnectionState::S1_SETUP_PENDING;
            return true;
        }
        break;
    case ConnectionState::S1_SETUP_PENDING:
        if (event == ConnectionEvent::SETUP_ACCEPTED)
        {
            m_state = ConnectionState::S1_SETUP_ESTABLISHED;
            return true;
        }
        if (event == ConnectionEvent::SETUP_REJECTED)
        {
            m_state = ConnectionState::S1_SETUP_FAILED;
            return true;
        }
        break;
    case ConnectionState::S1_SETUP_ESTABLISHED:
        break;
    }
    return false;
}

} // namespace lte::enb
