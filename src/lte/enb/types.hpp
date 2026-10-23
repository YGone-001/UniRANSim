//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lte::enb
{

struct Plmn
{
    std::string mcc;
    std::string mnc;

    [[nodiscard]] std::string toString() const
    {
        return mcc + "/" + mnc;
    }
};

struct RetryConfig
{
    int maxAttempts{3};
    int delayMs{2000};
    int responseTimeoutMs{10000};
    int connectMaxAttempts{2};
    int connectTimeoutMs{1000};
};

struct EnbConfig
{
    Plmn plmn;
    uint32_t enbId{};
    uint16_t tac{};
    std::optional<std::string> enbName;
    std::string localAddress;
    std::string mmeAddress;
    uint16_t mmePort{36412};
    int pagingDrx{128};
    std::string ueLinkAddress{"127.0.0.1"};
    uint16_t ueLinkPort{4998};
    // Real S1-U GTP-U endpoint owned by this eNB for the default EPS bearer.
    std::string s1uAddress{"127.0.0.1"};
    uint16_t s1uPort{2152};
    RetryConfig retry;
};

// Locally owned S1-U GTP-U TEID for one default EPS bearer. The value is never
// zero so the MME/SGW can tell an assigned tunnel endpoint from an empty one,
// and it is stable for a given E-RAB so release can reclaim it deterministically.
constexpr uint32_t AllocateLocalTeid(uint8_t erabId)
{
    return 0x00010000U | (static_cast<uint32_t>(erabId) << 8U) | 0x01U;
}

enum class ConnectionState
{
    DISCONNECTED,
    SCTP_CONNECTING,
    SCTP_ASSOCIATED,
    S1_SETUP_PENDING,
    S1_SETUP_ESTABLISHED,
    S1_SETUP_FAILED
};

enum class ConnectionEvent
{
    CONNECT_STARTED,
    SCTP_CONNECTED,
    SETUP_REQUEST_SENT,
    SETUP_ACCEPTED,
    SETUP_REJECTED,
    CONNECTION_LOST
};

const char *ToString(ConnectionState state);

class ConnectionStateMachine
{
  public:
    [[nodiscard]] ConnectionState state() const
    {
        return m_state;
    }
    bool transition(ConnectionEvent event);

  private:
    ConnectionState m_state{ConnectionState::DISCONNECTED};
};

} // namespace lte::enb
