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

// Bounded recovery after an established S1 association was lost. Zero
// maxAttempts means "retry until shutdown"; a positive value terminates the
// recovery loop so a permanently unavailable MME cannot spin forever.
struct RecoveryConfig
{
    int maxAttempts{0};
    int delayMs{2000};
    int delayMaxMs{15000};
};

// Opt-in failure injection for the test-owned eNB. The control file is only
// opened when a path is configured, so an ordinary deployment has no injection
// code path at all.
struct FailureInjectionConfig
{
    std::string controlFile;
    int pollIntervalMs{100};
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
    // Real S1-U GTP-U endpoint owned and advertised by this eNB.
    std::string s1uAddress;
    uint16_t s1uPort{2152};
    bool allowLoopbackS1u{false};
    // Bound on concurrently served simulated radio UEs in the registry.
    int maxUes{8};
    RetryConfig retry;
    RecoveryConfig recovery;
    FailureInjectionConfig failureInjection;
};

enum class ConnectionState
{
    DISCONNECTED,
    SCTP_CONNECTING,
    SCTP_ASSOCIATED,
    S1_SETUP_PENDING,
    S1_SETUP_ESTABLISHED,
    S1_SETUP_FAILED,
    // Entered after an established association was lost and a reconnection will
    // be attempted. It is not a failure state: it records that the running eNB
    // is between transport epochs.
    RECOVERING,
    // Terminal. Interrupts any backoff and stops UE and radio processing.
    STOPPING
};

enum class ConnectionEvent
{
    CONNECT_STARTED,
    SCTP_CONNECTED,
    SETUP_REQUEST_SENT,
    SETUP_ACCEPTED,
    SETUP_REJECTED,
    CONNECTION_LOST,
    RECOVERY_STARTED,
    SHUTDOWN_REQUESTED
};

// Bounded observability of the SCTP recovery loop. All counters are monotonic
// for the lifetime of the eNB runtime and never carry subscriber material.
// Post-recovery bearer traffic is deliberately not duplicated here: it is the
// per-UE UserPlaneCounters of UeEntry, which already count every forwarded
// packet on every bearer and are reported as a before/after delta.
struct RecoveryCounters
{
    uint64_t associationsEstablished{};
    uint64_t unexpectedAssociationLosses{};
    uint64_t injectedAssociationLosses{};
    uint64_t accessInvalidations{};
    uint64_t reconnectAttempts{};
    uint64_t reconnectSuccesses{};
    uint64_t reconnectFailures{};
    uint64_t s1SetupFailures{};
    uint64_t activeUesAffectedByLoss{};
    uint64_t logicalBearersRetained{};
    uint64_t localTeidsInvalidated{};
    uint64_t staleMessagesRejected{};
    uint64_t staleSenderRejects{};
    uint64_t unboundSenderRejects{};
    uint64_t successfulUeRestorations{};
    uint64_t failedUeRestorations{};
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
