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
    AUTHENTICATION_FAILED,
    SECURITY_MODE_COMMAND_RECEIVED,
    NAS_SECURITY_ACTIVE,
    SECURITY_MODE_COMPLETE_SENT,
    ESM_INFORMATION_REQUEST_RECEIVED,
    ESM_INFORMATION_RESPONSE_SENT,
    ATTACH_ACCEPT_RECEIVED,
    DEFAULT_BEARER_PENDING,
    ATTACH_COMPLETE_SENT,
    EPS_REGISTERED,
    DEFAULT_BEARER_SIGNALING_COMPLETE,
    TUN_READY,
    USER_PLANE_ACTIVE,
    PROCEDURE_FAILED
};

const char *ToString(State state);

// TS 33.401 5.1.3.1. EIA0 is null integrity and is not permitted for an
// ordinary authenticated EPS Attach. Only algorithms the LTE NAS stack can
// actually execute are reported as supported.
enum class IntegrityAlgorithm : uint8_t
{
    EIA0 = 0,
    EIA1 = 1,
    EIA2 = 2,
    EIA3 = 3
};

enum class CipheringAlgorithm : uint8_t
{
    EEA0 = 0,
    EEA1 = 1,
    EEA2 = 2,
    EEA3 = 3
};

// TS 24.301 9.3.1 security header types. Each carries a different protection
// meaning; they are not interchangeable.
enum class SecurityHeaderType : uint8_t
{
    PLAIN = 0,
    INTEGRITY_PROTECTED = 1,
    INTEGRITY_PROTECTED_AND_CIPHERED = 2,
    INTEGRITY_PROTECTED_WITH_NEW_CONTEXT = 3,
    INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_CONTEXT = 4
};

// The eNB-side default E-RAB signaling status. SIGNALING_ESTABLISHED remains
// distinct from UE TUN readiness and verified bidirectional IP reachability.
enum class BearerStatus
{
    NOT_CREATED,
    SETUP_PENDING,
    SIGNALING_ESTABLISHED,
    FAILED,
    RELEASED
};

const char *ToString(BearerStatus status);

struct LinkConfig
{
    std::string localAddress;
    uint16_t localPort{};
    std::string enbAddress;
    uint16_t enbPort{};
    int timeoutMs{15000};
};

struct TunConfig
{
    bool required{true};
    std::string namePrefix{"uniransim-lte"};
    int mtu{1400};
    // No routes are installed unless explicitly listed. A default route is
    // rejected; only validated IPv4 CIDR destinations are accepted.
    std::vector<std::string> routes;
};

enum class LifecycleScenario
{
    ATTACH_ONLY,
    DETACH,
    SERVICE_REQUEST,
    TAU_NORMAL,
    TAU_PERIODIC,
    // Network-triggered service restoration: release S1, remain ECM-IDLE and
    // wait for a paging indication instead of starting Service Request locally.
    PAGING
};

struct LifecycleConfig
{
    LifecycleScenario scenario{LifecycleScenario::ATTACH_ONLY};
    int triggerAfterMs{2000};
    int procedureTimeoutMs{5000};
    int maxRetries{3};
    bool switchOff{};
    // Bounded wait for the first network paging indication in the paging
    // scenario. A timeout is reported as a failure, never as paging success.
    int pagingWaitMs{60000};
};

struct Config
{
    std::string imsi;
    enb::Plmn plmn;
    // Simulated radio UE identity carried in every radio-link frame. Unique
    // among concurrently running lte-ue processes; defaults to the Phase 1
    // single-UE identity.
    uint32_t ueId{1};
    std::array<uint8_t, 16> key{};
    std::optional<std::array<uint8_t, 16>> op;
    std::optional<std::array<uint8_t, 16>> opc;
    std::array<uint8_t, 2> amf{};
    std::array<uint8_t, 6> initialSqn{};
    std::string pdnType{"IPv4"};
    std::optional<std::string> apn;
    // Truthful EPS UE network capability: EEA0+EEA2 and EIA2 (TS 24.301
    // 9.9.3.34). Only algorithms the LTE NAS stack actually implements are
    // advertised. See ValidateSecurityModeCommand.
    std::array<uint8_t, 2> networkCapability{{0xA0, 0x20}};
    // Synthetic identity used only when the network requests an IMEISV. It is
    // not a subscriber secret and not a real device identity.
    std::array<uint8_t, 8> imeisv{{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}};
    LinkConfig link;
    TunConfig tun;
    LifecycleConfig lifecycle;
};

// In-memory EPS security context. Phase 1 fills the AKA half; Phase 2 derives
// and activates the NAS half after a successfully validated Security Mode
// Command. Nothing here is ever logged or written to disk.
struct SecurityContext
{
    // EPS AKA (Phase 1)
    std::array<uint8_t, 32> kasme{};
    std::array<uint8_t, 16> ck{};
    std::array<uint8_t, 16> ik{};
    std::array<uint8_t, 6> sqn{};
    bool valid{};

    // EPS NAS security (Phase 2)
    uint8_t ksi{7};
    IntegrityAlgorithm integrity{IntegrityAlgorithm::EIA2};
    CipheringAlgorithm ciphering{CipheringAlgorithm::EEA0};
    std::array<uint8_t, 16> kNasInt{};
    std::array<uint8_t, 16> kNasEnc{};
    uint32_t ulNasCount{}; // 24-bit, TS 24.301 4.4.3.1
    uint32_t dlNasCount{};
    bool keysDerived{};
    bool securityActive{};
    // Exact octets advertised in the Attach Request, kept for the TS 24.301
    // 5.4.3.3 replay check of the Security Mode Command.
    std::vector<uint8_t> advertisedSecurityCapabilities;
};

} // namespace lte::ue
