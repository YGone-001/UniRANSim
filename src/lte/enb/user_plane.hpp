//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <lte/qos.hpp>
#include <stdexcept>

namespace lte::enb
{

uint32_t AllocateLocalTeid();

struct BearerParameters
{
    uint8_t erabId{};
    uint8_t qci{};
    uint32_t ueId{};
    std::array<uint8_t, 4> sgwAddress{};
    uint32_t sgwTeid{};
    uint32_t localTeid{};
    // Zero for a default bearer. A dedicated bearer must name the default EBI
    // of the same PDN connection.
    uint8_t linkedDefaultEbi{};
    ErabQos qos{};
};

enum class BearerKind : uint8_t
{
    DEFAULT,
    DEDICATED
};

class BearerError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

// Pure bearer mapping and validation. Socket ownership remains in the eNB
// runtime, while this object makes lifecycle and stale-TEID rules testable.
struct BearerPacketCounters
{
    uint64_t uplinkPackets{}, uplinkBytes{}, downlinkPackets{}, downlinkBytes{};
};

class DefaultBearerContext
{
  public:
    explicit DefaultBearerContext(BearerKind kind = BearerKind::DEFAULT) : m_kind(kind) {}
    void establish(const BearerParameters &parameters);
    void activateUe(uint32_t ueId, uint8_t epsBearerIdentity, const std::array<uint8_t, 4> &ipv4Address);
    void validateUplink(uint32_t ueId, const uint8_t *packet, size_t size) const;
    void validateDownlink(uint32_t incomingTeid, const uint8_t *packet, size_t size) const;
    void release();
    // Access release retains logical EPS identity, negotiated QoS and PDN address.
    void releaseAccessTransport();
    void recordUplink(size_t size) { ++m_counters.uplinkPackets; m_counters.uplinkBytes += size; }
    void recordDownlink(size_t size) { ++m_counters.downlinkPackets; m_counters.downlinkBytes += size; }
    [[nodiscard]] const BearerPacketCounters &counters() const { return m_counters; }
    [[nodiscard]] bool logicalConfirmed() const { return m_logicalConfirmed; }
    [[nodiscard]] bool restorationPending() const { return m_restoringAccess; }
    [[nodiscard]] bool logicalExists() const { return m_parameters.erabId != 0; }
    // Candidate validation precedes assignment. Neither operation recreates the bearer.
    void modifyQos(const ErabQos &qos);
    void modifyTransport(const std::array<uint8_t, 4> &address, uint32_t teid);

    [[nodiscard]] bool signalingEstablished() const { return m_established; }
    [[nodiscard]] bool active() const { return m_established && m_ueReady; }
    [[nodiscard]] const BearerParameters &parameters() const { return m_parameters; }
    [[nodiscard]] const std::array<uint8_t, 4> &ueIpv4() const { return m_ueIpv4; }
    [[nodiscard]] BearerKind kind() const { return m_kind; }

  private:
    BearerParameters m_parameters{};
    BearerPacketCounters m_counters{};
    std::array<uint8_t, 4> m_ueIpv4{};
    bool m_established{};
    bool m_restoringAccess{};
    bool m_logicalConfirmed{};
    bool m_ueReady{};
    BearerKind m_kind;
};

using BearerContext = DefaultBearerContext;

} // namespace lte::enb
