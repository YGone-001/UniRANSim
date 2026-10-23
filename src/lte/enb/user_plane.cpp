//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "user_plane.hpp"

#include <atomic>
#include <random>

#include <lte/ip_packet.hpp>

namespace lte::enb
{

uint32_t AllocateLocalTeid()
{
    // Process-wide monotonic allocation prevents an old downlink packet from a
    // released context matching the next Attach. Zero is permanently skipped.
    static std::atomic<uint32_t> next{[] {
        std::random_device random;
        uint32_t seed = (static_cast<uint32_t>(random()) << 16U) ^ static_cast<uint32_t>(random());
        return seed == 0 ? 1U : seed;
    }()};
    uint32_t value = next.fetch_add(1U, std::memory_order_relaxed);
    if (value == 0)
        value = next.fetch_add(1U, std::memory_order_relaxed);
    return value;
}

void DefaultBearerContext::establish(const BearerParameters &parameters)
{
    if (m_established)
        throw BearerError("A default bearer is already established");
    if (parameters.erabId < 5 || parameters.erabId > 15 || parameters.qci == 0 || parameters.ueId == 0 ||
        parameters.sgwTeid == 0 || parameters.localTeid == 0)
        throw BearerError("Invalid default bearer parameters");
    m_parameters = parameters;
    m_ueIpv4 = {};
    m_established = true;
    m_ueReady = false;
}

void DefaultBearerContext::activateUe(uint32_t ueId, uint8_t epsBearerIdentity,
                                      const std::array<uint8_t, 4> &ipv4Address)
{
    if (!m_established)
        throw BearerError("Default bearer signaling is not established");
    if (m_ueReady)
        throw BearerError("Default bearer is already active");
    if (ueId != m_parameters.ueId)
        throw BearerError("Bearer-ready UE identity does not match the S1 context");
    if (epsBearerIdentity != m_parameters.erabId)
        throw BearerError("EPS bearer identity does not match the E-RAB");
    if (ipv4Address == std::array<uint8_t, 4>{})
        throw BearerError("Assigned UE IPv4 address is zero");
    m_ueIpv4 = ipv4Address;
    m_ueReady = true;
}

void DefaultBearerContext::validateUplink(uint32_t ueId, const uint8_t *packet, size_t size) const
{
    if (!active())
        throw BearerError("Default bearer is inactive");
    if (ueId != m_parameters.ueId)
        throw BearerError("Uplink UE identity does not match the bearer");
    const auto ipv4 = ip::Validate(packet, size);
    if (ipv4.source != m_ueIpv4)
        throw BearerError("Uplink IPv4 source does not match the assigned UE address");
}

void DefaultBearerContext::validateDownlink(uint32_t incomingTeid, const uint8_t *packet, size_t size) const
{
    if (!active())
        throw BearerError("Default bearer is inactive");
    if (incomingTeid != m_parameters.localTeid)
        throw BearerError("Unknown or stale downlink TEID");
    const auto ipv4 = ip::Validate(packet, size);
    if (ipv4.destination != m_ueIpv4)
        throw BearerError("Downlink IPv4 destination does not match the assigned UE address");
}

void DefaultBearerContext::release()
{
    m_parameters = {};
    m_ueIpv4 = {};
    m_ueReady = false;
    m_established = false;
}

} // namespace lte::enb
