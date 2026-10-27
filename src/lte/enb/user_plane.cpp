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
        throw BearerError("An EPS bearer is already established");
    if (logicalExists() && (parameters.erabId != m_parameters.erabId ||
        parameters.ueId != m_parameters.ueId || parameters.linkedDefaultEbi != m_parameters.linkedDefaultEbi))
        throw BearerError("Access restoration cannot replace a logical EPS bearer identity");
    if (parameters.erabId < 5 || parameters.erabId > 15 || parameters.qci == 0 || parameters.ueId == 0 ||
        parameters.sgwTeid == 0 || parameters.localTeid == 0)
        throw BearerError("Invalid EPS bearer parameters");
    if (m_kind == BearerKind::DEFAULT && parameters.linkedDefaultEbi != 0)
        throw BearerError("A default bearer cannot have a linked EBI");
    if (m_kind == BearerKind::DEDICATED &&
        (parameters.linkedDefaultEbi < 5 || parameters.linkedDefaultEbi > 15 ||
         parameters.linkedDefaultEbi == parameters.erabId))
        throw BearerError("A dedicated bearer has an invalid linked default EBI");
    m_restoringAccess = logicalExists();
    m_parameters = parameters;
    m_established = true;
    m_ueReady = false;
}

void DefaultBearerContext::activateUe(uint32_t ueId, uint8_t epsBearerIdentity,
                                      const std::array<uint8_t, 4> &ipv4Address)
{
    if (!m_established)
        throw BearerError("EPS bearer signaling is not established");
    if (m_ueReady)
        throw BearerError("EPS bearer is already active");
    if (ueId != m_parameters.ueId)
        throw BearerError("Bearer-ready UE identity does not match the S1 context");
    if (epsBearerIdentity != m_parameters.erabId)
        throw BearerError("EPS bearer identity does not match the E-RAB");
    if (ipv4Address == std::array<uint8_t, 4>{})
        throw BearerError("Assigned UE IPv4 address is zero");
    m_ueIpv4 = ipv4Address;
    m_ueReady = true;
    m_logicalConfirmed = true;
    m_restoringAccess = false;
}

void DefaultBearerContext::validateUplink(uint32_t ueId, const uint8_t *packet, size_t size) const
{
    if (!active())
        throw BearerError("EPS bearer is inactive");
    if (ueId != m_parameters.ueId)
        throw BearerError("Uplink UE identity does not match the bearer");
    const auto ipv4 = ip::Validate(packet, size);
    if (ipv4.source != m_ueIpv4)
        throw BearerError("Uplink IPv4 source does not match the assigned UE address");
}

void DefaultBearerContext::validateDownlink(uint32_t incomingTeid, const uint8_t *packet, size_t size) const
{
    if (!active())
        throw BearerError("EPS bearer is inactive");
    if (incomingTeid != m_parameters.localTeid)
        throw BearerError("Unknown or stale downlink TEID");
    const auto ipv4 = ip::Validate(packet, size);
    if (ipv4.destination != m_ueIpv4)
        throw BearerError("Downlink IPv4 destination does not match the assigned UE address");
}

void DefaultBearerContext::release()
{
    m_parameters = {};
    m_logicalConfirmed = false;
    m_counters = {};
    m_ueIpv4 = {};
    m_ueReady = false;
    m_established = false;
    m_restoringAccess = false;
}

void DefaultBearerContext::releaseAccessTransport()
{
    m_parameters.localTeid = 0;
    m_parameters.sgwTeid = 0;
    m_parameters.sgwAddress = {};
    m_ueReady = false;
    m_established = false;
    m_restoringAccess = false;
}

void DefaultBearerContext::modifyQos(const ErabQos &qos)
{
    if (!m_established || !qos.valid())
        throw BearerError("Inactive bearer or invalid/unsupported E-RAB QoS");
    m_parameters.qos = qos;
    m_parameters.qci = qos.qci;
}

void DefaultBearerContext::modifyTransport(const std::array<uint8_t, 4> &address, uint32_t teid)
{
    if (!m_established || teid == 0 || address[0] == 0 || address[0] >= 224 ||
        address == std::array<uint8_t, 4>{255, 255, 255, 255})
        throw BearerError("Inactive bearer or invalid IPv4 S1-U transport endpoint");
    m_parameters.sgwAddress = address;
    m_parameters.sgwTeid = teid;
}

} // namespace lte::enb
