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
#include <map>
#include <stdexcept>
#include <unordered_map>

namespace lte::enb
{

uint32_t AllocateLocalTeid();

// A bounded record of the local S1-U TEIDs whose tunnel has been retired.
//
// Without it a retired identifier is indistinguishable from one that was never
// issued: both simply fail to resolve, and a delayed G-PDU or a reordered End
// Marker naming either looks the same. Keeping the record makes the two cases
// separable, which is what lets a late packet be reported as having outlived
// its tunnel and lets a second End Marker be recognised as a repeat of one
// already acted on instead of as a new event.
//
// The record holds only the identifier and the order in which it was retired.
// It keeps no UE identity, no peer address and no subscriber information, so a
// retired record can never disclose who the tunnel belonged to.
//
// The record is bounded. When it is full the longest-retired identifier is
// dropped first. That is safe because the allocator never hands out an
// identifier whose record still stands, and the allocator is monotonic across
// the whole process, so an evicted identifier is not handed out again before
// its own later turn in that sequence either. Eviction only ever ages the
// classification of a very late packet back to "unknown TEID"; it can never
// make an identifier valid twice over.
class RetiredTeidLedger
{
  public:
    static constexpr size_t DefaultCapacity = 4096;

    explicit RetiredTeidLedger(size_t capacity = DefaultCapacity);

    // Records the retirement of one local TEID. Zero is not a tunnel
    // identifier and is rejected. A second retirement of an identifier already
    // recorded is a duplicate or a reordered announcement and changes nothing,
    // which is what makes repeated End Markers idempotent. Returns true only
    // when this call is the one that recorded the retirement.
    bool retire(uint32_t teid);

    [[nodiscard]] bool contains(uint32_t teid) const;
    // Forgets a record because its identifier is being bound to a live tunnel
    // again. A live identifier is by definition not retired, and a record left
    // behind would keep the allocator from ever offering that identifier again.
    void revive(uint32_t teid);

    [[nodiscard]] size_t size() const { return m_byTeid.size(); }
    [[nodiscard]] size_t capacity() const { return m_capacity; }
    // How many records were dropped to stay within the bound. A non-zero value
    // is not a failure, but it is the point from which an identifier that was
    // once retired is no longer remembered as such.
    [[nodiscard]] uint64_t evictions() const { return m_evictions; }

  private:
    size_t m_capacity;
    std::unordered_map<uint32_t, uint64_t> m_byTeid;
    std::map<uint64_t, uint32_t> m_byOrder;
    uint64_t m_nextOrder{1};
    uint64_t m_evictions{};
};

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
    // GTP-U End Markers recognised on this tunnel's TEID. They are control
    // messages about the tunnel and are never counted as payload in either
    // direction. A second one is a repeat and raises only duplicateEndMarkers.
    uint64_t endMarkers{}, duplicateEndMarkers{};
};

class DefaultBearerContext
{
  public:
    explicit DefaultBearerContext(BearerKind kind = BearerKind::DEFAULT) : m_kind(kind) {}
    // Establishes the access transport of one EPS bearer. `restoringAccess`
    // marks the new access as a restoration of a logical bearer the UE's own
    // NAS has already confirmed, which is what makes the UE confirm the fresh
    // transport instead of treating it as a new bearer: it is true where this
    // context already held the logical bearer and where the UE declared the
    // bearer in its mobility uplink onto a cell that had never seen the
    // session. Neither case is an Initial Attach candidate, whose identity is
    // only confirmed later against the UE's validated NAS.
    void establish(const BearerParameters &parameters, bool restoringAccess);
    void establish(const BearerParameters &parameters) { establish(parameters, logicalExists()); }
    void activateUe(uint32_t ueId, uint8_t epsBearerIdentity, const std::array<uint8_t, 4> &ipv4Address);
    void validateUplink(uint32_t ueId, const uint8_t *packet, size_t size) const;
    void validateDownlink(uint32_t incomingTeid, const uint8_t *packet, size_t size) const;
    void release();
    // Access release retains logical EPS identity, negotiated QoS and PDN address.
    void releaseAccessTransport();
    void recordUplink(size_t size) { ++m_counters.uplinkPackets; m_counters.uplinkBytes += size; }
    void recordDownlink(size_t size) { ++m_counters.downlinkPackets; m_counters.downlinkBytes += size; }
    // Records one recognised End Marker on this tunnel. Only these two
    // observation counters move: the bearer keeps its transport, its identity
    // and its forwarding state, because an End Marker is not a release.
    void recordEndMarker()
    {
        if (m_counters.endMarkers != 0)
            ++m_counters.duplicateEndMarkers;
        ++m_counters.endMarkers;
    }
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
