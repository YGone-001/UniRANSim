//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"
#include "user_plane.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <utils/network.hpp>

namespace lte::enb
{

// Simulated S1 signalling lifecycle of one radio UE at the eNB. IDLE_RETAINED
// keeps the entry while the UE holds its EPS registration without an S1
// connection, matching an ECM-IDLE UE that may send a Service Request later.
enum class UeS1State
{
    NO_S1,
    CONTEXT_PENDING,
    CONTEXT_ESTABLISHED,
    BEARER_ACTIVE,
    IDLE_RETAINED
};

const char *ToString(UeS1State state);

struct UserPlaneCounters
{
    uint64_t simulatedUplinkPackets{};
    uint64_t simulatedUplinkBytes{};
    uint64_t simulatedDownlinkPackets{};
    uint64_t simulatedDownlinkBytes{};
    uint64_t s1uUplinkPackets{};
    uint64_t s1uUplinkBytes{};
    uint64_t s1uDownlinkPackets{};
    uint64_t s1uDownlinkBytes{};
    uint64_t malformedDrops{};
    uint64_t invalidTeidDrops{};
    uint64_t unexpectedPeerDrops{};
    uint64_t bearerInactiveDrops{};
};

class RegistryError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

// Per-UE eNB state. The simulated radio identity and its verified UDP peer are
// stable for the entry lifetime; the S1AP identifiers, the default bearer and
// the local S1-U TEID belong to one S1 connection and are invalidated when
// that connection is released.
struct EnbUeEntry
{
    uint32_t radioUeId{};
    InetAddress peer{};
    UeS1State s1{UeS1State::NO_S1};
    // Zero while no S1 connection exists; allocated fresh for every context.
    uint32_t enbUeS1apId{};
    // Zero until the MME assigns one; never invented locally.
    uint32_t mmeUeS1apId{};
    DefaultBearerContext bearer{};
    // The default bearer remains named for Phase 6 source compatibility.
    // Together with these bounded contexts it forms the per-UE EPS bearer
    // collection; matching EBI values in different UE entries are valid.
    static constexpr size_t MaxDedicatedBearers = 7;
    std::vector<BearerContext> dedicatedBearers;
    InetAddress sgwPeer{};
    UserPlaneCounters counters{};
    std::optional<UeAmbr> ueAmbr;
    // Simulated paging notifications delivered to this radio endpoint. It
    // counts delivery only; it is not evidence that the page was accepted.
    uint64_t pagingNotifications{};

    [[nodiscard]] bool s1Active() const
    {
        return s1 == UeS1State::CONTEXT_PENDING || s1 == UeS1State::CONTEXT_ESTABLISHED ||
               s1 == UeS1State::BEARER_ACTIVE;
    }
};

struct BearerLocation
{
    EnbUeEntry *entry{};
    BearerContext *bearer{};
};

// SCTP stream selection for UE-associated signalling. Stream zero carries
// non-UE S1AP such as S1 Setup; UE signalling is spread across the remaining
// negotiated outbound streams, with sharing when fewer streams than UEs exist.
uint16_t SctpStreamForUe(int outboundStreams, uint32_t enbUeS1apId);

// Bounded registry of concurrently served radio UEs with the identity indexes
// the S1AP dispatcher and the shared S1-U endpoint demultiplex by: radio UE
// ID, verified UDP peer, eNB-UE-S1AP-ID, MME-UE-S1AP-ID and local GTP-U TEID.
class UeRegistry
{
  public:
    explicit UeRegistry(size_t maxUes);

    // Registers a simulated radio identity and its verified UDP peer. A
    // duplicate radio identity, an identity claimed from another endpoint, an
    // endpoint already bound to another identity, or a full registry is
    // rejected.
    EnbUeEntry &registerPeer(uint32_t radioUeId, const InetAddress &peer);

    EnbUeEntry *find(uint32_t radioUeId);
    EnbUeEntry *findByPeer(const InetAddress &peer);
    EnbUeEntry *findByEnbUeS1apId(uint32_t enbUeS1apId);
    EnbUeEntry *findByMmeUeS1apId(uint32_t mmeUeS1apId);
    EnbUeEntry *findByLocalTeid(uint32_t teid);
    BearerLocation findBearerByLocalTeid(uint32_t teid);
    BearerContext *findBearer(EnbUeEntry &entry, uint8_t ebi);
    const BearerContext *findBearer(const EnbUeEntry &entry, uint8_t ebi) const;

    // Inserts a dedicated bearer only after validating that its linked default
    // EBI belongs to this exact UE and that capacity/EBI uniqueness hold.
    BearerContext &addDedicatedBearer(EnbUeEntry &entry, const BearerParameters &parameters);
    void releaseBearer(EnbUeEntry &entry, uint8_t ebi);

    // Allocates an eNB-UE-S1AP-ID unique among live contexts, skipping zero
    // and wrapping around without colliding with active identifiers.
    uint32_t allocateEnbUeS1apId();

    // Binds an S1 connection identifier to the entry. Both reject identifiers
    // already owned by another live context.
    void bindEnbUeS1apId(EnbUeEntry &entry, uint32_t enbUeS1apId);
    void setMmeUeS1apId(EnbUeEntry &entry, uint32_t mmeUeS1apId);

    // Allocates a local S1-U TEID unique across concurrently active bearers
    // and never zero.
    uint32_t allocateLocalTeid();
    void bindLocalTeid(EnbUeEntry &entry, uint32_t teid);
    void bindLocalTeid(EnbUeEntry &entry, BearerContext &bearer, uint32_t teid);

    // Releases the S1 connection of one UE: the S1AP identifiers and the local
    // GTP-U TEID stop resolving, the default bearer is released, and the entry
    // is retained in IDLE_RETAINED state for a later Service Request or
    // re-Attach. Other entries are untouched.
    void releaseS1(EnbUeEntry &entry);

    // Erases the entry and every index it owns.
    void remove(EnbUeEntry &entry);

    [[nodiscard]] size_t size() const;
    [[nodiscard]] size_t capacity() const;
    std::vector<EnbUeEntry *> all();

  private:
    size_t m_maxUes;
    uint32_t m_nextEnbUeS1apId{1};
    std::unordered_map<uint32_t, std::unique_ptr<EnbUeEntry>> m_byRadioUeId;
    // InetAddress has no std::hash specialization; its string form is unique.
    std::unordered_map<std::string, EnbUeEntry *> m_byPeer;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byEnbUeS1apId;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byMmeUeS1apId;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byLocalTeid;
};

std::array<uint8_t, 4> ParseIpv4(const std::string &address);
std::string Ipv4ToString(const std::array<uint8_t, 4> &address);
std::array<uint8_t, 4> TeidToBytes(uint32_t teid);
uint32_t TeidFromBytes(const std::array<uint8_t, 4> &value);

} // namespace lte::enb
