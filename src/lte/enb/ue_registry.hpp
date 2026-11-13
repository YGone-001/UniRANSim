//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "perf_counters.hpp"
#include "types.hpp"
#include "user_plane.hpp"

#include <lte/ue/radio_link.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
// stable for the entry lifetime; the S1AP identifiers, the access transport and
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
    uint32_t accessGeneration{};
    // How the current S1 connection was opened. A mobility uplink continues an
    // existing EPS session over a new S1 connection because the UE reselected
    // this cell in ECM-IDLE, and that is not an Initial Attach: the session's
    // bearer contexts survive and only the access epoch restarts.
    bool mobilityBootstrap{};
    // The bearer inventory the UE declared with that uplink: which E-RAB is its
    // default bearer and which are dedicated, all taken from contexts its own
    // NAS has already confirmed. A cell the UE reselected into holds no logical
    // EPS bearer context of the session, and the E-RAB list of an Initial
    // Context Setup Request names only identifiers and QoS and marks no roles,
    // so without this declaration the roles could only be guessed from QCI or
    // from the order of that list. The declaration is a claim about the UE's
    // own session and can only ever restrict what the network offered: an E-RAB
    // it does not name is not established for this UE, and one it names without
    // the network offering it establishes nothing at all.
    std::optional<lte::ue::link::BearerInventory> declaredBearers;
    // Whether the network still holds this UE's EPS session. A cell the UE
    // reselected into holds no bearer context of it at all, because a genuine
    // TAU establishes none, and ECM-IDLE then drops the access transport, so
    // neither the bearers nor the declaration is left to show that the session
    // is still there. What is left is this, and it is what lets an idle UE
    // whose session the MME holds ask for service again. The UE's own NAS
    // deleting that session, or starting a new Attach, clears it: a deleted
    // session holds nothing for anyone to restore.
    bool sessionRetained{};
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

// Opt-in fault points for the provisional-to-reached promotion. It is an
// argument, never a global: production calls `promoteProvisional` without one
// and cannot be made to fail by anything outside its own preconditions. A test
// passes one to reach the rollback that a working promotion cannot reach on its
// own, which is the only way to show that a half-published index never
// survives.
class PromotionFaultInjector
{
  public:
    enum class Fault : uint8_t
    {
        NONE,
        // Fail after the radio-peer index has been claimed, so the rollback has
        // one published index to undo.
        PEER_INDEX_PUBLICATION,
        // Fail after both indexes have been claimed, so the rollback has to
        // take the moved ownership back before it can undo them.
        RADIO_INDEX_PUBLICATION
    };

    constexpr PromotionFaultInjector() = default;
    constexpr explicit PromotionFaultInjector(Fault fault) : m_fault(fault)
    {
    }

    [[nodiscard]] constexpr Fault fault() const
    {
        return m_fault;
    }
    [[nodiscard]] constexpr bool firesAt(Fault point) const
    {
        return m_fault != Fault::NONE && m_fault == point;
    }

  private:
    Fault m_fault{Fault::NONE};
};

// Bounded registry of concurrently served radio UEs with the identity indexes
// the S1AP dispatcher and the shared S1-U endpoint demultiplex by: radio UE
// ID, verified UDP peer, eNB-UE-S1AP-ID, MME-UE-S1AP-ID and local GTP-U TEID.
class UeRegistry
{
  public:
    // `teidAllocator` supplies raw local TEID candidates. It is the process-wide
    // monotonic allocator in production; a test passes a deterministic sequence
    // to reach the exhaustion and boundary cases that a process-wide sequence
    // cannot reach on its own. Whatever the source, a candidate is only usable
    // once: `allocateLocalTeid` reserves it and `bindLocalTeid` accepts nothing
    // else. `retiredCapacity` bounds the retirement record; only a test lowers
    // it, to reach the eviction path on the same code a bearer runs.
    explicit UeRegistry(size_t maxUes, std::function<uint32_t()> teidAllocator = &AllocateLocalTeid,
                        size_t retiredCapacity = RetiredTeidLedger::DefaultCapacity);

    // Registers a simulated radio identity and its verified UDP peer. A
    // duplicate radio identity, an identity claimed from another endpoint, an
    // endpoint already bound to another identity, or a full registry is
    // rejected.
    EnbUeEntry &registerPeer(uint32_t radioUeId, const InetAddress &peer);

    // Creates a provisional target-side UE context for a handover preparation.
    //
    // A target eNB that has admitted a handover owns local S1-U transport for
    // bearers whose UE has not arrived yet. That ownership has to be real — the
    // identifiers come from this registry's allocator and are bound through
    // `bindLocalTeid` — but it is not a UE session. `registerPeer` demands a
    // simulated radio identity and a verified UDP peer precisely so that no
    // caller can manufacture an arrival, and a prepared handover has neither:
    // the UE is still at the source eNB. Inventing a peer to reuse that API
    // would be inventing the arrival this context is waiting for.
    //
    // So a provisional entry has `radioUeId == 0`, a value `registerPeer`
    // refuses and therefore one no reached UE can ever hold. The two kinds of
    // entry are structurally distinguishable and cannot be confused. It is
    // absent from the radio-identity and peer indexes, so `find` and
    // `findByPeer` never return it, while its S1AP identifiers and its local
    // TEIDs are indexed exactly like a reached UE's, which is what lets the
    // shared S1-U endpoint recognise its transport and refuse to forward to a
    // bearer that has not been made UE-ready.
    //
    // It is counted against the same `maxUes` bound as a reached UE, because
    // every provisional context consumes per-UE resources and per-UE TEIDs. A
    // full registry refuses it and allocates nothing.
    EnbUeEntry &allocateProvisional();

    // Whether this entry was created by `allocateProvisional`, that is, whether
    // it owns prepared resources for a UE that has not arrived.
    [[nodiscard]] static bool isProvisional(const EnbUeEntry &entry)
    {
        return entry.radioUeId == 0;
    }

    // Whether this registry currently holds the entry as one of its provisional
    // contexts. It is how a caller that holds a pointer to a prepared context
    // checks that the registry still owns it before touching it, rather than
    // trusting a pointer that a cleanup may already have released.
    [[nodiscard]] bool holdsProvisional(const EnbUeEntry &entry) const;

    // Erases a provisional entry and everything it owns. Every prepared bearer
    // is released through `unbindLocalTeid`, so a TEID that was actually bound
    // is retired through the normal lifecycle while one that was only reserved
    // is dropped without ever having been a tunnel. Calling it twice is
    // idempotent for the resources in question: the second call finds nothing
    // owned by this entry and cannot touch another transaction's identifiers.
    void removeProvisional(EnbUeEntry &entry);

    // Moves a provisional target context into the reached-UE indexes and gives
    // it the radio identity and peer it arrived under. This is the only way a
    // provisional context becomes a reached UE, and it is a move: the same
    // `EnbUeEntry` object keeps its bearers, its S1AP identifiers and its local
    // S1-U TEIDs, and no second entry is created to copy them into.
    //
    // Validation happens before anything is published. It refuses a context
    // that is not provisional, a zero radio identity, an entry this registry
    // does not hold, a radio identity another UE already owns, a radio endpoint
    // that already carries a UE, and a context whose S1AP identifiers are
    // already held by another entry. A refusal leaves the context provisional
    // and every index exactly as it was. There is no capacity check: the
    // provisional entry already occupies its slot, so promotion moves it rather
    // than consuming another one.
    //
    // Publication is rolled back if it does not complete, so no partially
    // published radio or peer index can survive: the context goes back to being
    // the provisional one it was and still owns everything it owned.
    //
    // The move also re-binds every prepared bearer to the arrived radio
    // identity. A prepared bearer is established against the only identity the
    // target held before the UE arrived — the MME-UE-S1AP-ID of its transaction
    // — while `forwardUplink` validates against the arriving UE's radio
    // identity, so a bearer that is not re-bound refuses every uplink of the UE
    // it was prepared for. That re-binding is part of the move and is undone by
    // the same rollback, so a promotion never leaves a published context whose
    // bearers are still bound to a UE that is not the one that arrived.
    EnbUeEntry &promoteProvisional(EnbUeEntry &entry, uint32_t radioUeId, const InetAddress &peer,
                                  const PromotionFaultInjector &faults = {});

    // The exact inverse of `promoteProvisional`, for a promotion that must not
    // stand because a later step of the same arrival did not complete.
    //
    // It unpublishes the radio and peer indexes, re-binds every prepared bearer
    // back to the MME-UE-S1AP-ID the preparation was committed under, clears the
    // radio identity and the peer, and returns the entry to the provisional map.
    // No TEID, no S1AP identifier and no capacity slot moves: the context keeps
    // the transport it owns and stays counted where it was.
    //
    // It refuses rather than guesses. A bearer that is already UE-ready is not
    // one this rollback may touch, a bearer bound to an identity other than the
    // arrived radio identity has moved since the promotion and is not re-pointed
    // here, and a context whose `mmeUeS1apId` is zero cannot have its prepared
    // bearers bound back to anything. Each of those leaves the context exactly
    // as it is and throws, because a half-reverted context is worse than the
    // reached one it started from.
    void demoteToProvisional(EnbUeEntry &entry);

    EnbUeEntry *find(uint32_t radioUeId);
    EnbUeEntry *findByPeer(const InetAddress &peer);
    EnbUeEntry *findByEnbUeS1apId(uint32_t enbUeS1apId);
    [[nodiscard]] const EnbUeEntry *findByEnbUeS1apId(uint32_t enbUeS1apId) const;
    EnbUeEntry *findByMmeUeS1apId(uint32_t mmeUeS1apId);
    EnbUeEntry *findByLocalTeid(uint32_t teid);
    BearerLocation findBearerByLocalTeid(uint32_t teid);
    BearerContext *findBearer(EnbUeEntry &entry, uint8_t ebi);
    const BearerContext *findBearer(const EnbUeEntry &entry, uint8_t ebi) const;

    // Inserts a dedicated bearer only after validating that its linked default
    // EBI belongs to this exact UE and that capacity/EBI uniqueness hold.
    // `accessRestoration` marks the new context as a restoration of a bearer
    // the UE's NAS already confirmed rather than a freshly activated one, which
    // is how a dedicated E-RAB established by a fresh-target mobility bootstrap
    // is confirmed generation-bound instead of being treated as a new bearer.
    BearerContext &addDedicatedBearer(EnbUeEntry &entry, const BearerParameters &parameters,
                                      bool accessRestoration = false);
    void releaseBearer(EnbUeEntry &entry, uint8_t ebi);

    // Allocates an eNB-UE-S1AP-ID unique among live contexts, skipping zero
    // and wrapping around without colliding with active identifiers.
    uint32_t allocateEnbUeS1apId();

    // Binds an S1 connection identifier to the entry. Both reject identifiers
    // already owned by another live context.
    void bindEnbUeS1apId(EnbUeEntry &entry, uint32_t enbUeS1apId);
    void setMmeUeS1apId(EnbUeEntry &entry, uint32_t mmeUeS1apId);
    void clearMmeUeS1apId(EnbUeEntry &entry);

    // Reserves a local S1-U TEID for one bearer and returns it. The value is
    // unique across concurrently active bearers, never zero, and never one that
    // is still remembered as retired. It is not yet bound: `bindLocalTeid` must
    // be called with exactly this value, and only a value this function
    // reserved can be bound at all. That contract is what stops a caller
    // attaching an identifier chosen by hand and so bypassing the allocator's
    // no-reissue guarantee.
    //
    // The search is bounded. With the production allocator, which never offers
    // the same value twice, at most one candidate can be unusable; the bound
    // only exists so that a pathological allocator fails deterministically
    // instead of looping for ever. Exhaustion throws RegistryError, and
    // TeidExhausted from a spent production allocator is propagated unchanged:
    // both leave no reservation behind.
    uint32_t allocateLocalTeid();
    // Binds a reserved identifier to a bearer of this entry. Both overloads
    // refuse a zero identifier, an identifier already owned by another bearer,
    // an identifier this registry never reserved, and one still recorded as
    // retired. Refusing the last is absolute: a retired identifier is never
    // rebound to a live tunnel, so a delayed packet of an old tunnel can never
    // resolve against a new one. There is no revival.
    void bindLocalTeid(EnbUeEntry &entry, uint32_t teid);
    void bindLocalTeid(EnbUeEntry &entry, BearerContext &bearer, uint32_t teid);

    // Whether this local TEID names a tunnel that has already been retired.
    // It answers only that: a false answer does not distinguish an identifier
    // that was never issued from one whose retirement record has aged out.
    [[nodiscard]] bool isRetiredTeid(uint32_t teid) const;
    [[nodiscard]] const RetiredTeidLedger &retiredTeids() const { return m_retiredTeids; }

    // Releases the S1 connection of one UE: the S1AP identifiers and the local
    // GTP-U TEIDs stop resolving, logical bearers are retained, and the entry
    // is retained in IDLE_RETAINED state for a later Service Request or
    // re-Attach. Other entries are untouched.
    void releaseS1(EnbUeEntry &entry);

    // Releases a UE context that a completed connected handover has moved to
    // another cell.
    //
    // It is deliberately not `releaseS1` plus `remove`. `releaseS1` is the
    // ECM-IDLE transition: it retains the logical EPS bearer contexts, keeps the
    // entry, marks the session retained and lets the caller tell the UE that its
    // access ended. None of that is true of a UE that is now connected to the
    // target, so this path retains nothing, tells nobody and leaves no entry.
    //
    // Every bound local S1-U TEID is retired through the ordinary ledger, so a
    // delayed G-PDU is classified as traffic that outlived its tunnel. The
    // S1AP identity indexes, the radio identity index and the peer index are
    // all dropped, and the entry is erased. It refuses a provisional context
    // and an entry this registry does not hold, so it can never reach another
    // transaction's resources.
    void removeHandoverSource(EnbUeEntry &entry);
    // Stops a local TEID resolving. A live mapping of this entry is retired
    // through `retireLocalTeid`, so it becomes identifiable as retired rather
    // than merely missing. A value that is not a live mapping of this entry is
    // an outstanding reservation from an establishment that did not complete,
    // and dropping the reservation is the rollback that keeps a failed
    // establishment from leaking one.
    void unbindLocalTeid(EnbUeEntry &entry, uint32_t teid);
    void deleteBearerContexts(EnbUeEntry &entry);

    // Starts a brand-new EPS session on a retained registry entry. Unlike a
    // Service Request, an Attach is a new logical session, so the retained
    // bearer contexts go away and the access-generation counter restarts
    // together with the fresh mobility context of the attaching UE. Leaving
    // the counter behind would desynchronise it from the UE and make a later
    // legitimate S1 release look stale to that UE.
    void beginNewAttach(EnbUeEntry &entry);

    // Erases the entry and every index it owns.
    void remove(EnbUeEntry &entry);

    [[nodiscard]] size_t size() const;
    [[nodiscard]] size_t capacity() const;

    // Opt-in performance counters. They are not owned here and are only
    // written when their `enabled` flag is set, so a normal run pays nothing.
    void setPerfCounters(PerfCounters *counters) { m_perf = counters; }
    void noteRegistration();
    std::vector<EnbUeEntry *> all();

  private:
    // Drops one local TEID from the live index and records it as retired. Every
    // path that stops a tunnel from resolving goes through here, so a TEID can
    // never become unresolvable without also becoming identifiable as retired.
    void retireLocalTeid(uint32_t teid);

    size_t m_maxUes;
    PerfCounters *m_perf{};
    std::function<uint32_t()> m_allocTeid;
    uint32_t m_nextEnbUeS1apId{1};
    RetiredTeidLedger m_retiredTeids;
    // Local TEIDs this registry's allocator has issued and that are not yet
    // bound to a bearer. It holds only values in flight, so it stays small; it
    // is what makes `bindLocalTeid` a validated registration rather than an
    // open setter. A reservation is consumed by a bind, dropped by an
    // `unbindLocalTeid` rollback, and dropped defensively by `retireLocalTeid`.
    std::unordered_set<uint32_t> m_reservedTeids;
    std::unordered_map<uint32_t, std::unique_ptr<EnbUeEntry>> m_byRadioUeId;
    // InetAddress has no std::hash specialization; its string form is unique.
    std::unordered_map<std::string, EnbUeEntry *> m_byPeer;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byEnbUeS1apId;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byMmeUeS1apId;
    std::unordered_map<uint32_t, EnbUeEntry *> m_byLocalTeid;
    // Provisional target-side contexts, kept apart from the radio-identity index
    // because they have no radio identity and no peer. The key is a local
    // ordinal with no protocol meaning: it is not an S1AP identifier, not a
    // TEID and not a UE identity.
    std::unordered_map<uint32_t, std::unique_ptr<EnbUeEntry>> m_provisional;
    uint32_t m_nextProvisionalId{1};
};

std::array<uint8_t, 4> ParseIpv4(const std::string &address);
std::string Ipv4ToString(const std::array<uint8_t, 4> &address);
std::array<uint8_t, 4> TeidToBytes(uint32_t teid);
uint32_t TeidFromBytes(const std::array<uint8_t, 4> &value);

} // namespace lte::enb
