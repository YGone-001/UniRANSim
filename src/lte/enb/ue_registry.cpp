//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "ue_registry.hpp"

#include <cstdio>
#include <utility>

namespace lte::enb
{

const char *ToString(UeS1State state)
{
    switch (state)
    {
    case UeS1State::NO_S1: return "NO_S1";
    case UeS1State::CONTEXT_PENDING: return "S1_CONTEXT_PENDING";
    case UeS1State::CONTEXT_ESTABLISHED: return "S1_CONTEXT_ESTABLISHED";
    case UeS1State::BEARER_ACTIVE: return "S1_BEARER_ACTIVE";
    case UeS1State::IDLE_RETAINED: return "IDLE_RETAINED";
    }
    return "UNKNOWN_S1_STATE";
}

uint16_t SctpStreamForUe(int outboundStreams, uint32_t enbUeS1apId)
{
    // Stream zero carries non-UE S1AP such as S1 Setup. Keep UE signalling on
    // a negotiated non-zero stream when the peer made one available.
    if (outboundStreams <= 1)
        return 0;
    return static_cast<uint16_t>(1U + ((enbUeS1apId - 1U) % static_cast<uint32_t>(outboundStreams - 1)));
}

std::array<uint8_t, 4> ParseIpv4(const std::string &address)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    char extra = 0;
    if (std::sscanf(address.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4 || a > 255 || b > 255 || c > 255 ||
        d > 255)
        throw std::runtime_error("S1-U address must be an IPv4 literal: " + address);
    return {static_cast<uint8_t>(a), static_cast<uint8_t>(b), static_cast<uint8_t>(c), static_cast<uint8_t>(d)};
}

std::string Ipv4ToString(const std::array<uint8_t, 4> &address)
{
    return std::to_string(address[0]) + "." + std::to_string(address[1]) + "." + std::to_string(address[2]) + "." +
           std::to_string(address[3]);
}

std::array<uint8_t, 4> TeidToBytes(uint32_t teid)
{
    return {static_cast<uint8_t>((teid >> 24U) & 0xFFU), static_cast<uint8_t>((teid >> 16U) & 0xFFU),
            static_cast<uint8_t>((teid >> 8U) & 0xFFU), static_cast<uint8_t>(teid & 0xFFU)};
}

uint32_t TeidFromBytes(const std::array<uint8_t, 4> &value)
{
    return (static_cast<uint32_t>(value[0]) << 24U) | (static_cast<uint32_t>(value[1]) << 16U) |
           (static_cast<uint32_t>(value[2]) << 8U) | value[3];
}

UeRegistry::UeRegistry(size_t maxUes, std::function<uint32_t()> teidAllocator, size_t retiredCapacity)
    : m_maxUes(maxUes), m_allocTeid(std::move(teidAllocator)), m_retiredTeids(retiredCapacity)
{
    if (!m_allocTeid)
        throw RegistryError("A local S1-U TEID allocator is required");
}

EnbUeEntry &UeRegistry::registerPeer(uint32_t radioUeId, const InetAddress &peer)
{
    if (radioUeId == 0)
        throw RegistryError("The simulated radio UE identity must be non-zero");
    if (m_byRadioUeId.count(radioUeId) != 0)
        throw RegistryError("A UE with this radio identity is already registered");
    if (m_byPeer.count(peer.toString()) != 0)
        throw RegistryError("This radio endpoint already carries another active UE identity");
    // A provisional target context consumes a per-UE slot too, so the bound is
    // over both kinds of entry. With no preparation outstanding the two are the
    // same number and an ordinary eNB sees no change.
    if (m_byRadioUeId.size() + m_provisional.size() >= m_maxUes)
        throw RegistryError("The eNB UE registry is full");

    auto entry = std::make_unique<EnbUeEntry>();
    entry->radioUeId = radioUeId;
    entry->peer = peer;
    EnbUeEntry *pointer = entry.get();
    m_byPeer.emplace(peer.toString(), pointer);
    m_byRadioUeId.emplace(radioUeId, std::move(entry));
    noteRegistration();
    return *pointer;
}

void UeRegistry::noteRegistration()
{
    if (m_perf == nullptr || !m_perf->enabled.load(std::memory_order_relaxed))
        return;
    m_perf->registrations.fetch_add(1, std::memory_order_relaxed);
    const uint64_t current = static_cast<uint64_t>(m_byRadioUeId.size() + m_provisional.size());
    uint64_t high = m_perf->registryHighWater.load(std::memory_order_relaxed);
    while (current > high && !m_perf->registryHighWater.compare_exchange_weak(high, current))
    {
    }
}

EnbUeEntry &UeRegistry::allocateProvisional()
{
    // The same per-UE bound as a reached UE. A provisional context holds real
    // transport identifiers and real bearer contexts, so it costs exactly what
    // a reached UE costs and must not be exempt from the capacity refusal that
    // makes exhaustion a testable, deterministic failure.
    if (m_byRadioUeId.size() + m_provisional.size() >= m_maxUes)
        throw RegistryError("The eNB UE registry is full");

    // `radioUeId` is left at zero on purpose. `registerPeer` refuses zero, so a
    // reached UE can never hold it, and `isProvisional` is therefore an exact
    // test rather than a flag that a caller could set.
    auto entry = std::make_unique<EnbUeEntry>();
    EnbUeEntry *pointer = entry.get();
    const uint32_t key = m_nextProvisionalId++;
    if (m_nextProvisionalId == 0)
        m_nextProvisionalId = 1;
    m_provisional.emplace(key, std::move(entry));
    return *pointer;
}

bool UeRegistry::holdsProvisional(const EnbUeEntry &entry) const
{
    for (const auto &item : m_provisional)
        if (item.second.get() == &entry)
            return true;
    return false;
}

void UeRegistry::removeProvisional(EnbUeEntry &entry)
{
    if (!isProvisional(entry))
        throw RegistryError("The UE entry is not a provisional target context");
    // Every prepared bearer is released through the same rollback a failed
    // establishment uses: a TEID that was actually bound is retired through
    // `retireLocalTeid` and becomes identifiable as retired, while one that was
    // only reserved is dropped without ever having been a tunnel. Neither is
    // left behind, and nothing here can reach an identifier this entry does not
    // own, so a repeated call is idempotent.
    deleteBearerContexts(entry);
    if (entry.enbUeS1apId != 0)
        m_byEnbUeS1apId.erase(entry.enbUeS1apId);
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    for (auto it = m_provisional.begin(); it != m_provisional.end(); ++it)
    {
        if (it->second.get() == &entry)
        {
            m_provisional.erase(it);
            return;
        }
    }
    throw RegistryError("The provisional UE entry is not registered");
}

EnbUeEntry &UeRegistry::promoteProvisional(EnbUeEntry &entry, uint32_t radioUeId, const InetAddress &peer,
                                          const PromotionFaultInjector &faults)
{
    // --- Validation. Nothing is published before every one of these holds,
    // --- so a refusal cannot leave a half-published index behind.
    if (!isProvisional(entry))
        throw RegistryError("The UE entry is not a provisional target context");
    if (radioUeId == 0)
        throw RegistryError("The simulated radio UE identity must be non-zero");
    auto provisional = m_provisional.end();
    for (auto it = m_provisional.begin(); it != m_provisional.end(); ++it)
    {
        if (it->second.get() == &entry)
        {
            provisional = it;
            break;
        }
    }
    if (provisional == m_provisional.end())
        throw RegistryError("The provisional UE entry is not registered");
    if (m_byRadioUeId.count(radioUeId) != 0)
        throw RegistryError("A UE with this radio identity is already registered");
    if (m_byPeer.count(peer.toString()) != 0)
        throw RegistryError("This radio endpoint already carries another active UE identity");
    // The S1AP identities are already indexed as a provisional context's are.
    // A different entry holding either one is a conflicting context that this
    // arrival cannot be reconciled with, and it is refused rather than
    // re-pointed.
    if (entry.enbUeS1apId != 0)
    {
        EnbUeEntry *other = findByEnbUeS1apId(entry.enbUeS1apId);
        if (other != nullptr && other != &entry)
            throw RegistryError("Another UE context already holds this eNB-UE-S1AP-ID");
    }
    if (entry.mmeUeS1apId != 0)
    {
        EnbUeEntry *other = findByMmeUeS1apId(entry.mmeUeS1apId);
        if (other != nullptr && other != &entry)
            throw RegistryError("Another UE context already holds this MME-UE-S1AP-ID");
    }

    // --- Access-identity binding. Every prepared bearer is still bound to the
    // --- only identity this target held before the UE arrived, and a bearer
    // --- bound to that identity refuses the uplink of the UE that has just
    // --- arrived under `radioUeId`. The whole set is checked before the first
    // --- one is moved, so the sequence cannot stop half way through and the
    // --- rollback only ever has a complete set to put back.
    std::vector<BearerContext *> rebound;
    if (entry.bearer.signalingEstablished() || !entry.dedicatedBearers.empty())
    {
        if (entry.mmeUeS1apId == 0)
            throw RegistryError("A prepared context with bearers names no identity to bind them back to");
        auto check = [](BearerContext &bearer, uint32_t expected) {
            if (!bearer.signalingEstablished())
                return;
            if (bearer.active())
                throw RegistryError("An active EPS bearer cannot be moved to another UE by a promotion");
            if (bearer.parameters().ueId != expected)
                throw RegistryError("A prepared EPS bearer is not bound to the identity of its own context");
        };
        check(entry.bearer, entry.mmeUeS1apId);
        for (auto &bearer : entry.dedicatedBearers)
            check(bearer, entry.mmeUeS1apId);
    }

    // --- Publication. The ownership moves out of the provisional map first,
    // --- so the object stays alive for the whole attempt and the rollback can
    // --- always take it back.
    //
    // Both indexes are given room for one more element before anything is
    // touched, so the two insertions below cannot fail from a rehash and the
    // rollback cannot be asked to recover from one.
    m_byPeer.reserve(m_byPeer.size() + 1);
    m_byRadioUeId.reserve(m_byRadioUeId.size() + 1);
    const uint32_t previousRadioUeId = entry.radioUeId;
    const InetAddress previousPeer = entry.peer;
    std::unique_ptr<EnbUeEntry> owned = std::move(provisional->second);
    m_provisional.erase(provisional);
    entry.radioUeId = radioUeId;
    entry.peer = peer;

    bool peerIndexed = false;
    bool radioIndexed = false;
    try
    {
        auto rebind = [&rebound](BearerContext &bearer, uint32_t to) {
            if (!bearer.signalingEstablished())
                return;
            bearer.rebindAccessIdentity(bearer.parameters().ueId, to);
            rebound.push_back(&bearer);
        };
        rebind(entry.bearer, radioUeId);
        for (auto &bearer : entry.dedicatedBearers)
            rebind(bearer, radioUeId);

        m_byPeer.emplace(peer.toString(), &entry);
        peerIndexed = true;
        if (faults.firesAt(PromotionFaultInjector::Fault::PEER_INDEX_PUBLICATION))
            throw RegistryError("injected: the radio peer index refused publication");
        m_byRadioUeId.emplace(radioUeId, std::move(owned));
        radioIndexed = true;
        if (faults.firesAt(PromotionFaultInjector::Fault::RADIO_INDEX_PUBLICATION))
            throw RegistryError("injected: the radio identity index refused publication");
    }
    catch (...)
    {
        // Roll back to exactly the provisional state. The moved ownership is
        // recovered before the index entry that holds it is erased, so the
        // context itself is never destroyed by its own rollback, and every
        // bearer this attempt moved is put back to the identity of the context
        // it is still owned by.
        for (auto it = rebound.rbegin(); it != rebound.rend(); ++it)
            (*it)->rebindAccessIdentity(radioUeId, entry.mmeUeS1apId);
        if (radioIndexed)
        {
            auto it = m_byRadioUeId.find(radioUeId);
            if (it != m_byRadioUeId.end())
            {
                owned = std::move(it->second);
                m_byRadioUeId.erase(it);
            }
        }
        if (peerIndexed)
            m_byPeer.erase(peer.toString());
        entry.radioUeId = previousRadioUeId;
        entry.peer = previousPeer;
        const uint32_t key = m_nextProvisionalId++;
        if (m_nextProvisionalId == 0)
            m_nextProvisionalId = 1;
        m_provisional.emplace(key, std::move(owned));
        throw;
    }
    return entry;
}

void UeRegistry::demoteToProvisional(EnbUeEntry &entry)
{
    if (isProvisional(entry))
        throw RegistryError("The UE entry is not a reached UE context");
    const uint32_t radioUeId = entry.radioUeId;
    if (radioUeId == 0)
        throw RegistryError("A reached UE context names no radio identity");
    if (m_byRadioUeId.count(radioUeId) == 0 || m_byRadioUeId.find(radioUeId)->second.get() != &entry)
        throw RegistryError("The reached UE entry is not registered under its own radio identity");
    if (m_byPeer.count(entry.peer.toString()) == 0 || m_byPeer.find(entry.peer.toString())->second != &entry)
        throw RegistryError("The reached UE entry is not registered under its own radio endpoint");

    // The whole set is checked before the first one is moved, for the same
    // reason the promotion checks it: a rollback that stops half way through
    // leaves bearers of one context bound to two different UEs.
    if (entry.mmeUeS1apId == 0)
        throw RegistryError("A prepared context with bearers names no identity to bind them back to");
    auto check = [radioUeId](BearerContext &bearer) {
        if (!bearer.signalingEstablished())
            return;
        if (bearer.active())
            throw RegistryError("An active EPS bearer cannot be moved back by a demotion");
        if (bearer.parameters().ueId != radioUeId)
            throw RegistryError("A promoted EPS bearer is not bound to the identity of its own context");
    };
    check(entry.bearer);
    for (auto &bearer : entry.dedicatedBearers)
        check(bearer);

    std::unique_ptr<EnbUeEntry> owned = std::move(m_byRadioUeId.find(radioUeId)->second);
    m_byRadioUeId.erase(radioUeId);
    const std::string peerKey = entry.peer.toString();
    m_byPeer.erase(peerKey);
    entry.radioUeId = 0;
    entry.peer = InetAddress{};

    try
    {
        auto rebind = [radioUeId, &entry](BearerContext &bearer) {
            if (!bearer.signalingEstablished())
                return;
            bearer.rebindAccessIdentity(radioUeId, entry.mmeUeS1apId);
        };
        rebind(entry.bearer);
        for (auto &bearer : entry.dedicatedBearers)
            rebind(bearer);
    }
    catch (...)
    {
        // Put the reached indexes back exactly as they were. The context is
        // left reached rather than half-reverted, which is the state the caller
        // is told about by the throw.
        entry.radioUeId = radioUeId;
        m_byPeer.emplace(peerKey, &entry);
        m_byRadioUeId.emplace(radioUeId, std::move(owned));
        throw;
    }

    const uint32_t key = m_nextProvisionalId++;
    if (m_nextProvisionalId == 0)
        m_nextProvisionalId = 1;
    m_provisional.emplace(key, std::move(owned));
}

EnbUeEntry *UeRegistry::find(uint32_t radioUeId)
{
    const auto it = m_byRadioUeId.find(radioUeId);
    return it == m_byRadioUeId.end() ? nullptr : it->second.get();
}

const EnbUeEntry *UeRegistry::find(uint32_t radioUeId) const
{
    return const_cast<UeRegistry *>(this)->find(radioUeId);
}

EnbUeEntry *UeRegistry::findByPeer(const InetAddress &peer)
{
    const auto it = m_byPeer.find(peer.toString());
    return it == m_byPeer.end() ? nullptr : it->second;
}

const EnbUeEntry *UeRegistry::findByEnbUeS1apId(uint32_t enbUeS1apId) const
{
    return const_cast<UeRegistry *>(this)->findByEnbUeS1apId(enbUeS1apId);
}

EnbUeEntry *UeRegistry::findByEnbUeS1apId(uint32_t enbUeS1apId)
{
    const auto it = m_byEnbUeS1apId.find(enbUeS1apId);
    return it == m_byEnbUeS1apId.end() ? nullptr : it->second;
}

EnbUeEntry *UeRegistry::findByMmeUeS1apId(uint32_t mmeUeS1apId)
{
    const auto it = m_byMmeUeS1apId.find(mmeUeS1apId);
    return it == m_byMmeUeS1apId.end() ? nullptr : it->second;
}

EnbUeEntry *UeRegistry::findByLocalTeid(uint32_t teid)
{
    const auto it = m_byLocalTeid.find(teid);
    return it == m_byLocalTeid.end() ? nullptr : it->second;
}

BearerLocation UeRegistry::findBearerByLocalTeid(uint32_t teid)
{
    auto *entry = findByLocalTeid(teid);
    if (entry == nullptr)
        return {};
    if (entry->bearer.signalingEstablished() && entry->bearer.parameters().localTeid == teid)
        return {entry, &entry->bearer};
    for (auto &bearer : entry->dedicatedBearers)
        if (bearer.signalingEstablished() && bearer.parameters().localTeid == teid)
            return {entry, &bearer};
    // The index must never outlive its bearer. Fail closed if a future caller
    // violates that invariant rather than delivering to the whole UE.
    return {};
}

BearerContext *UeRegistry::findBearer(EnbUeEntry &entry, uint8_t ebi)
{
    if (entry.bearer.logicalExists() && entry.bearer.parameters().erabId == ebi)
        return &entry.bearer;
    for (auto &bearer : entry.dedicatedBearers)
        if (bearer.logicalExists() && bearer.parameters().erabId == ebi)
            return &bearer;
    return nullptr;
}

const BearerContext *UeRegistry::findBearer(const EnbUeEntry &entry, uint8_t ebi) const
{
    return const_cast<UeRegistry *>(this)->findBearer(const_cast<EnbUeEntry &>(entry), ebi);
}

BearerContext &UeRegistry::addDedicatedBearer(EnbUeEntry &entry, const BearerParameters &parameters,
                                              bool accessRestoration)
{
    if (parameters.erabId < 5 || parameters.erabId > 15 ||
        (findBearer(entry, parameters.erabId) != nullptr && findBearer(entry, parameters.erabId)->signalingEstablished()))
        throw RegistryError("The EPS bearer identity is invalid or already owned by this UE");
    if (!entry.bearer.signalingEstablished() || entry.bearer.parameters().erabId != parameters.linkedDefaultEbi)
        throw RegistryError("Dedicated bearer references no valid default bearer");
    // A bearer retained across ECM-IDLE keeps its EBI but has no transport. The
    // network re-establishes that same bearer on Service Request, so reuse the
    // context instead of rejecting it as a duplicate identity. It is always a
    // restoration: its logical bearer is one this eNB already held.
    for (auto &retained : entry.dedicatedBearers)
    {
        if (retained.parameters().erabId == parameters.erabId && !retained.signalingEstablished())
        {
            if (!retained.logicalConfirmed())
                throw RegistryError("Unconfirmed NAS bearer cannot be restored");
            retained.establish(parameters, true);
            return retained;
        }
    }
    if (entry.dedicatedBearers.size() >= EnbUeEntry::MaxDedicatedBearers)
        throw RegistryError("The per-UE dedicated bearer capacity is exhausted");
    BearerContext candidate(BearerKind::DEDICATED);
    candidate.establish(parameters, accessRestoration);
    entry.dedicatedBearers.push_back(std::move(candidate));
    return entry.dedicatedBearers.back();
}

void UeRegistry::releaseBearer(EnbUeEntry &entry, uint8_t ebi)
{
    if (entry.bearer.parameters().erabId == ebi)
    {
        // The PDN's default bearer owns all dedicated dependencies.
        for (auto &dedicated : entry.dedicatedBearers)
        {
            if (dedicated.parameters().localTeid != 0)
                retireLocalTeid(dedicated.parameters().localTeid);
            dedicated.release();
        }
        entry.dedicatedBearers.clear();
        if (entry.bearer.parameters().localTeid != 0)
            retireLocalTeid(entry.bearer.parameters().localTeid);
        entry.bearer.release();
        return;
    }
    for (auto it = entry.dedicatedBearers.begin(); it != entry.dedicatedBearers.end(); ++it)
    {
        if (it->parameters().erabId != ebi)
            continue;
        if (it->parameters().localTeid != 0)
            retireLocalTeid(it->parameters().localTeid);
        it->release();
        entry.dedicatedBearers.erase(it);
        return;
    }
    throw RegistryError("Cannot release an unknown EPS bearer");
}

uint32_t UeRegistry::allocateEnbUeS1apId()
{
    // S1AP encodes the eNB-UE-S1AP-ID in 24 bits; zero is reserved. Monotonic
    // allocation with wraparound past 0xFFFFFF, never colliding with a live
    // context, keeps released identifiers from becoming valid again early.
    for (uint32_t attempt = 0; attempt <= 0xFFFFFFU; ++attempt)
    {
        const uint32_t candidate = m_nextEnbUeS1apId;
        m_nextEnbUeS1apId = (m_nextEnbUeS1apId >= 0xFFFFFFU) ? 1U : m_nextEnbUeS1apId + 1U;
        if (candidate != 0 && m_byEnbUeS1apId.count(candidate) == 0)
            return candidate;
    }
    throw RegistryError("No free eNB-UE-S1AP-ID is available");
}

void UeRegistry::bindEnbUeS1apId(EnbUeEntry &entry, uint32_t enbUeS1apId)
{
    if (enbUeS1apId == 0)
        throw RegistryError("The eNB-UE-S1AP-ID must be non-zero");
    if (entry.enbUeS1apId == enbUeS1apId)
        return;
    if (entry.enbUeS1apId != 0)
        throw RegistryError("The UE already owns a live eNB-UE-S1AP-ID");
    if (m_byEnbUeS1apId.count(enbUeS1apId) != 0)
        throw RegistryError("The eNB-UE-S1AP-ID is already owned by another UE context");
    entry.enbUeS1apId = enbUeS1apId;
    m_byEnbUeS1apId.emplace(enbUeS1apId, &entry);
}

void UeRegistry::setMmeUeS1apId(EnbUeEntry &entry, uint32_t mmeUeS1apId)
{
    if (mmeUeS1apId == 0)
        throw RegistryError("The MME-UE-S1AP-ID must be non-zero");
    if (entry.mmeUeS1apId == mmeUeS1apId)
        return;
    if (const auto *owner = findByMmeUeS1apId(mmeUeS1apId); owner != nullptr && owner != &entry)
        throw RegistryError("The MME-UE-S1AP-ID is already owned by another UE context");
    // Allocate the new index before changing ownership, for exception safety.
    m_byMmeUeS1apId.emplace(mmeUeS1apId, &entry);
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    entry.mmeUeS1apId = mmeUeS1apId;
}

void UeRegistry::clearMmeUeS1apId(EnbUeEntry &entry)
{
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    entry.mmeUeS1apId = 0;
}

uint32_t UeRegistry::allocateLocalTeid()
{
    // The production allocator is monotonic and never offers the same value
    // twice within the process, so a candidate it produces is never one that is
    // already live or already retired: the loop runs at most twice against it,
    // once for the reserved zero. It is bounded rather than open only so that a
    // pathological injected allocator, which can keep returning unusable
    // values, fails deterministically instead of hanging.
    //
    // The bound is the registry's own capacity horizon: it cannot be forbidding
    // more distinct identifiers at once than the live bearers it can hold plus
    // the retirement records it keeps plus the reserved zero, and one more
    // candidate is enough to find a free one among them. An allocator that
    // cannot produce a usable value inside that many attempts is refused, and a
    // refusal reserves nothing.
    const size_t maxAttempts =
        m_maxUes * (1 + EnbUeEntry::MaxDedicatedBearers) + m_retiredTeids.capacity() + 2;
    for (size_t attempt = 0; attempt < maxAttempts; ++attempt)
    {
        const uint32_t candidate = m_allocTeid();
        if (candidate == 0)
            continue;
        if (m_byLocalTeid.count(candidate) != 0)
            continue;
        if (m_retiredTeids.contains(candidate))
            continue;
        // Reserved before returning, so that only this registry's own
        // allocations can ever be bound.
        m_reservedTeids.insert(candidate);
        return candidate;
    }
    throw RegistryError("No usable local S1-U TEID is available");
}

void UeRegistry::bindLocalTeid(EnbUeEntry &entry, uint32_t teid)
{
    bindLocalTeid(entry, entry.bearer, teid);
}

void UeRegistry::bindLocalTeid(EnbUeEntry &entry, BearerContext &bearer, uint32_t teid)
{
    if (teid == 0)
        throw RegistryError("An active S1-U TEID must be non-zero");
    // A retired identifier is refused absolutely. Rebinding one would erase the
    // evidence that its tunnel ended, and a delayed packet of that tunnel would
    // then resolve against the new bearer that happens to hold the identifier.
    // Nothing withdraws a retirement record.
    if (m_retiredTeids.contains(teid))
        throw RegistryError("A retired S1-U TEID cannot be rebound to a live tunnel");
    // Only an identifier this registry's allocator issued may become a live
    // mapping. Without this, `bindLocalTeid` is an open setter and the
    // allocator's no-reissue guarantee is bypassed by any caller that chooses
    // its own value. The check also refuses an identifier whose retirement
    // record has aged out, because such a value is not reserved either.
    if (m_reservedTeids.count(teid) == 0)
        throw RegistryError("The S1-U TEID was not reserved by this registry's allocator");
    if (m_byLocalTeid.count(teid) != 0)
        throw RegistryError("The S1-U TEID is already owned by another bearer");
    if (bearer.parameters().localTeid != teid)
        throw RegistryError("The bearer already owns a different local S1-U TEID");
    m_reservedTeids.erase(teid);
    m_byLocalTeid.emplace(teid, &entry);
}

bool UeRegistry::isRetiredTeid(uint32_t teid) const
{
    return m_retiredTeids.contains(teid);
}

void UeRegistry::retireLocalTeid(uint32_t teid)
{
    if (teid == 0)
        return;
    m_byLocalTeid.erase(teid);
    // A reservation belonging to an establishment that never completed is
    // dropped here too, so a reserved identifier cannot outlive the attempt.
    m_reservedTeids.erase(teid);
    // The identifier stops resolving and is remembered as retired, so a delayed
    // G-PDU or a reordered End Marker naming it is reported as having outlived
    // its tunnel rather than as naming a tunnel that was never issued.
    m_retiredTeids.retire(teid);
}

void UeRegistry::releaseS1(EnbUeEntry &entry)
{
    // The access generation numbers one cell's access epochs, and the two ends
    // of the radio link hold that number in common. It advances when an access
    // that carried bearer transport ends, because that is the one transition
    // the UE is told about: the release names the bearer it is releasing. A
    // context released before it ever carried any, such as the S1 connection a
    // Tracking Area Update opens and the MME closes again, tells the UE
    // nothing, and a silent advance is what puts the two counts out of step and
    // makes the next generation-bound message look stale at the UE.
    if (entry.s1 == UeS1State::BEARER_ACTIVE && ++entry.accessGeneration == 0)
        ++entry.accessGeneration;
    if (entry.enbUeS1apId != 0)
        m_byEnbUeS1apId.erase(entry.enbUeS1apId);
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    entry.enbUeS1apId = 0;
    entry.mmeUeS1apId = 0;
    entry.sgwPeer = InetAddress{};
    if (entry.bearer.parameters().localTeid != 0)
        retireLocalTeid(entry.bearer.parameters().localTeid);
    for (auto &dedicated : entry.dedicatedBearers)
        if (dedicated.parameters().localTeid != 0)
            retireLocalTeid(dedicated.parameters().localTeid);
    entry.bearer.releaseAccessTransport();
    // ECM-IDLE drops access TEIDs, not EPS bearer contexts. Clearing the
    // dedicated contexts here would silently deactivate a bearer the network
    // still believes exists, so the logical entries are retained without
    // transport until a Service Request restores them.
    for (auto &dedicated : entry.dedicatedBearers)
        dedicated.releaseAccessTransport();
    // The declaration described one access setup on this cell. The next uplink
    // describes its own, so a stale inventory is never reused for it.
    entry.mobilityBootstrap = false;
    entry.declaredBearers.reset();
    // Releasing the access is what retains the UE: the session it may later
    // ask service for is the one the network still holds for it.
    entry.sessionRetained = true;
    entry.s1 = UeS1State::IDLE_RETAINED;
}

void UeRegistry::removeHandoverSource(EnbUeEntry &entry)
{
    // Only a reached UE this registry really holds can be moved away from this
    // cell. A provisional context is a UE that has not arrived, and an entry
    // this registry does not own is another registry's business.
    if (isProvisional(entry))
        throw RegistryError("A provisional context is not a UE a handover moved away from this cell");
    const auto it = m_byRadioUeId.find(entry.radioUeId);
    if (it == m_byRadioUeId.end() || it->second.get() != &entry)
        throw RegistryError("The UE entry is not registered");

    if (entry.enbUeS1apId != 0)
        m_byEnbUeS1apId.erase(entry.enbUeS1apId);
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    entry.enbUeS1apId = 0;
    entry.mmeUeS1apId = 0;
    entry.sgwPeer = InetAddress{};

    // Both bearers' local identifiers stop resolving and are remembered as
    // retired, so a delayed T-PDU naming one is classified as traffic that
    // outlived its tunnel rather than as a packet that never had one.
    retireLocalTeid(entry.bearer.parameters().localTeid);
    for (auto &dedicated : entry.dedicatedBearers)
        retireLocalTeid(dedicated.parameters().localTeid);

    // Nothing is retained. An ECM-IDLE release keeps the logical EPS bearer
    // contexts because the UE may ask service for them; this UE's session is
    // now the target's, and keeping a copy here would be a second owner of one
    // session.
    entry.bearer.release();
    entry.dedicatedBearers.clear();
    entry.ueAmbr.reset();
    entry.mobilityBootstrap = false;
    entry.declaredBearers.reset();
    entry.sessionRetained = false;
    entry.pagingNotifications = 0;

    m_byPeer.erase(entry.peer.toString());
    m_byRadioUeId.erase(it);
}

void UeRegistry::unbindLocalTeid(EnbUeEntry &entry, uint32_t teid)
{
    const auto it = m_byLocalTeid.find(teid);
    if (it != m_byLocalTeid.end() && it->second == &entry)
    {
        retireLocalTeid(teid);
        return;
    }
    // Not a live mapping of this entry. This is the rollback of an
    // establishment that never completed, and dropping its reservation is the
    // rollback: the identifier is not retired, because no tunnel of this
    // registry ever existed to retire.
    m_reservedTeids.erase(teid);
}

void UeRegistry::deleteBearerContexts(EnbUeEntry &entry)
{
    unbindLocalTeid(entry, entry.bearer.parameters().localTeid);
    for (auto &bearer : entry.dedicatedBearers)
        unbindLocalTeid(entry, bearer.parameters().localTeid);
    entry.bearer.release();
    entry.dedicatedBearers.clear();
    entry.ueAmbr.reset();
    // A declaration about a session whose bearer contexts are gone describes
    // nothing that is still here.
    entry.mobilityBootstrap = false;
    entry.declaredBearers.reset();
    // Nor is there a session left for this UE to ask service for.
    entry.sessionRetained = false;
}

void UeRegistry::beginNewAttach(EnbUeEntry &entry)
{
    deleteBearerContexts(entry);
    entry.accessGeneration = 0;
}

void UeRegistry::remove(EnbUeEntry &entry)
{
    if (m_perf != nullptr && m_perf->enabled.load(std::memory_order_relaxed))
        m_perf->teardowns.fetch_add(1, std::memory_order_relaxed);
    releaseS1(entry);
    const auto it = m_byRadioUeId.find(entry.radioUeId);
    if (it == m_byRadioUeId.end() || it->second.get() != &entry)
        throw RegistryError("The UE entry is not registered");
    m_byPeer.erase(entry.peer.toString());
    m_byRadioUeId.erase(it);
}

size_t UeRegistry::size() const
{
    return m_byRadioUeId.size();
}

size_t UeRegistry::capacity() const
{
    return m_maxUes;
}

std::vector<EnbUeEntry *> UeRegistry::all()
{
    std::vector<EnbUeEntry *> entries;
    entries.reserve(m_byRadioUeId.size());
    for (auto &item : m_byRadioUeId)
        entries.push_back(item.second.get());
    return entries;
}

} // namespace lte::enb
