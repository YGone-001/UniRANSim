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
    if (m_byRadioUeId.size() >= m_maxUes)
        throw RegistryError("The eNB UE registry is full");

    auto entry = std::make_unique<EnbUeEntry>();
    entry->radioUeId = radioUeId;
    entry->peer = peer;
    EnbUeEntry *pointer = entry.get();
    m_byPeer.emplace(peer.toString(), pointer);
    m_byRadioUeId.emplace(radioUeId, std::move(entry));
    return *pointer;
}

EnbUeEntry *UeRegistry::find(uint32_t radioUeId)
{
    const auto it = m_byRadioUeId.find(radioUeId);
    return it == m_byRadioUeId.end() ? nullptr : it->second.get();
}

EnbUeEntry *UeRegistry::findByPeer(const InetAddress &peer)
{
    const auto it = m_byPeer.find(peer.toString());
    return it == m_byPeer.end() ? nullptr : it->second;
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
