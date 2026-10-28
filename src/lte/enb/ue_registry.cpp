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

UeRegistry::UeRegistry(size_t maxUes) : m_maxUes(maxUes)
{
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

BearerContext &UeRegistry::addDedicatedBearer(EnbUeEntry &entry, const BearerParameters &parameters)
{
    if (parameters.erabId < 5 || parameters.erabId > 15 ||
        (findBearer(entry, parameters.erabId) != nullptr && findBearer(entry, parameters.erabId)->signalingEstablished()))
        throw RegistryError("The EPS bearer identity is invalid or already owned by this UE");
    if (!entry.bearer.signalingEstablished() || entry.bearer.parameters().erabId != parameters.linkedDefaultEbi)
        throw RegistryError("Dedicated bearer references no valid default bearer");
    // A bearer retained across ECM-IDLE keeps its EBI but has no transport. The
    // network re-establishes that same bearer on Service Request, so reuse the
    // context instead of rejecting it as a duplicate identity.
    for (auto &retained : entry.dedicatedBearers)
    {
        if (retained.parameters().erabId == parameters.erabId && !retained.signalingEstablished())
        {
            if (!retained.logicalConfirmed())
                throw RegistryError("Unconfirmed NAS bearer cannot be restored");
            retained.establish(parameters);
            return retained;
        }
    }
    if (entry.dedicatedBearers.size() >= EnbUeEntry::MaxDedicatedBearers)
        throw RegistryError("The per-UE dedicated bearer capacity is exhausted");
    BearerContext candidate(BearerKind::DEDICATED);
    candidate.establish(parameters);
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
                m_byLocalTeid.erase(dedicated.parameters().localTeid);
            dedicated.release();
        }
        entry.dedicatedBearers.clear();
        if (entry.bearer.parameters().localTeid != 0)
            m_byLocalTeid.erase(entry.bearer.parameters().localTeid);
        entry.bearer.release();
        return;
    }
    for (auto it = entry.dedicatedBearers.begin(); it != entry.dedicatedBearers.end(); ++it)
    {
        if (it->parameters().erabId != ebi)
            continue;
        if (it->parameters().localTeid != 0)
            m_byLocalTeid.erase(it->parameters().localTeid);
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
    // The process-wide allocator never hands out zero; skipping identifiers
    // that are still live also makes wraparound collision-free.
    for (;;)
    {
        const uint32_t candidate = AllocateLocalTeid();
        if (m_byLocalTeid.count(candidate) == 0)
            return candidate;
    }
}

void UeRegistry::bindLocalTeid(EnbUeEntry &entry, uint32_t teid)
{
    bindLocalTeid(entry, entry.bearer, teid);
}

void UeRegistry::bindLocalTeid(EnbUeEntry &entry, BearerContext &bearer, uint32_t teid)
{
    if (teid == 0)
        throw RegistryError("An active S1-U TEID must be non-zero");
    if (m_byLocalTeid.count(teid) != 0)
        throw RegistryError("The S1-U TEID is already owned by another bearer");
    if (bearer.parameters().localTeid != teid)
        throw RegistryError("The bearer already owns a different local S1-U TEID");
    m_byLocalTeid.emplace(teid, &entry);
}

void UeRegistry::releaseS1(EnbUeEntry &entry)
{
    if (entry.s1 != UeS1State::IDLE_RETAINED && ++entry.accessGeneration == 0)
        ++entry.accessGeneration;
    if (entry.enbUeS1apId != 0)
        m_byEnbUeS1apId.erase(entry.enbUeS1apId);
    if (entry.mmeUeS1apId != 0)
        m_byMmeUeS1apId.erase(entry.mmeUeS1apId);
    entry.enbUeS1apId = 0;
    entry.mmeUeS1apId = 0;
    entry.sgwPeer = InetAddress{};
    if (entry.bearer.parameters().localTeid != 0)
        m_byLocalTeid.erase(entry.bearer.parameters().localTeid);
    for (auto &dedicated : entry.dedicatedBearers)
        if (dedicated.parameters().localTeid != 0)
            m_byLocalTeid.erase(dedicated.parameters().localTeid);
    entry.bearer.releaseAccessTransport();
    // ECM-IDLE drops access TEIDs, not EPS bearer contexts. Clearing the
    // dedicated contexts here would silently deactivate a bearer the network
    // still believes exists, so the logical entries are retained without
    // transport until a Service Request restores them.
    for (auto &dedicated : entry.dedicatedBearers)
        dedicated.releaseAccessTransport();
    entry.s1 = UeS1State::IDLE_RETAINED;
}

void UeRegistry::unbindLocalTeid(EnbUeEntry &entry, uint32_t teid)
{
    const auto it = m_byLocalTeid.find(teid);
    if (it != m_byLocalTeid.end() && it->second == &entry)
        m_byLocalTeid.erase(it);
}

void UeRegistry::deleteBearerContexts(EnbUeEntry &entry)
{
    unbindLocalTeid(entry, entry.bearer.parameters().localTeid);
    for (auto &bearer : entry.dedicatedBearers)
        unbindLocalTeid(entry, bearer.parameters().localTeid);
    entry.bearer.release();
    entry.dedicatedBearers.clear();
    entry.ueAmbr.reset();
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
