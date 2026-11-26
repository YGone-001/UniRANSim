//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "drb_runtime.hpp"

#include <atomic>
#include <limits>
#include <utility>

namespace lte::rrc
{
namespace
{

void PutU32(std::vector<uint8_t> &out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 24U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

uint32_t GetU32(const uint8_t *data)
{
    return (static_cast<uint32_t>(data[0]) << 24U) | (static_cast<uint32_t>(data[1]) << 16U) |
           (static_cast<uint32_t>(data[2]) << 8U) | static_cast<uint32_t>(data[3]);
}

rlc::am::AmConfig NormalizeAm(rlc::am::AmConfig am)
{
    am.maxPduBytes = DrbAmMaxPduBytes;
    return am;
}

} // namespace

std::vector<uint8_t> EncodeDrbData(uint8_t drbIdentity, const std::vector<uint8_t> &rlcPdu)
{
    if (drbIdentity == 0 || rlcPdu.empty())
        return {};
    std::vector<uint8_t> payload;
    payload.reserve(DrbRoutingHeaderSize + rlcPdu.size());
    payload.push_back(DrbKindData);
    payload.push_back(drbIdentity);
    payload.insert(payload.end(), rlcPdu.begin(), rlcPdu.end());
    return payload;
}

std::vector<uint8_t> EncodeDrbReady(const DrbReady &ready)
{
    if (ready.ebi == 0 || ready.ipv4 == std::array<uint8_t, 4>{})
        return {};
    std::vector<uint8_t> payload;
    payload.reserve(DrbRoutingHeaderSize + 8);
    payload.push_back(DrbKindReady);
    payload.push_back(ready.ebi);
    PutU32(payload, ready.generation);
    payload.insert(payload.end(), ready.ipv4.begin(), ready.ipv4.end());
    return payload;
}

bool DecodeDrbRouting(const std::vector<uint8_t> &payload, uint8_t &kind, uint8_t &drbIdentity, size_t &bodyOffset)
{
    if (payload.size() < DrbRoutingHeaderSize)
        return false;
    kind = payload[0];
    drbIdentity = payload[1];
    if (drbIdentity == 0)
        return false;
    bodyOffset = DrbRoutingHeaderSize;
    return true;
}

bool DecodeDrbReady(const uint8_t *data, size_t size, uint8_t routingEbi, DrbReady &out)
{
    if (data == nullptr || size != 8)
        return false;
    DrbReady ready;
    ready.ebi = routingEbi;
    ready.generation = GetU32(data);
    for (size_t i = 0; i < 4; ++i)
        ready.ipv4[i] = data[4 + i];
    if (ready.ebi == 0 || ready.ipv4 == std::array<uint8_t, 4>{})
        return false;
    out = ready;
    return true;
}

DrbBearer::DrbBearer(DrbBearerConfig config, rlc::am::EndpointRole role, uint32_t association, Sender sender,
                     Deliverer deliverer)
    : config_(config), role_(role), association_(association), deliverer_(std::move(deliverer)),
      rlc_(role, association, NormalizeAm(config.am),
           [this](std::vector<uint8_t> sdu) {
               if (released_)
                   return;
               std::vector<uint8_t> packet;
               try
               {
                   packet = pdcpRx_->Unprotect(sdu);
               }
               catch (const security::PdcpSecurityException &)
               {
                   // A replayed COUNT, a wrong-order PDU or a PDU this bearer's
                   // key cannot decipher is dropped here and never reaches the
                   // owner. The RLC entity has already delivered it, so this is
                   // a PDCP refusal, not an RLC one.
                   counters_.pdcpFailures++;
                   return;
               }
               counters_.downlinkPackets++;
               counters_.downlinkBytes += packet.size();
               if (deliverer_)
                   deliverer_(config_.ebi, packet);
           },
           uu::LogicalChannel::DTCH, [this, sender = std::move(sender)](const std::vector<uint8_t> &pdu) {
               if (!sender(pdu))
                   counters_.sendFailures++;
           })
{
    config_.am = NormalizeAm(config.am);
    // The PDCP direction is the direction of the traffic, not the local role:
    // a UE transmits uplink and receives downlink, an eNB the reverse. The
    // COUNT, BEARER and DIRECTION inputs of the ciphering must therefore match
    // on the two ends of one bearer.
    const bool transmitUplink = rlc::am::TransmitDirection(role_) == uu::Direction::UPLINK;
    const bool receiveUplink = rlc::am::ReceiveDirection(role_) == uu::Direction::UPLINK;
    pdcpTx_ = security::PdcpSecurityEntity::Create(
        security::PdcpProfile::DRB12, security::RadioBearerIdentity::Drb(config_.drbIdentity), transmitUplink, 0,
        config_.cipheringAlgorithm, security::Key128{}, config_.kUpEnc);
    pdcpRx_ = security::PdcpSecurityEntity::Create(
        security::PdcpProfile::DRB12, security::RadioBearerIdentity::Drb(config_.drbIdentity), receiveUplink, 0,
        config_.cipheringAlgorithm, security::Key128{}, config_.kUpEnc);
    pdcpTx_->ActivateCiphering();
    pdcpRx_->ActivateCiphering();
}

bool DrbBearer::SubmitIp(const uint8_t *packet, size_t size)
{
    if (released_ || packet == nullptr || size == 0)
    {
        counters_.malformedDrops++;
        return false;
    }
    if (size > MaxDrbSduBytes)
    {
        counters_.oversizedDrops++;
        return false;
    }
    std::vector<uint8_t> pdu;
    try
    {
        pdu = pdcpTx_->Protect(std::vector<uint8_t>(packet, packet + size));
    }
    catch (const security::PdcpSecurityException &)
    {
        counters_.pdcpFailures++;
        return false;
    }
    try
    {
        rlc_.SubmitSdu(pdu);
    }
    catch (const std::exception &)
    {
        counters_.rlcFailures++;
        return false;
    }
    counters_.uplinkPackets++;
    counters_.uplinkBytes += size;
    return true;
}

bool DrbBearer::OnRlcFrame(const uu::Frame &frame)
{
    if (released_)
        return false;
    if (!rlc_.OnFrame(frame))
    {
        counters_.malformedDrops += 1;
        return false;
    }
    return true;
}

void DrbBearer::Tick()
{
    if (!released_)
        rlc_.Tick();
}

void DrbBearer::Release() noexcept
{
    released_ = true;
    pdcpTx_.reset();
    pdcpRx_.reset();
    rlc_.Release();
}

DrbRuntime::DrbRuntime(rlc::am::EndpointRole role, uint32_t association, Sender sender, Deliverer deliverer)
    : role_(role), association_(association), sender_(std::move(sender)), deliverer_(std::move(deliverer))
{
    // A stable generation invalidates the scheduler entries of a runtime that
    // was destroyed and re-created for the same association.
    static std::atomic<uint64_t> nextGeneration{1};
    generation_ = nextGeneration.fetch_add(1, std::memory_order_relaxed);
}

bool DrbRuntime::AddBearer(const DrbBearerConfig &config)
{
    if (config.ebi == 0 || config.drbIdentity == 0 || config.am.maxPduBytes <= DrbRoutingHeaderSize)
        return false;
    if (bearers_.count(config.ebi) != 0)
    {
        counters_.duplicateSetups++;
        return false;
    }
    for (const auto &existing : bearers_)
        if (existing.second->DrbIdentity() == config.drbIdentity)
        {
            counters_.duplicateSetups++;
            return false;
        }
    auto bearer = std::make_unique<DrbBearer>(
        config, role_, association_,
        [this, identity = config.drbIdentity](const std::vector<uint8_t> &pdu) {
            return SendPayload(DrbKindData, identity, pdu);
        },
        [this](uint8_t ebi, const std::vector<uint8_t> &ip) {
            counters_.downlinkPackets++;
            counters_.downlinkBytes += ip.size();
            if (deliverer_)
                deliverer_(ebi, ip);
        });
    bearer->SetActivityCallback([this, ebi = config.ebi] {
        if (onActivity_)
            onActivity_(ebi);
    });
    bearers_.emplace(config.ebi, std::move(bearer));
    return true;
}

void DrbRuntime::SetActivityCallback(std::function<void(uint8_t ebi)> callback)
{
    onActivity_ = std::move(callback);
    for (auto &entry : bearers_)
    {
        const uint8_t ebi = entry.first;
        entry.second->SetActivityCallback([this, ebi] {
            if (onActivity_)
                onActivity_(ebi);
        });
    }
}

DrbBearer *DrbRuntime::BearerForTick(uint8_t ebi)
{
    const auto it = bearers_.find(ebi);
    return it == bearers_.end() ? nullptr : it->second.get();
}

int64_t DrbRuntime::NextDeadlineMs() const
{
    int64_t best = std::numeric_limits<int64_t>::max();
    for (const auto &entry : bearers_)
    {
        const uint32_t next = entry.second->NextTickIn();
        if (next == rlc::am::LteAmEntity::NeverTick)
            continue;
        const int64_t deadline = entry.second->LastTickMs() + static_cast<int64_t>(next);
        if (deadline < best)
            best = deadline;
    }
    return best;
}

void DrbRuntime::AdvanceTo(int64_t nowMs)
{
    for (auto &entry : bearers_)
        entry.second->AdvanceTo(nowMs);
}

void DrbRuntime::SetReadyHandler(ReadyHandler handler)
{
    readyHandler_ = std::move(handler);
}

bool DrbRuntime::SubmitIp(uint8_t ebi, const uint8_t *packet, size_t size)
{
    const auto it = bearers_.find(ebi);
    if (it == bearers_.end())
    {
        counters_.unknownBearerDrops++;
        return false;
    }
    if (!it->second->SubmitIp(packet, size))
        return false;
    counters_.uplinkPackets++;
    counters_.uplinkBytes += size;
    return true;
}

bool DrbRuntime::OnFrame(const uu::Frame &frame)
{
    if (frame.channel != uu::LogicalChannel::DTCH || frame.association != association_ ||
        frame.direction != rlc::am::ReceiveDirection(role_))
    {
        counters_.wrongFrameDrops++;
        return false;
    }
    uint8_t kind = 0;
    uint8_t drbIdentity = 0;
    size_t offset = 0;
    if (!DecodeDrbRouting(frame.payload, kind, drbIdentity, offset))
    {
        counters_.malformedDrops++;
        return false;
    }
    if (kind == DrbKindData)
    {
        for (const auto &entry : bearers_)
        {
            if (entry.second->DrbIdentity() != drbIdentity)
                continue;
            uu::Frame rlc = frame;
            rlc.payload.assign(frame.payload.begin() + offset, frame.payload.end());
            const bool accepted = entry.second->OnRlcFrame(rlc);
            if (!accepted)
                counters_.rlcFailures++;
            return accepted;
        }
        counters_.unknownBearerDrops++;
        return false;
    }
    if (kind == DrbKindReady)
    {
        if (role_ != rlc::am::EndpointRole::ENB)
        {
            counters_.wrongFrameDrops++;
            return false;
        }
        DrbReady ready;
        if (!DecodeDrbReady(frame.payload.data() + offset, frame.payload.size() - offset, drbIdentity, ready))
        {
            counters_.malformedDrops++;
            return false;
        }
        counters_.readyReceived++;
        return readyHandler_ ? readyHandler_(ready) : false;
    }
    counters_.malformedDrops++;
    return false;
}

bool DrbRuntime::SendReady(const DrbReady &ready)
{
    if (role_ != rlc::am::EndpointRole::UE || !HasBearer(ready.ebi))
        return false;
    std::vector<uint8_t> body;
    body.reserve(8);
    PutU32(body, ready.generation);
    body.insert(body.end(), ready.ipv4.begin(), ready.ipv4.end());
    if (!SendPayload(DrbKindReady, ready.ebi, body))
        return false;
    counters_.readySent++;
    return true;
}

void DrbRuntime::ReleaseBearer(uint8_t ebi)
{
    const auto it = bearers_.find(ebi);
    if (it == bearers_.end())
        return;
    it->second->Release();
    bearers_.erase(it);
}

void DrbRuntime::Release() noexcept
{
    for (auto &entry : bearers_)
        entry.second->Release();
    bearers_.clear();
}

void DrbRuntime::Tick()
{
    for (auto &entry : bearers_)
        entry.second->Tick();
}

bool DrbRuntime::HasBearer(uint8_t ebi) const
{
    return bearers_.count(ebi) != 0;
}

const DrbBearer *DrbRuntime::Bearer(uint8_t ebi) const
{
    const auto it = bearers_.find(ebi);
    return it == bearers_.end() ? nullptr : it->second.get();
}

uint16_t DrbRuntime::MaxOutstandingPdus() const
{
    uint16_t outstanding = 0;
    for (const auto &entry : bearers_)
        outstanding = std::max(outstanding, entry.second->OutstandingPdus());
    return outstanding;
}

bool DrbRuntime::SendPayload(uint8_t kind, uint8_t drbIdentity, const std::vector<uint8_t> &body)
{
    if (!sender_ || drbIdentity == 0 || body.empty())
        return false;
    std::vector<uint8_t> payload;
    payload.reserve(DrbRoutingHeaderSize + body.size());
    payload.push_back(kind);
    payload.push_back(drbIdentity);
    payload.insert(payload.end(), body.begin(), body.end());
    return sender_(payload);
}

} // namespace lte::rrc
