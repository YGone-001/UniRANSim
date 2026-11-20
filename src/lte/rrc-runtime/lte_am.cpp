//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "lte_am.hpp"

#include <algorithm>
#include <stdexcept>

namespace lte::rlc::am
{
namespace
{

constexpr uint16_t Window = AmWindow;

} // namespace

const char *ToString(AmState state)
{
    switch (state)
    {
    case AmState::ACTIVE: return "ACTIVE";
    case AmState::FAILED: return "FAILED";
    case AmState::RELEASED: return "RELEASED";
    }
    return "UNKNOWN";
}

LteAmEntity::LteAmEntity(AmConfig config, Sender sender, Deliverer deliverer)
    : config_(config), sender_(std::move(sender)), deliverer_(std::move(deliverer))
{
    if (!sender_ || !deliverer_ || config_.maxPduBytes <= 4 || config_.maxRetx == 0)
        throw std::invalid_argument("LTE AM entity needs a sender, a deliverer and a usable configuration");
    state_ = AmState::ACTIVE;
}

int LteAmEntity::Distance(uint16_t from, uint16_t to)
{
    // Distance from 'from' to 'to' in a 1024-wide sequence space, always in
    // [0, 1024). This is the only place SN arithmetic happens.
    return (static_cast<int>(to) - static_cast<int>(from) + SnModulus) % SnModulus;
}

void LteAmEntity::Release() noexcept
{
    state_ = AmState::RELEASED;
    transmissions_.clear();
    receive_.clear();
}

void LteAmEntity::Fail()
{
    state_ = AmState::FAILED;
    transmissions_.clear();
}

void LteAmEntity::SendPdu(uint16_t sn, bool poll, FramingInfo fi, const std::vector<uint8_t> &data,
                          std::optional<std::pair<uint16_t, uint16_t>> soRange)
{
    AmdPdu pdu;
    pdu.sn = sn;
    pdu.poll = poll;
    pdu.fi = fi;
    pdu.data = data;
    if (soRange)
    {
        pdu.segment = true;
        pdu.so = soRange->first;
        pdu.lsf = soRange->second == SoMax;
    }
    sender_(EncodeAmd(pdu));
    transmissionsCount_++;
}

void LteAmEntity::SubmitSdu(const std::vector<uint8_t> &sdu)
{
    if (state_ != AmState::ACTIVE)
        throw std::logic_error("LTE AM entity is not active");
    if (sdu.empty())
        return;

    // Header is two octets; no LI is used for the initial segmentation, so the
    // payload capacity is maxPdu - 2.
    const size_t capacity = config_.maxPduBytes - 2;
    if (capacity == 0)
        throw std::logic_error("maxPduBytes leaves no payload");

    size_t offset = 0;
    while (offset < sdu.size())
    {
        if (Distance(vtA_, vtS_) >= Window)
            throw std::logic_error("transmission window is full");

        const size_t chunk = std::min(capacity, sdu.size() - offset);
        const bool first = offset == 0;
        const bool last = offset + chunk == sdu.size();
        FramingInfo fi = FramingInfo::MIDDLE_SEGMENT;
        if (first && last)
            fi = FramingInfo::COMPLETE;
        else if (first)
            fi = FramingInfo::FIRST_SEGMENT;
        else if (last)
            fi = FramingInfo::LAST_SEGMENT;

        StoredSdu stored;
        stored.sn = vtS_;
        stored.fi = fi;
        stored.data.assign(sdu.begin() + static_cast<long>(offset), sdu.begin() + static_cast<long>(offset + chunk));
        stored.transmissions = 1;
        transmissions_[vtS_] = stored;

        SendPdu(vtS_, false, fi, stored.data, std::nullopt);
        vtS_ = static_cast<uint16_t>((vtS_ + 1) % SnModulus);
        offset += chunk;
    }
}

void LteAmEntity::TransmitStored(StoredSdu &stored, bool poll)
{
    if (stored.transmissions >= config_.maxRetx)
    {
        Fail();
        return;
    }
    stored.transmissions++;
    retransmissions_++;
    SendPdu(stored.sn, poll, stored.fi, stored.data, std::nullopt);
}

void LteAmEntity::OnStatusPdu(const std::vector<uint8_t> &pdu)
{
    if (state_ != AmState::ACTIVE)
        return;

    StatusPdu status;
    std::string why;
    if (!DecodeStatus(pdu.data(), pdu.size(), status, &why))
        return;

    while (vtA_ != status.ackSn && Distance(vtA_, status.ackSn) < Window)
    {
        transmissions_.erase(vtA_);
        vtA_ = static_cast<uint16_t>((vtA_ + 1) % SnModulus);
    }

    for (const auto &nack : status.nacks)
    {
        const auto it = transmissions_.find(nack.sn);
        if (it == transmissions_.end())
            continue;
        if (!nack.soRange)
        {
            TransmitStored(it->second, false);
            if (state_ != AmState::ACTIVE)
                return;
            continue;
        }
        StoredSdu &stored = it->second;
        const uint16_t start = nack.soRange->first;
        const uint16_t end = nack.soRange->second;
        if (start >= stored.data.size())
            continue;
        const size_t last = std::min<size_t>(end == SoMax ? stored.data.size() - 1 : end, stored.data.size() - 1);
        std::vector<uint8_t> piece(stored.data.begin() + start, stored.data.begin() + last + 1);
        const bool coversEnd = last + 1 == stored.data.size();
        if (stored.transmissions >= config_.maxRetx)
        {
            Fail();
            return;
        }
        stored.transmissions++;
        retransmissions_++;
        SendPdu(stored.sn, false, stored.fi, piece, std::make_pair(start, coversEnd ? SoMax : static_cast<uint16_t>(last)));
    }
}

void LteAmEntity::OnPdu(const std::vector<uint8_t> &pdu)
{
    if (state_ != AmState::ACTIVE)
        return;

    AmdPdu decoded;
    std::string why;
    if (!DecodeAmd(pdu.data(), pdu.size(), decoded, &why))
        return;

    if (Distance(vrR_, decoded.sn) >= Window)
    {
        droppedOutOfWindow_++;
        statusPending_ = true;
        return;
    }

    RxEntry entry;
    const auto existing = receive_.find(decoded.sn);
    if (existing != receive_.end())
        entry = existing->second;

    if (decoded.segment)
    {
        if (decoded.so == 0)
            entry.firstFi = decoded.fi;
        if (decoded.lsf)
            entry.lastFi = decoded.fi;
    }
    else
    {
        entry.firstFi = decoded.fi;
        entry.lastFi = decoded.fi;
    }
    RxSegment segment;
    segment.so = decoded.segment ? decoded.so : 0;
    segment.lsf = decoded.segment ? decoded.lsf : true;
    segment.data = decoded.data;
    entry.segments.push_back(segment);

    std::sort(entry.segments.begin(), entry.segments.end(),
              [](const RxSegment &a, const RxSegment &b) { return a.so < b.so; });
    size_t covered = 0;
    bool complete = false;
    for (const auto &part : entry.segments)
    {
        if (part.so > covered)
            break;
        covered = std::max(covered, static_cast<size_t>(part.so) + part.data.size());
        if (part.lsf)
        {
            complete = true;
            entry.totalSize = covered;
            break;
        }
    }
    entry.complete = complete;
    receive_[decoded.sn] = entry;
    // Anything received may change what is missing, so a report is due. The
    // highest received SN takes the partially received PDU itself into account:
    // a half-received PDU at VR(R) still has to be reported.
    statusPending_ = true;
    const int receivedDistance = Distance(vrR_, decoded.sn);
    if (receivedDistance + 1 > Distance(vrR_, vrH_))
        vrH_ = static_cast<uint16_t>((vrR_ + receivedDistance + 1) % SnModulus);

    if (decoded.sn == vrR_)
        TryDeliverInOrder();
    else
    {
        reordering_ = true;
        if (Distance(vrR_, decoded.sn) > Distance(vrR_, vrH_))
            vrH_ = static_cast<uint16_t>((vrR_ + Distance(vrR_, decoded.sn)) % SnModulus);
        statusPending_ = true;
    }
}

void LteAmEntity::TryDeliverInOrder()
{
    while (true)
    {
        const auto it = receive_.find(vrR_);
        if (it == receive_.end() || !it->second.complete)
            break;

        std::vector<uint8_t> data;
        std::sort(it->second.segments.begin(), it->second.segments.end(),
                  [](const RxSegment &a, const RxSegment &b) { return a.so < b.so; });
        for (const auto &part : it->second.segments)
            data.insert(data.end(), part.data.begin(), part.data.end());

        // Reassemble the SDU across PDUs: FI marks where one SDU starts and
        // ends, so a segmented SDU must not be delivered piece by piece.
        const FramingInfo first = it->second.firstFi;
        const FramingInfo last = it->second.lastFi;
        if (first == FramingInfo::COMPLETE && last == FramingInfo::COMPLETE)
        {
            deliverer_(data);
            delivered_++;
            assembly_.clear();
        }
        else if (first == FramingInfo::FIRST_SEGMENT)
        {
            assembly_ = data;
            if (last == FramingInfo::LAST_SEGMENT || last == FramingInfo::COMPLETE)
            {
                deliverer_(assembly_);
                delivered_++;
                assembly_.clear();
            }
        }
        else
        {
            assembly_.insert(assembly_.end(), data.begin(), data.end());
            if (last == FramingInfo::LAST_SEGMENT || last == FramingInfo::COMPLETE)
            {
                deliverer_(assembly_);
                delivered_++;
                assembly_.clear();
            }
        }
        receive_.erase(it);
        vrR_ = static_cast<uint16_t>((vrR_ + 1) % SnModulus);
        statusPending_ = true;
        prohibitTimer_ = 0;
    }
    if (receive_.empty())
        reordering_ = false;
}

void LteAmEntity::SendStatus()
{
    StatusPdu status;
    status.ackSn = vrR_;

    for (int offset = 0; offset < Distance(vrR_, vrH_); offset++)
    {
        const uint16_t sn = static_cast<uint16_t>((vrR_ + offset) % SnModulus);
        const auto it = receive_.find(sn);
        if (it == receive_.end())
        {
            // Nothing at all arrived for this SN: a whole-PDU NACK.
            StatusNack nack;
            nack.sn = sn;
            status.nacks.push_back(nack);
            continue;
        }
        if (it->second.complete)
            continue;  // Never nack a fully reconstructed PDU.

        // Partially received: report every byte range that is still missing.
        // The segments are kept sorted on insertion, but sort defensively.
        auto segments = it->second.segments;
        std::sort(segments.begin(), segments.end(),
                  [](const RxSegment &a, const RxSegment &b) { return a.so < b.so; });

        size_t covered = 0;
        bool sawEnd = false;
        for (const auto &segment : segments)
        {
            if (segment.so > covered)
            {
                StatusNack gap;
                gap.sn = sn;
                gap.soRange = std::make_pair(static_cast<uint16_t>(covered), static_cast<uint16_t>(segment.so - 1));
                status.nacks.push_back(gap);
            }
            covered = std::max(covered, static_cast<size_t>(segment.so) + segment.data.size());
            if (segment.lsf)
            {
                sawEnd = true;
                break;
            }
        }

        if (sawEnd)
        {
            if (covered < it->second.totalSize)
            {
                StatusNack gap;
                gap.sn = sn;
                gap.soRange = std::make_pair(static_cast<uint16_t>(covered),
                                              static_cast<uint16_t>(it->second.totalSize - 1));
                status.nacks.push_back(gap);
            }
        }
        else if (covered > 0 && covered <= SoMax)
        {
            // The last byte of the original PDU has not arrived, so the
            // missing range runs to its end: SOend = 0x7FFF.
            StatusNack gap;
            gap.sn = sn;
            gap.soRange = std::make_pair(static_cast<uint16_t>(covered), static_cast<uint16_t>(SoMax));
            status.nacks.push_back(gap);
        }
    }

    sender_(EncodeStatus(status));
    statusPending_ = false;
    prohibitTimer_ = config_.prohibitTicks;
}

void LteAmEntity::OnTick()
{
    if (state_ != AmState::ACTIVE)
        return;

    if (prohibitTimer_ > 0)
        prohibitTimer_--;
    if (statusPending_ && prohibitTimer_ == 0)
        SendStatus();

    if (reordering_)
    {
        if (++reorderTimer_ >= config_.reorderingTicks)
        {
            reorderTimer_ = 0;
            vrX_ = vrH_;
            vrR_ = vrH_;
            reordering_ = false;
            TryDeliverInOrder();
            statusPending_ = true;
        }
    }

    if (!transmissions_.empty())
    {
        if (++pollTimer_ >= config_.pollTicks)
        {
            pollTimer_ = 0;
            auto oldest = transmissions_.begin();
            TransmitStored(oldest->second, true);
        }
    }
    else
    {
        pollTimer_ = 0;
    }
}

} // namespace lte::rlc::am
