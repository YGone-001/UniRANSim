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
                          std::optional<std::pair<uint16_t, uint16_t>> soRange, const std::vector<uint16_t> &li)
{
    AmdPdu pdu;
    pdu.sn = sn;
    pdu.poll = poll;
    pdu.fi = fi;
    pdu.data = data;
    pdu.li = li;
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

        SendPdu(vtS_, CountNewData(chunk), fi, stored.data, std::nullopt);
        vtS_ = static_cast<uint16_t>((vtS_ + 1) % SnModulus);
        offset += chunk;
    }
}

void LteAmEntity::SubmitSdus(const std::vector<std::vector<uint8_t>> &sdus)
{
    if (state_ != AmState::ACTIVE)
        throw std::logic_error("LTE AM entity is not active");
    if (sdus.empty())
        return;
    if (sdus.size() == 1)
    {
        SubmitSdu(sdus[0]);
        return;
    }

    std::vector<uint16_t> li;
    std::vector<uint8_t> data;
    size_t total = 0;
    for (const auto &sdu : sdus)
    {
        if (sdu.empty())
            throw std::logic_error("an empty SDU cannot be concatenated");
        total += sdu.size();
        data.insert(data.end(), sdu.begin(), sdu.end());
    }
    // Every element but the last carries an LI.
    for (size_t i = 0; i + 1 < sdus.size(); i++)
        li.push_back(static_cast<uint16_t>(sdus[i].size()));

    // Two-octet header, plus the E/LI chain including its padding when the LI
    // count is odd.
    const size_t liBytes = li.size() % 2 == 0 ? (li.size() * 12) / 8 : (li.size() * 12 + 4) / 8;
    if (2 + liBytes + total > config_.maxPduBytes)
        throw std::logic_error("concatenated SDUs do not fit in one PDU");
    if (Distance(vtA_, vtS_) >= Window)
        throw std::logic_error("transmission window is full");

    StoredSdu stored;
    stored.sn = vtS_;
    stored.fi = FramingInfo::COMPLETE;
    stored.data = data;
    stored.li = li;
    stored.transmissions = 1;
    transmissions_[vtS_] = stored;
    SendPdu(vtS_, CountNewData(total), FramingInfo::COMPLETE, data, std::nullopt, li);
    vtS_ = static_cast<uint16_t>((vtS_ + 1) % SnModulus);
}

bool LteAmEntity::CountNewData(size_t bytes)
{
    // TS 36.322 5.3.3.2: PDU_WITHOUT_POLL counts AMD PDUs carrying new data,
    // BYTE_WITHOUT_POLL counts their new data bytes. Either reaching its
    // configured limit asks for a poll, and both reset when one is sent.
    pduWithoutPoll_++;
    byteWithoutPoll_ += bytes;

    bool poll = false;
    if (config_.pollPdu != 0 && pduWithoutPoll_ >= config_.pollPdu)
        poll = true;
    if (config_.pollByte != 0 && byteWithoutPoll_ >= config_.pollByte)
        poll = true;
    if (poll)
    {
        pduWithoutPoll_ = 0;
        byteWithoutPoll_ = 0;
    }
    return poll;
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
    SendPdu(stored.sn, poll, stored.fi, stored.data, std::nullopt, stored.li);
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
        // The LI chain lives at the very beginning of the PDU data, so a
        // replacement segment that starts at offset zero carries it and one
        // that starts later does not. The chain is only sent when the whole
        // element prefix it describes fits in the piece; the receiver would
        // otherwise refuse a chain longer than the data field.
        std::vector<uint16_t> replacementLi;
        if (start == 0)
        {
            size_t described = 0;
            for (auto length : stored.li)
                described += length;
            if (described <= piece.size())
                replacementLi = stored.li;
        }
        SendPdu(stored.sn, false, stored.fi, piece,
                std::make_pair(start, coversEnd ? SoMax : static_cast<uint16_t>(last)), replacementLi);
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
    if (!decoded.li.empty())
        entry.li = decoded.li;

    // Bytes that have already arrived are not inserted a second time. A
    // duplicated PDU would otherwise be concatenated twice when the SDU is
    // reassembled, and a partially overlapping retransmission would append
    // bytes the receiver already holds. Only the still-missing sub-ranges of
    // this PDU are kept, and the LSF flag stays on the piece that reaches the
    // original end of the data.
    const size_t segmentStart = decoded.segment ? decoded.so : 0;
    const bool segmentLsf = decoded.segment ? decoded.lsf : true;
    const size_t segmentEnd = segmentStart + decoded.data.size();

    std::sort(entry.segments.begin(), entry.segments.end(),
              [](const RxSegment &a, const RxSegment &b) { return a.so < b.so; });

    std::vector<RxSegment> missing;
    size_t cursor = segmentStart;
    for (const auto &part : entry.segments)
    {
        const size_t partEnd = static_cast<size_t>(part.so) + part.data.size();
        if (partEnd <= cursor)
            continue;
        if (part.so >= segmentEnd)
            break;
        if (part.so > cursor)
        {
            RxSegment piece;
            piece.so = static_cast<uint16_t>(cursor);
            piece.lsf = false;
            piece.data.assign(decoded.data.begin() + static_cast<long>(cursor - segmentStart),
                              decoded.data.begin() + static_cast<long>(part.so - segmentStart));
            missing.push_back(std::move(piece));
        }
        cursor = partEnd;
        if (cursor >= segmentEnd)
            break;
    }
    if (cursor < segmentEnd)
    {
        RxSegment piece;
        piece.so = static_cast<uint16_t>(cursor);
        piece.lsf = segmentLsf;
        piece.data.assign(decoded.data.begin() + static_cast<long>(cursor - segmentStart), decoded.data.end());
        missing.push_back(std::move(piece));
    }
    for (auto &piece : missing)
        entry.segments.push_back(std::move(piece));

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
            // Several SDUs may share one PDU: the LI chain says where each
            // element ends, and the last element has no LI.
            const auto &li = it->second.li;
            if (li.empty())
            {
                deliverer_(data);
                delivered_++;
            }
            else
            {
                size_t offset = 0;
                for (size_t i = 0; i <= li.size(); i++)
                {
                    const size_t length = i < li.size() ? li[i] : data.size() - offset;
                    if (offset + length > data.size())
                        break;
                    deliverer_(std::vector<uint8_t>(data.begin() + static_cast<long>(offset),
                                                    data.begin() + static_cast<long>(offset + length)));
                    delivered_++;
                    offset += length;
                }
            }
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
            // TS 36.322 5.2.2.4 updates RX_Highest_Status on t-Reordering
            // expiry; it does not advance RX_Next. Moving VR(R) to VR(H) here
            // would acknowledge past the hole, and because the STATUS report is
            // computed over [VR(R), VR(H)) the missing SN would never be named
            // again - the gap would be dropped silently. Keep VR(R) where it is
            // so the report names the hole and the peer retransmits it.
            vrX_ = vrH_;
            reordering_ = false;
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
