//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// A test-owned node on the simulated Uu link, shared by the RLC AM and SRB1
// acceptance suites. It forwards, drops, duplicates, delays, reorders or
// re-segments frames; it never repairs loss and never fabricates an ACK.
#pragma once

#include <lte/rrc-runtime/lte_am.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace uu_test
{

using namespace lte;
using namespace lte::rlc::am;

enum class Endpoint
{
    UE,
    ENB
};

// Deterministic link behaviour for one direction. Every counter is one-based
// and counts PDUs of that type in that direction; -1 disables the rule.
struct Impairment
{
    int dropAmdAt{-1};
    int dropStatusAt{-1};
    int splitAmdAt{-1};
    uint16_t splitSo{0};
    // false: the head is delivered and the tail is lost. true: the tail is
    // delivered and the head is lost.
    bool splitKeepTail{false};
    int duplicateAmdAt{-1};
    int reorderAmdAt{-1};
    int delayAmdAt{-1};
    int delayRounds{0};
    bool dropAllAmd{false};
    bool dropAllStatus{false};
};

// One frame as it crossed the link, decoded with the LTE codec. This is the
// evidence stream: direction, endpoint, PDU type, SN, SO, LSF, LI count, poll
// bit, length and, for a STATUS, the ACK_SN and the first NACK range.
struct TraceEntry
{
    uint32_t round{0};
    Endpoint from{Endpoint::UE};
    Endpoint to{Endpoint::ENB};
    bool delivered{true};
    bool amd{true};
    uu::Direction label{uu::Direction::UPLINK};
    uu::LogicalChannel channel{uu::LogicalChannel::DCCH};
    size_t bytes{0};
    uint16_t sn{0};
    bool segment{false};
    uint16_t so{0};
    bool lsf{false};
    bool poll{false};
    size_t liCount{0};
    uint16_t ackSn{0};
    size_t nacks{0};
    bool nackHasSo{false};
    uint16_t nackSoStart{0};
    uint16_t nackSoEnd{0};
};

inline std::string Describe(const TraceEntry &entry)
{
    std::string line = "r" + std::to_string(entry.round) + " " +
                       (entry.from == Endpoint::UE ? "ue->enb " : "enb->ue ");
    line += entry.delivered ? "sent " : "lost ";
    line += entry.label == uu::Direction::UPLINK ? "ul " : "dl ";
    if (entry.channel == uu::LogicalChannel::CCCH)
    {
        line += "CCCH len=" + std::to_string(entry.bytes);
        return line;
    }
    line += entry.amd ? "AMD" : "STATUS";
    if (entry.amd)
    {
        line += " sn=" + std::to_string(entry.sn);
        if (entry.segment)
            line += " so=" + std::to_string(entry.so) + (entry.lsf ? " lsf" : "");
        if (entry.poll)
            line += " poll";
        if (entry.liCount != 0)
            line += " li=" + std::to_string(entry.liCount);
    }
    else
    {
        line += " ack=" + std::to_string(entry.ackSn) + " nacks=" + std::to_string(entry.nacks);
        if (entry.nackHasSo)
            line += " so=" + std::to_string(entry.nackSoStart) + ".." + std::to_string(entry.nackSoEnd);
    }
    line += " len=" + std::to_string(entry.bytes);
    return line;
}

// A test-owned node on the Uu link. It owns the two sockets the endpoints talk
// to, so every datagram it forwards has crossed the real transport twice.
class UuRelay
{
  public:
    bool Bind(std::string *why)
    {
        auto ueSide = uu::Socket::BindLoopback(0, why);
        auto enbSide = uu::Socket::BindLoopback(0, why);
        if (!ueSide || !enbSide)
            return false;
        ueSide_ = std::move(*ueSide);
        enbSide_ = std::move(*enbSide);
        return true;
    }

    void CloseSockets() noexcept
    {
        ueSide_.Close();
        enbSide_.Close();
    }

    [[nodiscard]] uint16_t UeFacingPort() const
    {
        return ueSide_.Port();
    }
    [[nodiscard]] uint16_t EnbFacingPort() const
    {
        return enbSide_.Port();
    }

    void SetPeers(uint16_t uePort, uint16_t enbPort)
    {
        uePort_ = uePort;
        enbPort_ = enbPort;
    }

    void SetImpairments(const Impairment &uplink, const Impairment &downlink)
    {
        uplink_ = uplink;
        downlink_ = downlink;
    }

    void Pump()
    {
        round_++;
        uu::Frame frame;
        while (ueSide_.Receive(frame, 0, nullptr))
            Handle(Endpoint::UE, frame);
        while (enbSide_.Receive(frame, 0, nullptr))
            Handle(Endpoint::ENB, frame);

        for (size_t i = 0; i < delayed_.size();)
        {
            Delayed item = delayed_[i];
            if (--item.roundsLeft <= 0)
            {
                delayed_.erase(delayed_.begin() + static_cast<long>(i));
                Deliver(item.to == Endpoint::ENB ? Endpoint::UE : Endpoint::ENB, item.to, item.frame);
            }
            else
            {
                delayed_[i].roundsLeft = item.roundsLeft;
                i++;
            }
        }
    }

    [[nodiscard]] const std::vector<TraceEntry> &Trace() const
    {
        return trace_;
    }

  private:
    struct Delayed
    {
        Endpoint to{Endpoint::ENB};
        uu::Frame frame{};
        int roundsLeft{0};
    };

    static size_t Index(Endpoint to)
    {
        return to == Endpoint::ENB ? 0U : 1U;
    }

    // The relay forwards the frame exactly as the endpoint emitted it. It does
    // not repair a wrong direction label, a wrong channel or a wrong
    // association: the receiving bearer has to notice those for itself.
    void RawSend(Endpoint to, const uu::Frame &frame)
    {
        if (to == Endpoint::ENB)
            enbSide_.Send(enbPort_, frame, nullptr);
        else
            ueSide_.Send(uePort_, frame, nullptr);
    }

    void Record(Endpoint from, Endpoint to, const uu::Frame &frame, bool delivered)
    {
        if (frame.payload.empty())
            return;
        TraceEntry entry;
        entry.round = round_;
        entry.from = from;
        entry.to = to;
        entry.delivered = delivered;
        entry.label = frame.direction;
        entry.channel = frame.channel;
        entry.bytes = frame.payload.size();
        // Only a DCCH payload is an RLC PDU; a CCCH payload is an RRC message
        // in transparent mode and is not decoded here.
        entry.amd = frame.channel == uu::LogicalChannel::DCCH && (frame.payload[0] & 0x80U) != 0;

        std::string why;
        if (frame.channel != uu::LogicalChannel::DCCH)
        {
        }
        else if (entry.amd)
        {
            AmdPdu pdu;
            if (DecodeAmd(frame.payload.data(), frame.payload.size(), pdu, &why))
            {
                entry.sn = pdu.sn;
                entry.segment = pdu.segment;
                entry.so = pdu.segment ? pdu.so : 0;
                entry.lsf = pdu.lsf;
                entry.poll = pdu.poll;
                entry.liCount = pdu.li.size();
            }
        }
        else
        {
            StatusPdu status;
            if (DecodeStatus(frame.payload.data(), frame.payload.size(), status, &why))
            {
                entry.ackSn = status.ackSn;
                entry.nacks = status.nacks.size();
                if (!status.nacks.empty() && status.nacks[0].soRange)
                {
                    entry.nackHasSo = true;
                    entry.nackSoStart = status.nacks[0].soRange->first;
                    entry.nackSoEnd = status.nacks[0].soRange->second;
                }
            }
        }
        trace_.push_back(entry);
    }

    // Delivers one frame and, when a reordered frame is waiting, releases that
    // one afterwards so the peer sees them out of order.
    void Deliver(Endpoint from, Endpoint to, const uu::Frame &frame, bool hold = false)
    {
        const size_t index = Index(to);
        if (hold)
        {
            reorderHold_[index] = frame;
            return;
        }
        RawSend(to, frame);
        Record(from, to, frame, true);
        if (reorderHold_[index])
        {
            uu::Frame held = *reorderHold_[index];
            reorderHold_[index].reset();
            RawSend(to, held);
            Record(from, to, held, true);
        }
    }

    // Replaces one AMD PDU with an AMD segment pair and loses one of them, which
    // is how a selected byte range is dropped without touching the transport or
    // the header the transmitter built.
    bool Split(Endpoint from, Endpoint to, const uu::Frame &frame, const Impairment &policy)
    {
        AmdPdu pdu;
        std::string why;
        if (!DecodeAmd(frame.payload.data(), frame.payload.size(), pdu, &why))
            return false;
        if (pdu.segment)
            return false;
        const size_t split = policy.splitSo;
        if (split == 0 || split >= pdu.data.size())
            return false;
        size_t described = 0;
        for (auto value : pdu.li)
            described += value;
        // An LI chain longer than the head would make the head undecodable.
        if (described > split)
            return false;

        AmdPdu head;
        head.sn = pdu.sn;
        head.poll = pdu.poll;
        head.fi = pdu.fi;
        head.segment = true;
        head.so = 0;
        head.lsf = false;
        head.li = pdu.li;
        head.data.assign(pdu.data.begin(), pdu.data.begin() + static_cast<long>(split));

        AmdPdu tail;
        tail.sn = pdu.sn;
        tail.poll = pdu.poll;
        tail.fi = pdu.fi;
        tail.segment = true;
        tail.so = static_cast<uint16_t>(split);
        tail.lsf = true;
        tail.data.assign(pdu.data.begin() + static_cast<long>(split), pdu.data.end());

        uu::Frame headFrame = frame;
        headFrame.payload = EncodeAmd(head);
        uu::Frame tailFrame = frame;
        tailFrame.payload = EncodeAmd(tail);

        if (policy.splitKeepTail)
        {
            Record(from, to, headFrame, false);
            Deliver(from, to, tailFrame);
        }
        else
        {
            Deliver(from, to, headFrame);
            Record(from, to, tailFrame, false);
        }
        return true;
    }

    void Handle(Endpoint from, const uu::Frame &frame)
    {
        if (frame.payload.empty())
            return;

        const Endpoint to = from == Endpoint::UE ? Endpoint::ENB : Endpoint::UE;
        // Only a DCCH payload is an RLC PDU. SRB0 traffic on CCCH is forwarded
        // unchanged: the impairments are RLC impairments, and reading an RRC
        // message's first octet as a D/C bit would misclassify it.
        if (frame.channel != uu::LogicalChannel::DCCH)
        {
            Deliver(from, to, frame);
            return;
        }
        const Impairment &policy = from == Endpoint::UE ? uplink_ : downlink_;
        const bool amd = (frame.payload[0] & 0x80U) != 0;

        int &counter = amd ? (from == Endpoint::UE ? uplinkAmd_ : downlinkAmd_)
                           : (from == Endpoint::UE ? uplinkStatus_ : downlinkStatus_);
        counter++;
        const int occurrence = counter;

        if (amd ? policy.dropAllAmd : policy.dropAllStatus)
        {
            Record(from, to, frame, false);
            return;
        }
        if (amd ? occurrence == policy.dropAmdAt : occurrence == policy.dropStatusAt)
        {
            Record(from, to, frame, false);
            return;
        }
        if (amd && occurrence == policy.splitAmdAt && Split(from, to, frame, policy))
            return;
        if (amd && occurrence == policy.delayAmdAt && policy.delayRounds > 0)
        {
            delayed_.push_back(Delayed{to, frame, policy.delayRounds});
            return;
        }
        if (amd && occurrence == policy.duplicateAmdAt)
        {
            RawSend(to, frame);
            Record(from, to, frame, true);
        }
        Deliver(from, to, frame, amd && occurrence == policy.reorderAmdAt);
    }

    uu::Socket ueSide_{};
    uu::Socket enbSide_{};
    uint16_t uePort_{0};
    uint16_t enbPort_{0};
    Impairment uplink_{};
    Impairment downlink_{};
    int uplinkAmd_{0};
    int downlinkAmd_{0};
    int uplinkStatus_{0};
    int downlinkStatus_{0};
    uint32_t round_{0};
    std::vector<Delayed> delayed_{};
    std::vector<TraceEntry> trace_{};
    std::optional<uu::Frame> reorderHold_[2]{};
};

} // namespace uu_test
