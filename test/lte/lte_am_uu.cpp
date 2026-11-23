//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1-R2-C3: the LTE RLC AM bearer over the simulated Uu socket.
//
// Every PDU below is serialized by the LTE codec, wrapped in the B6-A envelope
// and carried by a real loopback datagram. The impairment node sits on the link
// - it replays, drops, duplicates, delays or re-segments what the endpoints
// actually emitted - so nothing reaches an entity except through a socket.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/lte_am.hpp>
#include <lte/rrc-runtime/lte_am_bearer.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using namespace lte;
using namespace lte::rlc::am;

namespace
{

constexpr uint32_t ChanA = 0x41;
constexpr uint32_t ChanB = 0x42;

std::vector<uint8_t> Pattern(size_t count, uint8_t seed)
{
    std::vector<uint8_t> out(count);
    for (size_t i = 0; i < count; i++)
        out[i] = static_cast<uint8_t>((seed + i * 7U) & 0xFFU);
    return out;
}

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

std::string Describe(const TraceEntry &entry)
{
    std::string line = "r" + std::to_string(entry.round) + " " +
                       (entry.from == Endpoint::UE ? "ue->enb " : "enb->ue ");
    line += entry.delivered ? "sent " : "lost ";
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

    void RawSend(Endpoint to, uu::Frame frame)
    {
        frame.direction = to == Endpoint::ENB ? uu::Direction::DOWNLINK : uu::Direction::UPLINK;
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
        entry.bytes = frame.payload.size();
        entry.amd = (frame.payload[0] & 0x80U) != 0;

        std::string why;
        if (entry.amd)
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

// Two independent LTE AM endpoints inside one process, each with its own entity
// and its own socket, connected only through the relay.
class UuSession
{
  public:
    UuSession(AmConfig ueConfig, AmConfig enbConfig, uint32_t association)
    {
        if (!relay_.Bind(&why_))
            return;
        auto ueSocket = uu::Socket::BindLoopback(0, &why_);
        auto enbSocket = uu::Socket::BindLoopback(0, &why_);
        if (!ueSocket || !enbSocket)
            return;

        enbPort_ = enbSocket->Port();
        relay_.SetPeers(ueSocket->Port(), enbPort_);
        ue_ = std::make_unique<LteAmBearer>(std::move(*ueSocket), relay_.UeFacingPort(), association, ueConfig,
                                            [this](std::vector<uint8_t> sdu) {
                                                ueDelivered_.push_back(std::move(sdu));
                                            });
        enb_ = std::make_unique<LteAmBearer>(std::move(*enbSocket), relay_.EnbFacingPort(), association, enbConfig,
                                             [this](std::vector<uint8_t> sdu) {
                                                 enbDelivered_.push_back(std::move(sdu));
                                             });
        ok_ = true;
    }

    [[nodiscard]] bool Ok() const
    {
        return ok_;
    }
    [[nodiscard]] const std::string &Why() const
    {
        return why_;
    }

    LteAmBearer &Ue()
    {
        return *ue_;
    }
    LteAmBearer &Enb()
    {
        return *enb_;
    }
    UuRelay &Relay()
    {
        return relay_;
    }

    [[nodiscard]] uint16_t EnbPort() const
    {
        return enbPort_;
    }
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &UeDelivered() const
    {
        return ueDelivered_;
    }
    [[nodiscard]] const std::vector<std::vector<uint8_t>> &EnbDelivered() const
    {
        return enbDelivered_;
    }
    [[nodiscard]] const std::vector<TraceEntry> &Trace() const
    {
        return relay_.Trace();
    }

    // One scheduling round: the link moves what is queued, each endpoint drains
    // every frame available to it, and then the timers advance once.
    void Round()
    {
        relay_.Pump();
        for (int i = 0; i < 8 && ue()->Pump(0); i++)
        {
        }
        for (int i = 0; i < 8 && enb()->Pump(0); i++)
        {
        }
        ue()->Tick();
        enb()->Tick();
    }

    bool RunUntil(const std::function<bool()> &done, int maxRounds)
    {
        for (int i = 0; i < maxRounds; i++)
        {
            Round();
            if (done())
                return true;
        }
        return done();
    }

    // Advances the transmitter while the peer is not scheduled at all, so no
    // STATUS can come back and the poll timer is the only thing that moves.
    void UeOnlyRound()
    {
        relay_.Pump();
        ue()->Pump(0);
        ue()->Tick();
    }

  private:
    LteAmBearer *ue()
    {
        return ue_.get();
    }
    LteAmBearer *enb()
    {
        return enb_.get();
    }

    UuRelay relay_{};
    std::unique_ptr<LteAmBearer> ue_{};
    std::unique_ptr<LteAmBearer> enb_{};
    uint16_t enbPort_{0};
    std::string why_{};
    bool ok_{false};
    std::vector<std::vector<uint8_t>> ueDelivered_{};
    std::vector<std::vector<uint8_t>> enbDelivered_{};
};

} // namespace

TEST_CASE("lte/rlc-am-uu/an sdu crosses the uu socket and the status releases the buffer")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    const std::vector<uint8_t> sdu = {0x11, 0x22, 0x33};
    session.Ue().SubmitSdu(sdu);
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 1 && session.Ue().VtA() == 1; }, 40));

    CHECK(session.EnbDelivered()[0] == sdu);
    CHECK(session.Ue().VtS() == 1);
    CHECK(session.UeDelivered().empty());
    CHECK(session.Ue().Retransmissions() == 0);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));

    REQUIRE(trace.size() == 2);
    CHECK(trace[0].from == Endpoint::UE);
    CHECK(trace[0].to == Endpoint::ENB);
    CHECK(trace[0].delivered);
    CHECK(trace[0].amd);
    CHECK(trace[0].sn == 0);
    CHECK(trace[0].bytes == 5);  // two-octet header and three data bytes
    CHECK(trace[0].liCount == 0);
    CHECK(trace[1].from == Endpoint::ENB);
    CHECK_FALSE(trace[1].amd);
    CHECK(trace[1].ackSn == 1);
    CHECK(trace[1].nacks == 0);
    CHECK(trace[1].bytes == 2);
}

TEST_CASE("lte/rlc-am-uu/both directions exchange and acknowledge independently")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    session.Ue().SubmitSdu({0xA0, 0xA1});
    session.Enb().SubmitSdu({0xB0});
    REQUIRE(session.RunUntil(
        [&] {
            return session.EnbDelivered().size() == 1 && session.UeDelivered().size() == 1 &&
                   session.Ue().VtA() == 1 && session.Enb().VtA() == 1;
        },
        60));

    CHECK(session.EnbDelivered()[0] == std::vector<uint8_t>({0xA0, 0xA1}));
    CHECK(session.UeDelivered()[0] == std::vector<uint8_t>({0xB0}));
    CHECK(session.Ue().VrR() == 1);
    CHECK(session.Enb().VrR() == 1);
}

TEST_CASE("lte/rlc-am-uu/a lost amd pdu is nacked and retransmitted with a poll")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.dropAmdAt = 1;
    session.Relay().SetImpairments(uplink, Impairment{});

    session.Ue().SubmitSdu({0xC1, 0xC2});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 1 && session.Ue().VtA() == 1; }, 80));

    CHECK(session.EnbDelivered()[0] == std::vector<uint8_t>({0xC1, 0xC2}));
    CHECK(session.Ue().Retransmissions() == 1);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
    REQUIRE(trace.size() == 3);
    CHECK_FALSE(trace[0].delivered);
    CHECK(trace[0].amd);
    CHECK(trace[0].sn == 0);
    CHECK(trace[1].delivered);
    CHECK(trace[1].amd);
    CHECK(trace[1].sn == 0);
    CHECK(trace[1].poll);
    CHECK_FALSE(trace[2].amd);
    CHECK(trace[2].ackSn == 1);
}

TEST_CASE("lte/rlc-am-uu/a lost status is recovered by the poll timer without a false ack")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment downlink;
    downlink.dropStatusAt = 1;
    session.Relay().SetImpairments(Impairment{}, downlink);

    session.Ue().SubmitSdu({0xD1});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 1 && session.Ue().VtA() == 1; }, 80));

    CHECK(session.EnbDelivered().size() == 1);
    CHECK(session.Ue().Retransmissions() == 1);
    CHECK(session.Ue().VtA() == 1);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
    REQUIRE(trace.size() == 4);
    CHECK_FALSE(trace[1].amd);
    CHECK_FALSE(trace[1].delivered);
    CHECK(trace[1].ackSn == 1);
    CHECK(trace[2].amd);
    CHECK(trace[2].poll);
    CHECK(trace[3].amd == false);
    CHECK(trace[3].delivered);
    CHECK(trace[3].ackSn == 1);
}

TEST_CASE("lte/rlc-am-uu/a duplicated pdu that arrives before its gap is delivered once")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.delayAmdAt = 1;  // SN 0 is held back, so SN 1 arrives out of order
    uplink.delayRounds = 4;
    uplink.duplicateAmdAt = 2;
    session.Relay().SetImpairments(uplink, Impairment{});

    session.Ue().SubmitSdu({0xA1});
    session.Ue().SubmitSdu({0xA2});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 2; }, 40));

    // The second copy of SN 1 must contribute no byte twice, so each SDU keeps
    // its single-byte size.
    REQUIRE(session.EnbDelivered().size() == 2);
    CHECK(session.EnbDelivered()[0] == std::vector<uint8_t>({0xA1}));
    CHECK(session.EnbDelivered()[1] == std::vector<uint8_t>({0xA2}));
    CHECK(session.Enb().VrR() == 2);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
}

TEST_CASE("lte/rlc-am-uu/reordering is buffered and delivered in sequence")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.reorderAmdAt = 1;
    session.Relay().SetImpairments(uplink, Impairment{});

    session.Ue().SubmitSdu({0xB1});
    session.Ue().SubmitSdu({0xB2});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 2; }, 40));

    const auto &trace = session.Trace();
    REQUIRE(trace.size() >= 2);
    CHECK(trace[0].sn == 1);
    CHECK(trace[1].sn == 0);
    CHECK(session.EnbDelivered()[0] == std::vector<uint8_t>({0xB1}));
    CHECK(session.EnbDelivered()[1] == std::vector<uint8_t>({0xB2}));
    CHECK(session.Enb().VrR() == 2);
    CHECK(session.Ue().Retransmissions() == 0);
}

TEST_CASE("lte/rlc-am-uu/a missing byte range is nacked and re-segmented over the uu")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.splitAmdAt = 1;
    uplink.splitSo = 6;
    session.Relay().SetImpairments(uplink, Impairment{});

    const auto sdu = Pattern(12, 0x10);
    session.Ue().SubmitSdu(sdu);
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 1 && session.Ue().VtA() == 1; }, 80));

    CHECK(session.EnbDelivered()[0] == sdu);
    CHECK(session.Ue().Retransmissions() == 1);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));

    REQUIRE(trace.size() == 5);
    CHECK(trace[0].amd);
    CHECK(trace[0].segment);
    CHECK(trace[0].so == 0);
    CHECK_FALSE(trace[0].lsf);
    CHECK(trace[0].delivered);
    CHECK_FALSE(trace[1].delivered);
    CHECK(trace[1].segment);
    CHECK(trace[1].so == 6);
    CHECK(trace[1].lsf);

    CHECK_FALSE(trace[2].amd);
    CHECK(trace[2].ackSn == 0);
    REQUIRE(trace[2].nacks == 1);
    CHECK(trace[2].nackHasSo);
    CHECK(trace[2].nackSoStart == 6);
    CHECK(trace[2].nackSoEnd == SoMax);

    // The replacement segment covers exactly the reported range and ends the
    // PDU, so it carries LSF.
    CHECK(trace[3].amd);
    CHECK(trace[3].segment);
    CHECK(trace[3].so == 6);
    CHECK(trace[3].lsf);
    CHECK(trace[3].bytes == 10);

    CHECK_FALSE(trace[4].amd);
    CHECK(trace[4].ackSn == 1);
    CHECK(trace[4].nacks == 0);
}

TEST_CASE("lte/rlc-am-uu/a lost head segment is replaced with its li chain intact")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.splitAmdAt = 1;
    uplink.splitSo = 8;
    uplink.splitKeepTail = true;
    session.Relay().SetImpairments(uplink, Impairment{});

    const std::vector<std::vector<uint8_t>> sdus = {Pattern(2, 0x01), Pattern(3, 0x02), Pattern(7, 0x03)};
    session.Ue().SubmitSdus(sdus);
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 3 && session.Ue().VtA() == 1; }, 80));

    REQUIRE(session.EnbDelivered().size() == 3);
    for (size_t i = 0; i < sdus.size(); i++)
        CHECK(session.EnbDelivered()[i] == sdus[i]);

    const auto &trace = session.Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));

    // The replacement starts at offset zero, so it is the piece that has to
    // carry the two LIs of the original PDU.
    REQUIRE(trace.size() == 5);
    CHECK_FALSE(trace[0].delivered);
    CHECK(trace[0].so == 0);
    CHECK(trace[1].delivered);
    CHECK(trace[1].so == 8);
    CHECK(trace[2].nackHasSo);
    CHECK(trace[2].nackSoStart == 0);
    CHECK(trace[2].nackSoEnd == 7);
    CHECK(trace[3].amd);
    CHECK(trace[3].so == 0);
    CHECK(trace[3].liCount == 2);
    CHECK(trace[4].ackSn == 1);
}

TEST_CASE("lte/rlc-am-uu/concatenated sdus keep their li chain across a retransmission")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.dropAmdAt = 1;
    session.Relay().SetImpairments(uplink, Impairment{});

    const std::vector<std::vector<uint8_t>> sdus = {{0x01}, {0x02, 0x03}, {0x04}};
    session.Ue().SubmitSdus(sdus);
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 3 && session.Ue().VtA() == 1; }, 80));

    REQUIRE(session.EnbDelivered().size() == 3);
    for (size_t i = 0; i < sdus.size(); i++)
        CHECK(session.EnbDelivered()[i] == sdus[i]);

    const auto &trace = session.Trace();
    REQUIRE(trace.size() == 3);
    CHECK(trace[0].liCount == 2);
    CHECK(trace[1].liCount == 2);
    CHECK(trace[1].poll);
    CHECK(trace[1].bytes == trace[0].bytes);
}

TEST_CASE("lte/rlc-am-uu/status prohibition spaces two reports over the uu")
{
    AmConfig ueConfig;
    ueConfig.pollTicks = 1000;  // no retransmission: the hole must stay open
    AmConfig enbConfig;
    enbConfig.prohibitTicks = 6;
    enbConfig.reorderingTicks = 1000;
    UuSession session(ueConfig, enbConfig, ChanA);
    REQUIRE(session.Ok());

    // SN 0 is lost, so SN 1 and SN 2 arrive out of order and each triggers a
    // report while nothing can be delivered. The reports themselves are dropped,
    // so the sender never learns of the hole and cannot close it: only the
    // prohibit timer decides when the second report may leave.
    Impairment uplink;
    uplink.dropAmdAt = 1;
    Impairment downlink;
    downlink.dropAllStatus = true;
    session.Relay().SetImpairments(uplink, downlink);

    session.Ue().SubmitSdu({0x01});
    for (int i = 0; i < 2; i++)
        session.Round();
    session.Ue().SubmitSdu({0x02});
    for (int i = 0; i < 2; i++)
        session.Round();
    session.Ue().SubmitSdu({0x03});
    for (int i = 0; i < 8; i++)
        session.Round();

    std::vector<uint32_t> statusRounds;
    for (const auto &entry : session.Trace())
    {
        if (!entry.amd)
            statusRounds.push_back(entry.round);
    }
    for (const auto &entry : session.Trace())
        MESSAGE(Describe(entry));

    REQUIRE(statusRounds.size() >= 2);
    CHECK(statusRounds[1] - statusRounds[0] >= 5);
    CHECK(session.EnbDelivered().empty());
    CHECK(session.Ue().Retransmissions() == 0);
}

TEST_CASE("lte/rlc-am-uu/the poll timer retransmits while the peer is silent")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());

    session.Ue().SubmitSdu({0x51});
    for (int i = 0; i < 12; i++)
        session.UeOnlyRound();

    CHECK(session.Ue().VtA() == 0);
    CHECK(session.Ue().Retransmissions() == 1);

    const auto &trace = session.Trace();
    REQUIRE(trace.size() == 2);
    CHECK(trace[0].amd);
    CHECK_FALSE(trace[0].poll);
    CHECK(trace[1].amd);
    CHECK(trace[1].poll);
    CHECK(trace[1].sn == 0);
}

TEST_CASE("lte/rlc-am-uu/the reordering timer reports the gap instead of skipping it")
{
    AmConfig enbConfig;
    enbConfig.reorderingTicks = 3;
    enbConfig.prohibitTicks = 1;
    enbConfig.pollTicks = 1000;  // the transmitter stays quiet for the whole test
    UuSession session(AmConfig{}, enbConfig, ChanA);
    REQUIRE(session.Ok());

    Impairment uplink;
    uplink.delayAmdAt = 1;
    uplink.delayRounds = 8;
    Impairment downlink;
    downlink.dropAllStatus = true;
    session.Relay().SetImpairments(uplink, downlink);

    session.Ue().SubmitSdu({0x61});
    session.Ue().SubmitSdu({0x62});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 2; }, 60));

    // The gap was never skipped: RX_Next stayed at SN 0 until SN 0 arrived.
    CHECK(session.EnbDelivered()[0] == std::vector<uint8_t>({0x61}));
    CHECK(session.EnbDelivered()[1] == std::vector<uint8_t>({0x62}));
    CHECK(session.Enb().VrR() == 2);
    CHECK(session.Enb().DroppedOutOfWindow() == 0);

    size_t statuses = 0;
    for (const auto &entry : session.Trace())
    {
        if (!entry.amd && entry.nackHasSo == false && entry.nacks == 1 && entry.ackSn == 0)
            statuses++;
    }
    // The first report comes from the out-of-order arrival, the second from
    // t-Reordering expiry; both name the missing SN 0.
    CHECK(statuses >= 2);
}

TEST_CASE("lte/rlc-am-uu/two ue contexts keep independent state and associations")
{
    UuSession first(AmConfig{}, AmConfig{}, ChanA);
    UuSession second(AmConfig{}, AmConfig{}, ChanB);
    REQUIRE(first.Ok());
    REQUIRE(second.Ok());

    Impairment uplink;
    uplink.dropAmdAt = 1;
    first.Relay().SetImpairments(uplink, Impairment{});

    first.Ue().SubmitSdu({0x71});
    second.Ue().SubmitSdu({0x72});

    // The undisturbed context completes while the other one still has a hole.
    REQUIRE(second.RunUntil([&] { return second.EnbDelivered().size() == 1 && second.Ue().VtA() == 1; }, 20));
    CHECK(first.EnbDelivered().empty());
    CHECK(first.Ue().VtA() == 0);
    CHECK(second.Enb().VrR() == 1);
    CHECK(first.Enb().VrR() == 0);

    REQUIRE(first.RunUntil([&] { return first.EnbDelivered().size() == 1 && first.Ue().VtA() == 1; }, 80));
    CHECK(first.EnbDelivered()[0] == std::vector<uint8_t>({0x71}));
    CHECK(second.EnbDelivered()[0] == std::vector<uint8_t>({0x72}));
    CHECK(second.Ue().Retransmissions() == 0);

    // A frame for another association is consumed and changes nothing.
    auto probe = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(probe.has_value());
    AmdPdu stray;
    stray.sn = 3;
    stray.data = {0xAA};
    uu::Frame frame;
    frame.association = ChanB + 7;
    frame.direction = uu::Direction::DOWNLINK;
    frame.channel = uu::LogicalChannel::DCCH;
    frame.payload = EncodeAmd(stray);
    CHECK(probe->Send(first.EnbPort(), frame, nullptr));
    for (int i = 0; i < 3; i++)
        first.Round();
    CHECK(first.EnbDelivered().size() == 1);
    CHECK(first.Enb().VrR() == 1);
}

TEST_CASE("lte/rlc-am-uu/a released entity stops and a replacement starts from a fresh port")
{
    UuSession session(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(session.Ok());
    const uint16_t oldPort = session.EnbPort();
    const uint16_t oldRelayPort = session.Relay().UeFacingPort();

    session.Ue().SubmitSdu({0x81});
    REQUIRE(session.RunUntil([&] { return session.EnbDelivered().size() == 1; }, 20));

    session.Enb().Release();
    CHECK(session.Enb().State() == AmState::RELEASED);
    CHECK_THROWS(session.Enb().SubmitSdu({0x82}));

    session.Ue().SubmitSdu({0x83});
    for (int i = 0; i < 20; i++)
        session.Round();
    CHECK(session.EnbDelivered().size() == 1);
    CHECK(session.Ue().VtA() < 2);

    // A replacement context binds new sockets, so nothing queued for the old
    // generation can be mistaken for traffic of the new one.
    UuSession replacement(AmConfig{}, AmConfig{}, ChanA);
    REQUIRE(replacement.Ok());
    CHECK(replacement.EnbPort() != oldPort);
    CHECK(replacement.Relay().UeFacingPort() != oldRelayPort);

    replacement.Ue().SubmitSdu({0x84});
    REQUIRE(replacement.RunUntil([&] { return replacement.EnbDelivered().size() == 1; }, 20));
    CHECK(replacement.EnbDelivered()[0] == std::vector<uint8_t>({0x84}));
}

namespace
{

struct ChildReport
{
    uint16_t vtA{0};
    uint16_t vtS{0};
    uint32_t retransmissions{0};
    uint32_t transmissions{0};
};

struct ProcessOutcome
{
    bool ok{false};
    int exitStatus{-1};
    int exitCode{-1};
    ChildReport report{};
    std::vector<std::vector<uint8_t>> delivered{};
    std::vector<TraceEntry> trace{};
};

bool ReadAll(int fd, void *buffer, size_t size)
{
    auto *out = static_cast<uint8_t *>(buffer);
    size_t done = 0;
    while (done < size)
    {
        const ssize_t got = ::read(fd, out + done, size - done);
        if (got <= 0)
            return false;
        done += static_cast<size_t>(got);
    }
    return true;
}

bool WriteAll(int fd, const void *buffer, size_t size)
{
    const auto *in = static_cast<const uint8_t *>(buffer);
    size_t done = 0;
    while (done < size)
    {
        const ssize_t put = ::write(fd, in + done, size - done);
        if (put <= 0)
            return false;
        done += static_cast<size_t>(put);
    }
    return true;
}

// The UE runs in its own process, with its own entity and its own socket. The
// supervisor owns the eNB endpoint and the link; the two sides exchange nothing
// but LTE PDUs, and reconcile by comparing the supervisor's frame log with the
// report the UE process writes for itself.
ProcessOutcome RunUeProcess(const std::vector<std::vector<uint8_t>> &sdus, const AmConfig &ueConfig,
                            const Impairment &uplink, bool concatenate, int roundBudget)
{
    ProcessOutcome outcome;

    UuRelay relay;
    std::string why;
    if (!relay.Bind(&why))
        return outcome;
    auto enbSocket = uu::Socket::BindLoopback(0, &why);
    if (!enbSocket)
        return outcome;

    int toParent[2] = {-1, -1};
    if (::pipe(toParent) != 0)
        return outcome;

    const pid_t child = ::fork();
    if (child < 0)
        return outcome;

    if (child == 0)
    {
        ::close(toParent[0]);
        // The child owns neither the link node nor the eNB endpoint.
        relay.CloseSockets();
        enbSocket->Close();

        auto socket = uu::Socket::BindLoopback(0, nullptr);
        if (!socket)
            ::_exit(11);
        const uint16_t uePort = socket->Port();
        if (!WriteAll(toParent[1], &uePort, sizeof(uePort)))
            ::_exit(12);

        ChildReport report;
        {
            LteAmBearer ue(std::move(*socket), relay.UeFacingPort(), ChanA, ueConfig, nullptr);
            if (concatenate)
                ue.SubmitSdus(sdus);
            else
                for (const auto &sdu : sdus)
                    ue.SubmitSdu(sdu);

            for (int i = 0; i < roundBudget; i++)
            {
                ue.Pump(1);
                ue.Tick();
                if (ue.VtA() == ue.VtS())
                    break;
            }
            report.vtA = ue.VtA();
            report.vtS = ue.VtS();
            report.retransmissions = static_cast<uint32_t>(ue.Retransmissions());
            report.transmissions = static_cast<uint32_t>(ue.Transmissions());
        }
        if (!WriteAll(toParent[1], &report, sizeof(report)))
            ::_exit(13);
        ::_exit(report.vtA == report.vtS ? 0 : 7);
    }

    ::close(toParent[1]);

    uint16_t uePort = 0;
    if (!ReadAll(toParent[0], &uePort, sizeof(uePort)))
    {
        ::close(toParent[0]);
        ::waitpid(child, nullptr, 0);
        return outcome;
    }
    relay.SetPeers(uePort, enbSocket->Port());
    relay.SetImpairments(uplink, Impairment{});

    int status = 0;
    bool reaped = false;
    {
        LteAmBearer enb(std::move(*enbSocket), relay.EnbFacingPort(), ChanA, AmConfig{},
                        [&outcome](std::vector<uint8_t> sdu) { outcome.delivered.push_back(std::move(sdu)); });
        for (int i = 0; i < roundBudget + 2000; i++)
        {
            relay.Pump();
            enb.Pump(1);
            enb.Tick();
            const pid_t done = ::waitpid(child, &status, WNOHANG);
            if (done == child)
            {
                reaped = true;
                break;
            }
        }
    }
    if (!reaped)
        ::waitpid(child, &status, 0);

    outcome.trace = relay.Trace();
    outcome.exitStatus = status;
    outcome.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    outcome.ok = ReadAll(toParent[0], &outcome.report, sizeof(outcome.report));
    ::close(toParent[0]);
    return outcome;
}

} // namespace

TEST_CASE("lte/rlc-am-uu/separate ue process recovers a lost amd pdu")
{
    const auto sdu = Pattern(9, 0x20);
    Impairment uplink;
    uplink.dropAmdAt = 1;

    const ProcessOutcome outcome = RunUeProcess({sdu}, AmConfig{}, uplink, false, 3000);
    REQUIRE(outcome.ok);
    REQUIRE(WIFEXITED(outcome.exitStatus));
    CHECK(outcome.exitCode == 0);
    CHECK(outcome.report.vtS == 1);
    CHECK(outcome.report.vtA == 1);
    CHECK(outcome.report.retransmissions == 1);

    REQUIRE(outcome.delivered.size() == 1);
    CHECK(outcome.delivered[0] == sdu);

    // The supervisor's own log must agree with the UE's report: one lost
    // transmission, one polled retransmission and one acknowledgement.
    REQUIRE(outcome.trace.size() == 3);
    CHECK_FALSE(outcome.trace[0].delivered);
    CHECK(outcome.trace[0].amd);
    CHECK(outcome.trace[1].delivered);
    CHECK(outcome.trace[1].poll);
    CHECK_FALSE(outcome.trace[2].amd);
    CHECK(outcome.trace[2].ackSn == 1);
}

TEST_CASE("lte/rlc-am-uu/separate ue process recovers a partial loss with a segment nack")
{
    const auto sdu = Pattern(12, 0x30);
    Impairment uplink;
    uplink.splitAmdAt = 1;
    uplink.splitSo = 5;

    const ProcessOutcome outcome = RunUeProcess({sdu}, AmConfig{}, uplink, false, 3000);
    REQUIRE(outcome.ok);
    REQUIRE(WIFEXITED(outcome.exitStatus));
    CHECK(outcome.exitCode == 0);
    CHECK(outcome.report.vtS == 1);
    CHECK(outcome.report.vtA == 1);
    CHECK(outcome.report.retransmissions == 1);

    REQUIRE(outcome.delivered.size() == 1);
    CHECK(outcome.delivered[0] == sdu);

    REQUIRE(outcome.trace.size() == 5);
    CHECK(outcome.trace[0].delivered);
    CHECK(outcome.trace[0].so == 0);
    CHECK_FALSE(outcome.trace[1].delivered);
    CHECK(outcome.trace[1].so == 5);
    CHECK(outcome.trace[1].lsf);
    CHECK_FALSE(outcome.trace[2].amd);
    CHECK(outcome.trace[2].nacks == 1);
    CHECK(outcome.trace[2].nackSoStart == 5);
    CHECK(outcome.trace[2].nackSoEnd == SoMax);
    CHECK(outcome.trace[3].amd);
    CHECK(outcome.trace[3].so == 5);
    CHECK(outcome.trace[3].bytes == 4 + 7);
    CHECK(outcome.trace[4].ackSn == 1);
}

TEST_CASE("lte/rlc-am-uu/separate ue process preserves an li chain across a lost pdu")
{
    const std::vector<std::vector<uint8_t>> sdus = {Pattern(2, 0x41), Pattern(4, 0x42), Pattern(3, 0x43)};
    Impairment uplink;
    uplink.dropAmdAt = 1;

    const ProcessOutcome outcome = RunUeProcess(sdus, AmConfig{}, uplink, true, 3000);
    REQUIRE(outcome.ok);
    REQUIRE(WIFEXITED(outcome.exitStatus));
    CHECK(outcome.exitCode == 0);
    CHECK(outcome.report.vtS == 1);
    CHECK(outcome.report.vtA == 1);

    REQUIRE(outcome.delivered.size() == 3);
    for (size_t i = 0; i < sdus.size(); i++)
        CHECK(outcome.delivered[i] == sdus[i]);

    REQUIRE(outcome.trace.size() == 3);
    CHECK(outcome.trace[0].liCount == 2);
    CHECK(outcome.trace[1].liCount == 2);
    CHECK(outcome.trace[1].poll);
    CHECK_FALSE(outcome.trace[2].amd);
    CHECK(outcome.trace[2].ackSn == 1);
}

