//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 19-F-B: the downlink receive contract.
//
// The UE's production receive loop lives inside lte::ue::Run() and needs a
// kernel TUN to reach the user-plane states this file is about, so it is only
// reachable from the four privileged integrations. Rather than add a fifth
// privileged invocation, these cases exercise the same loop shape over a real
// udp::UdpServer and keep every decision in production code:
//
//   * link::Decode decides what a frame is and whether it is well formed;
//   * link::IsDownlink decides the direction;
//   * ip::Validate decides whether the payload is a deliverable IPv4 packet;
//   * MobilityContext::canForwardUserPlane decides whether user plane may run;
//   * DedicatedBearerRuntime::accessReady decides whether a dedicated bearer
//     may carry data.
//
// What this file reproduces is only the turn structure: the first frame of a
// turn may wait, the additional frames may not, and the number of frames one
// turn may take is bounded. That structure is the subject of the measurement in
// docs/lte-downlink-receive-performance.md, and pinning it here is what makes a
// later change to it visible instead of silent.
//
// The IPv4 fixtures carry no header checksum because the UE's ip::Validate does
// not check one: the kernel checks it when the packet enters a TUN. A fixture
// here is evidence about frame acceptance, never about kernel delivery.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <unistd.h>

#include <lib/udp/server.hpp>
#include <lte/enb/runtime_metrics.hpp>
#include <lte/ip_packet.hpp>
#include <lte/ue/bearer_runtime.hpp>
#include <lte/ue/lifecycle.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/runtime_policy.hpp>
#include <lte/ue/types.hpp>

namespace
{

namespace link = lte::ue::link;

constexpr uint32_t UeId = 7;
constexpr uint32_t OtherUeId = 8;
constexpr size_t Mtu = 1400;
constexpr uint8_t DefaultEbi = 5;
constexpr uint8_t DedicatedEbi = 6;
const std::array<uint8_t, 4> UeIpv4{10, 45, 0, 35};

// The bounded number of frames one receive turn may take. It is a constant in
// this file, not a production setting: the audit established that the
// production loop takes one frame per turn, and this bound is the envelope the
// measurement says a batch would have to stay inside.
constexpr int TurnFrameBudget = 8;

// A structurally valid IPv4/UDP datagram of "size" bytes with "marker" in the
// first four payload octets, so a delivered frame can be identified after the
// codec has handed it back.
std::vector<uint8_t> Ipv4Packet(uint32_t marker, size_t size = 200,
                                const std::array<uint8_t, 4> &destination = UeIpv4)
{
    std::vector<uint8_t> packet(size, 0);
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>(size >> 8U);
    packet[3] = static_cast<uint8_t>(size);
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 10;
    packet[13] = 99;
    packet[14] = 0;
    packet[15] = 1;
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    packet[28] = static_cast<uint8_t>(marker >> 24U);
    packet[29] = static_cast<uint8_t>(marker >> 16U);
    packet[30] = static_cast<uint8_t>(marker >> 8U);
    packet[31] = static_cast<uint8_t>(marker);
    return packet;
}

std::vector<uint8_t> DataFrame(uint32_t marker, uint32_t ueId = UeId,
                               const std::array<uint8_t, 4> &destination = UeIpv4)
{
    return link::Encode({link::MessageType::DATA_DOWNLINK, ueId, Ipv4Packet(marker, 200, destination)});
}

std::vector<uint8_t> DedicatedDataFrame(uint8_t ebi, uint32_t marker)
{
    auto payload = Ipv4Packet(marker);
    payload.insert(payload.begin(), ebi);
    return link::Encode({link::MessageType::DATA_DOWNLINK_BEARER, UeId, std::move(payload)});
}

std::vector<uint8_t> NasFrame(const std::vector<uint8_t> &nas)
{
    return link::Encode({link::MessageType::NAS_DOWNLINK, UeId, nas});
}

// One delivered frame, as the UE's receive path would hand it to its bearer.
struct Delivered
{
    link::MessageType type;
    uint8_t ebi;      // 0 for a frame that names no bearer
    uint32_t marker;  // the fixture marker, or the first payload octet
};

struct TurnResult
{
    int attempts{0};
    int frames{0};
    int empty{0};
    int peerRejects{0};
    int identityRejects{0};
    int decodeFailures{0};
    int writeErrors{0};
    int budgetExhausted{0};
    std::vector<Delivered> delivered;
};

// The radio endpoints a UE and its eNB would own, both real sockets.
struct ReceiveLab
{
    udp::UdpServer ue{"127.0.0.1", 0};
    udp::UdpServer enb{"127.0.0.1", 0};

    void send(const std::vector<uint8_t> &frame) const
    {
        enb.Send(ue.LocalAddress(), frame.data(), frame.size());
    }

    void sendFrom(udp::UdpServer &other, const std::vector<uint8_t> &frame) const
    {
        other.Send(ue.LocalAddress(), frame.data(), frame.size());
    }
};

// One receive turn, in the shape of lte::ue::Run(): the first frame may wait for
// the timeout the runtime policy chose, each further frame may not, and the
// turn never takes more than "budget" frames. A frame that fails any check is
// counted and the turn continues, exactly as the production loop does.
TurnResult RunTurn(ReceiveLab &lab, int budget, int firstTimeoutMs, const InetAddress &expectedPeer,
                   uint32_t ueId = UeId, bool sinkAccepts = true, int stopAfter = -1,
                   lte::ue::MobilityContext *mobility = nullptr,
                   const std::vector<lte::ue::DedicatedBearerRuntime> *bearers = nullptr)
{
    TurnResult result;
    uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
    for (int index = 0; index < budget; ++index)
    {
        if (stopAfter >= 0 && result.frames >= stopAfter)
            break;
        const int timeoutMs = index == 0 ? firstTimeoutMs : 0;
        InetAddress peer;
        ++result.attempts;
        const int received = lab.ue.Receive(buffer, sizeof(buffer), timeoutMs, peer);
        if (received <= 0)
        {
            ++result.empty;
            break;
        }
        if (peer != expectedPeer)
        {
            ++result.peerRejects;
            continue;
        }
        try
        {
            auto message = link::Decode(buffer, static_cast<size_t>(received));
            if (!link::IsDownlink(message.type) || message.ueId != ueId)
            {
                ++result.identityRejects;
                continue;
            }

            Delivered delivered{message.type, 0, 0};
            if (message.type == link::MessageType::DATA_DOWNLINK)
            {
                if (mobility != nullptr && !mobility->canForwardUserPlane())
                {
                    ++result.identityRejects;
                    continue;
                }
                const auto ipv4 = lte::ip::Validate(message.payload.data(), message.payload.size(), Mtu);
                if (ipv4.destination != UeIpv4)
                    throw lte::ip::ValidationError("downlink destination does not match the assigned address");
                delivered.marker = (static_cast<uint32_t>(message.payload[28]) << 24U) |
                                   (static_cast<uint32_t>(message.payload[29]) << 16U) |
                                   (static_cast<uint32_t>(message.payload[30]) << 8U) |
                                   static_cast<uint32_t>(message.payload[31]);
            }
            else if (message.type == link::MessageType::DATA_DOWNLINK_BEARER)
            {
                if (message.payload.size() < 2)
                    throw link::DecodeError("malformed bearer-aware downlink frame");
                const uint8_t ebi = message.payload[0];
                if (bearers == nullptr ||
                    std::none_of(bearers->begin(), bearers->end(),
                                 [ebi](const lte::ue::DedicatedBearerRuntime &candidate) {
                                     return candidate.ebi == ebi && candidate.accessReady;
                                 }))
                {
                    ++result.identityRejects;
                    continue;
                }
                const std::vector<uint8_t> packet(message.payload.begin() + 1, message.payload.end());
                const auto ipv4 = lte::ip::Validate(packet.data(), packet.size(), Mtu);
                if (ipv4.destination != UeIpv4)
                    throw lte::ip::ValidationError("downlink destination does not match the assigned address");
                delivered.ebi = ebi;
                delivered.marker = (static_cast<uint32_t>(packet[28]) << 24U) |
                                   (static_cast<uint32_t>(packet[29]) << 16U) |
                                   (static_cast<uint32_t>(packet[30]) << 8U) | static_cast<uint32_t>(packet[31]);
            }
            else
            {
                delivered.marker = message.payload.empty() ? 0 : message.payload[0];
            }

            // The TUN write. A sink that refuses is the production path's own
            // writePacket == false: the frame is not delivered, the error is
            // counted, and the turn goes on to the next frame.
            if (!sinkAccepts)
            {
                ++result.writeErrors;
                continue;
            }
            ++result.frames;
            result.delivered.push_back(delivered);
            if (index + 1 == budget)
                ++result.budgetExhausted;
        }
        catch (const std::exception &)
        {
            ++result.decodeFailures;
            continue;
        }
    }
    return result;
}

lte::ue::DedicatedBearerRuntime DedicatedBearer(uint8_t ebi, bool ready)
{
    lte::ue::DedicatedBearerRuntime bearer;
    bearer.ebi = ebi;
    bearer.accessReady = ready;
    return bearer;
}

size_t OpenDescriptorCount()
{
    return lte::enb::CountOpenFileDescriptors(static_cast<int>(::getpid()));
}

} // namespace

TEST_CASE("lte/downlink/receive: an empty radio socket ends the turn without spinning")
{
    ReceiveLab lab;
    const auto result = RunTurn(lab, TurnFrameBudget, 0, lab.enb.LocalAddress());

    // One attempt, no frame, and the turn returns instead of polling the socket
    // again: an empty socket must never turn a bounded batch into a busy loop.
    CHECK(result.attempts == 1);
    CHECK(result.empty == 1);
    CHECK(result.frames == 0);
    CHECK(result.delivered.empty());
}

TEST_CASE("lte/downlink/receive: one DATA_DOWNLINK frame is accepted")
{
    ReceiveLab lab;
    lab.send(DataFrame(0x11));
    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());

    CHECK(result.frames == 1);
    REQUIRE(result.delivered.size() == 1);
    CHECK(result.delivered[0].type == link::MessageType::DATA_DOWNLINK);
    CHECK(result.delivered[0].marker == 0x11);
    CHECK(result.decodeFailures == 0);
}

TEST_CASE("lte/downlink/receive: a burst keeps arrival order")
{
    ReceiveLab lab;
    for (uint32_t marker = 1; marker <= 5; ++marker)
        lab.send(DataFrame(marker));
    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());

    REQUIRE(result.frames == 5);
    for (uint32_t index = 0; index < 5; ++index)
        CHECK(result.delivered[index].marker == index + 1);
}

TEST_CASE("lte/downlink/receive: the turn budget bounds a burst and leaves the rest queued")
{
    ReceiveLab lab;
    for (uint32_t marker = 1; marker <= 20; ++marker)
        lab.send(DataFrame(marker));

    const auto first = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    CHECK(first.frames == TurnFrameBudget);
    CHECK(first.budgetExhausted == 1);

    const auto second = RunTurn(lab, TurnFrameBudget, 0, lab.enb.LocalAddress());
    CHECK(second.frames == TurnFrameBudget);

    const auto third = RunTurn(lab, TurnFrameBudget, 0, lab.enb.LocalAddress());
    CHECK(third.frames == 4);

    // The 8 + 8 + 4 split is the whole burst: no frame was lost by batching and
    // none was delivered twice.
    std::vector<uint32_t> markers;
    for (const auto *turn : {&first, &second, &third})
        for (const auto &frame : turn->delivered)
            markers.push_back(frame.marker);
    REQUIRE(markers.size() == 20);
    for (uint32_t index = 0; index < 20; ++index)
        CHECK(markers[index] == index + 1);
}

TEST_CASE("lte/downlink/receive: NAS and data frames keep their arrival order in one burst")
{
    ReceiveLab lab;
    lab.send(NasFrame({0x07, 0x42, 0x01, 0x02}));
    lab.send(DataFrame(0x21));
    lab.send(DataFrame(0x22));
    lab.send(NasFrame({0x07, 0x43, 0x03}));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    REQUIRE(result.frames == 4);
    CHECK(result.delivered[0].type == link::MessageType::NAS_DOWNLINK);
    CHECK(result.delivered[1].type == link::MessageType::DATA_DOWNLINK);
    CHECK(result.delivered[1].marker == 0x21);
    CHECK(result.delivered[2].marker == 0x22);
    CHECK(result.delivered[3].type == link::MessageType::NAS_DOWNLINK);
}

TEST_CASE("lte/downlink/receive: a malformed frame is rejected without ending the burst")
{
    ReceiveLab lab;
    auto broken = DataFrame(0x31);
    broken[1] = 0xFF; // unknown message type: refused at decode
    lab.send(broken);
    lab.send(DataFrame(0x32));
    lab.send(DataFrame(0x33));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    CHECK(result.decodeFailures == 1);
    REQUIRE(result.frames == 2);
    CHECK(result.delivered[0].marker == 0x32);
    CHECK(result.delivered[1].marker == 0x33);
}

TEST_CASE("lte/downlink/receive: an unexpected peer, a wrong UE and an uplink frame are all refused")
{
    ReceiveLab lab;
    udp::UdpServer stranger("127.0.0.1", 0);
    lab.sendFrom(stranger, DataFrame(0x41));
    lab.send(DataFrame(0x42, OtherUeId));
    lab.send(link::Encode({link::MessageType::DATA_UPLINK, UeId, Ipv4Packet(0x43)}));
    lab.send(DataFrame(0x44));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    CHECK(result.peerRejects == 1);
    CHECK(result.identityRejects == 2);
    REQUIRE(result.frames == 1);
    CHECK(result.delivered[0].marker == 0x44);
}

TEST_CASE("lte/downlink/receive: a downlink destination that is not the UE address is refused")
{
    ReceiveLab lab;
    lab.send(DataFrame(0x51, UeId, {10, 45, 0, 99}));
    lab.send(DataFrame(0x52));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    CHECK(result.decodeFailures == 1);
    REQUIRE(result.frames == 1);
    CHECK(result.delivered[0].marker == 0x52);
}

TEST_CASE("lte/downlink/receive: a refused TUN write counts an error and does not deliver")
{
    ReceiveLab lab;
    lab.send(DataFrame(0x61));
    lab.send(DataFrame(0x62));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, false);
    CHECK(result.frames == 0);
    CHECK(result.writeErrors == 2);
    CHECK(result.delivered.empty());
}

TEST_CASE("lte/downlink/receive: a busy cycle stops at the shutdown the caller set")
{
    ReceiveLab lab;
    for (uint32_t marker = 1; marker <= 10; ++marker)
        lab.send(DataFrame(marker));

    // A shutdown observed mid-cycle is honoured before the budget is spent, so
    // a batch can never delay the shutdown path.
    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, true, 3);
    CHECK(result.frames == 3);
    CHECK(result.attempts == 3);
}

TEST_CASE("lte/downlink/receive: released access refuses user plane but keeps signalling")
{
    lte::ue::MobilityContext mobility;
    mobility.emm = lte::ue::EmmState::REGISTERED;
    mobility.ecm = lte::ue::EcmState::CONNECTED;
    mobility.bearer = lte::ue::EpsBearerState::USER_PLANE_READY;
    mobility.defaultEbi = DefaultEbi;
    mobility.accessGeneration = 0;
    REQUIRE(mobility.canForwardUserPlane());

    // The network's own access release: the EPS registration and the logical
    // bearer survive it, the user plane does not.
    mobility.acceptAccessRelease(DefaultEbi, 1);
    CHECK_FALSE(mobility.canForwardUserPlane());

    ReceiveLab lab;
    lab.send(DataFrame(0x71));
    lab.send(NasFrame({0x07, 0x42, 0x09}));

    // The user-plane frame is refused by the production predicate; the NAS
    // frame behind it is still decoded and delivered, which is what a release
    // followed by new signalling looks like on one socket.
    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, true, -1, &mobility);
    CHECK(result.identityRejects == 1);
    REQUIRE(result.frames == 1);
    CHECK(result.delivered[0].type == link::MessageType::NAS_DOWNLINK);
}

TEST_CASE("lte/downlink/receive: a released dedicated bearer no longer carries its traffic")
{
    std::vector<lte::ue::DedicatedBearerRuntime> bearers{DedicatedBearer(DedicatedEbi, true)};

    ReceiveLab lab;
    lab.send(DedicatedDataFrame(DedicatedEbi, 0x81));

    auto accepted = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, true, -1, nullptr, &bearers);
    REQUIRE(accepted.frames == 1);
    CHECK(accepted.delivered[0].ebi == DedicatedEbi);
    CHECK(accepted.delivered[0].marker == 0x81);

    // The release the UE performs on BEARER_RELEASED is the removal of the
    // entry; the frame that names it afterwards is refused rather than falling
    // back to the default bearer.
    bearers.clear();
    lab.send(DedicatedDataFrame(DedicatedEbi, 0x82));
    lab.send(DataFrame(0x83));
    auto refused = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, true, -1, nullptr, &bearers);
    CHECK(refused.identityRejects == 1);
    REQUIRE(refused.frames == 1);
    CHECK(refused.delivered[0].type == link::MessageType::DATA_DOWNLINK);
    CHECK(refused.delivered[0].marker == 0x83);

    // A dedicated bearer that is not access-ready is equally refused.
    bearers.push_back(DedicatedBearer(DedicatedEbi, false));
    lab.send(DedicatedDataFrame(DedicatedEbi, 0x84));
    auto inactive = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress(), UeId, true, -1, nullptr, &bearers);
    CHECK(inactive.identityRejects == 1);
    CHECK(inactive.frames == 0);
}

TEST_CASE("lte/downlink/receive: a paging indication inside a data burst is decoded in place")
{
    ReceiveLab lab;
    lab.send(DataFrame(0x91));
    lab.send(link::Encode({link::MessageType::PAGING_INDICATION, UeId,
                           {0x01, 0xC0, 0x00, 0x04, 0x34, 0x00, 0x01}}));
    lab.send(DataFrame(0x92));

    const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
    REQUIRE(result.frames == 3);
    CHECK(result.delivered[0].type == link::MessageType::DATA_DOWNLINK);
    CHECK(result.delivered[1].type == link::MessageType::PAGING_INDICATION);
    CHECK(result.delivered[2].type == link::MessageType::DATA_DOWNLINK);
    CHECK(result.delivered[2].marker == 0x92);
}

TEST_CASE("lte/downlink/receive: a turn with no downlink traffic costs one non-blocking poll")
{
    // The production policy for a turn whose TUN produced uplink: check the
    // radio socket without blocking. An empty socket must then return at once,
    // which is what keeps an uplink-only workload from acquiring a downlink
    // wait it does not need.
    CHECK(lte::ue::RadioReceiveTimeoutMs(true, true) == 0);
    ReceiveLab lab;
    const auto result = RunTurn(lab, TurnFrameBudget, lte::ue::RadioReceiveTimeoutMs(true, true),
                                lab.enb.LocalAddress());
    CHECK(result.attempts == 1);
    CHECK(result.frames == 0);
}

TEST_CASE("lte/downlink/receive: the receive endpoints release their sockets")
{
    const size_t before = OpenDescriptorCount();
    {
        ReceiveLab lab;
        lab.send(DataFrame(0xA1));
        const auto result = RunTurn(lab, TurnFrameBudget, 1000, lab.enb.LocalAddress());
        CHECK(result.frames == 1);
    }
    CHECK(OpenDescriptorCount() == before);
}