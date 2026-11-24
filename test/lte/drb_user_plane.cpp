//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D6: the DRB user plane.
//
// The cases below drive the production classes on real loopback UDP sockets:
//
//   DRB SDU -> PDCP (DRB12, EEA2) -> RLC AM -> Uu (DTCH) -> RLC AM -> PDCP -> SDU
//
// and, for the eNB, the same DRB is wired into the production S1uEndpoint so an
// uplink SDU leaves as a real GTP-U G-PDU and a downlink G-PDU arrives back
// through the DRB. Nothing here calls the opposite endpoint's objects directly
// and nothing fabricates a GTP-U or PDCP result: every datagram crosses a
// socket.
#include <ext/doctest/doctest.h>

#include <lte/enb/gtpu.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ip_packet.hpp>
#include <lte/rrc-runtime/drb_runtime.hpp>
#include <lte/rrc-runtime/rrc_drb_config.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace
{

using lte::rrc::DrbBearerConfig;
using lte::rrc::DrbReady;
using lte::rrc::DrbRuntime;
using lte::rlc::am::EndpointRole;
namespace uu = lte::uu;

std::vector<uint8_t> Ipv4(std::array<uint8_t, 4> source, std::array<uint8_t, 4> destination, size_t extra = 0,
                          uint8_t tag = 0)
{
    std::vector<uint8_t> packet(20 + extra, 0);
    const size_t total = packet.size();
    packet[0] = 0x45;
    packet[2] = static_cast<uint8_t>((total >> 8U) & 0xFFU);
    packet[3] = static_cast<uint8_t>(total & 0xFFU);
    packet[8] = 64;
    packet[9] = 17;
    std::copy(source.begin(), source.end(), packet.begin() + 12);
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    if (extra > 0)
        packet[20] = tag;
    return packet;
}

lte::security::Key128 Key(uint8_t seed)
{
    lte::security::Key128 key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(seed + i);
    return key;
}

lte::rlc::am::AmConfig AmConfig()
{
    lte::rlc::am::AmConfig am;
    am.maxPduBytes = 1700;
    am.pollTicks = 5;
    am.reorderingTicks = 5;
    am.prohibitTicks = 1;
    am.pollPdu = 0;
    am.pollByte = 0;
    am.maxRetx = 9;
    return am;
}

DrbBearerConfig BearerConfig(uint8_t ebi, uint8_t seed, uint8_t algorithm = 2)
{
    DrbBearerConfig config;
    config.ebi = ebi;
    config.drbIdentity = ebi;
    config.am = AmConfig();
    config.cipheringAlgorithm = algorithm;  // 2 is EEA2; 0 is the named null profile
    config.kUpEnc = algorithm == 0 ? lte::security::Key128{} : Key(seed);
    return config;
}

// Two production DrbRuntime endpoints on two real Uu sockets. The Uu envelope
// carries association, direction and the DTCH logical channel; the DRB routing
// header selects the bearer.
struct DrbPair
{
    uu::Socket ueSocket;
    uu::Socket enbSocket;
    uint16_t uePort{0};
    uint16_t enbPort{0};
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> uplinkAtEnb;
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> downlinkAtUe;
    std::optional<DrbReady> readyAtEnb;
    std::unique_ptr<DrbRuntime> ue;
    std::unique_ptr<DrbRuntime> enb;

    static constexpr uint32_t Association = 47001;

    DrbPair()
    {
        std::string why;
        auto ueBound = uu::Socket::BindLoopback(0, &why);
        REQUIRE_MESSAGE(ueBound.has_value(), why);
        ueSocket = std::move(*ueBound);
        auto enbBound = uu::Socket::BindLoopback(0, &why);
        REQUIRE_MESSAGE(enbBound.has_value(), why);
        enbSocket = std::move(*enbBound);
        uePort = ueSocket.Port();
        enbPort = enbSocket.Port();

        ue = std::make_unique<DrbRuntime>(
            EndpointRole::UE, Association,
            [this](const std::vector<uint8_t> &payload) {
                uu::Frame frame;
                frame.association = Association;
                frame.direction = uu::Direction::UPLINK;
                frame.channel = uu::LogicalChannel::DTCH;
                frame.payload = payload;
                return ueSocket.Send(enbPort, frame, nullptr);
            },
            [this](uint8_t ebi, const std::vector<uint8_t> &packet) { downlinkAtUe.emplace_back(ebi, packet); });
        enb = std::make_unique<DrbRuntime>(
            EndpointRole::ENB, Association,
            [this](const std::vector<uint8_t> &payload) {
                uu::Frame frame;
                frame.association = Association;
                frame.direction = uu::Direction::DOWNLINK;
                frame.channel = uu::LogicalChannel::DTCH;
                frame.payload = payload;
                return enbSocket.Send(uePort, frame, nullptr);
            },
            [this](uint8_t ebi, const std::vector<uint8_t> &packet) { uplinkAtEnb.emplace_back(ebi, packet); });
        enb->SetReadyHandler([this](const DrbReady &ready) {
            readyAtEnb = ready;
            return true;
        });
    }

    void AddBearer(uint8_t ebi, uint8_t seed = 0x40, uint8_t algorithm = 2)
    {
        REQUIRE(ue->AddBearer(BearerConfig(ebi, seed, algorithm)));
        REQUIRE(enb->AddBearer(BearerConfig(ebi, seed, algorithm)));
    }

    void Settle(int rounds = 8)
    {
        for (int round = 0; round < rounds; ++round)
        {
            for (int budget = 0; budget < 32; ++budget)
            {
                uu::Frame frame;
                if (!ueSocket.Receive(frame, 2, nullptr))
                    break;
                ue->OnFrame(frame);
            }
            for (int budget = 0; budget < 32; ++budget)
            {
                uu::Frame frame;
                if (!enbSocket.Receive(frame, 2, nullptr))
                    break;
                enb->OnFrame(frame);
            }
            ue->Tick();
            enb->Tick();
        }
    }
};

} // namespace

TEST_CASE("lte/drb/pdcp: EEA0 is a named null protection that still carries the DRB12 header")
{
    DrbPair pair;
    pair.AddBearer(5, 0x00, 0);  // EEA0 and no key

    const auto packet = Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}, 8, 0xE0);
    REQUIRE(pair.ue->SubmitIp(5, packet.data(), packet.size()));
    pair.Settle();
    REQUIRE(pair.uplinkAtEnb.size() == 1);
    // The data field is in the clear because EEA0 protects nothing; that is a
    // real selection, not a missing cipher.
    CHECK(pair.uplinkAtEnb[0].second == packet);

    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 8, 0xE1);
    REQUIRE(pair.enb->SubmitIp(5, downlink.data(), downlink.size()));
    pair.Settle();
    REQUIRE(pair.downlinkAtUe.size() == 1);
    CHECK(pair.downlinkAtUe[0].second == downlink);
}

TEST_CASE("lte/drb/config: the RRC DRB configuration round trips and refuses unsupported shapes")
{
    lte::rrc::DrbReconfiguration message;
    message.transactionId = 2;
    for (const uint8_t ebi : {5, 6})
    {
        lte::rrc::DrbToAdd drb;
        drb.ebi = ebi;
        drb.drbIdentity = ebi;
        drb.logicalChannelIdentity = static_cast<uint8_t>(3 + (ebi - 5));
        drb.priority = static_cast<uint8_t>(1 + (ebi - 5));
        drb.am = lte::rrc::MapAmRlcConfiguration(2, 7, 14, 5, 1, 1);
        message.drbs.push_back(drb);
    }

    const auto encoded = lte::rrc::EncodeDrbReconfiguration(message);
    REQUIRE_FALSE(encoded.empty());
    lte::rrc::DrbReconfiguration decoded;
    REQUIRE(lte::rrc::DecodeDrbReconfiguration(encoded.data(), encoded.size(), decoded));
    CHECK(decoded.transactionId == 2);
    REQUIRE(decoded.drbs.size() == 2);
    CHECK(decoded.drbs[0].ebi == 5);
    CHECK(decoded.drbs[0].drbIdentity == 5);
    CHECK(decoded.drbs[0].logicalChannelIdentity == 3);
    CHECK(decoded.drbs[0].priority == 1);
    CHECK(decoded.drbs[0].am.maxPduBytes == 128);  // the mapper's production default
    CHECK(decoded.drbs[1].ebi == 6);
    CHECK(decoded.drbs[1].logicalChannelIdentity == 4);

    // A truncated or foreign message is refused, never guessed at.
    CHECK_FALSE(lte::rrc::DecodeDrbReconfiguration(encoded.data(), encoded.size() - 1, decoded));
    const std::vector<uint8_t> garbage(16, 0xAB);
    CHECK_FALSE(lte::rrc::DecodeDrbReconfiguration(garbage.data(), garbage.size(), decoded));

    // Encoding refuses a shape the standard cannot express.
    auto invalid = message;
    invalid.transactionId = 4;
    CHECK(lte::rrc::EncodeDrbReconfiguration(invalid).empty());
    invalid = message;
    invalid.drbs[1].ebi = 5;
    CHECK(lte::rrc::EncodeDrbReconfiguration(invalid).empty());
    invalid = message;
    invalid.drbs[0].ebi = 4;
    CHECK(lte::rrc::EncodeDrbReconfiguration(invalid).empty());
    invalid = message;
    invalid.drbs[0].logicalChannelIdentity = 12;
    CHECK(lte::rrc::EncodeDrbReconfiguration(invalid).empty());

    const auto complete = lte::rrc::EncodeDrbReconfigurationComplete(2);
    REQUIRE_FALSE(complete.empty());
    uint8_t transaction = 9;
    REQUIRE(lte::rrc::DecodeDrbReconfigurationComplete(complete.data(), complete.size(), transaction));
    CHECK(transaction == 2);
    CHECK(lte::rrc::EncodeDrbReconfigurationComplete(4).empty());
}

TEST_CASE("lte/drb/data-plane: IP packets cross PDCP and RLC AM over real Uu sockets in both directions")
{
    DrbPair pair;
    pair.AddBearer(5);
    pair.AddBearer(6, 0x60);

    // The UE confirms the DRB set and restates its PDN address.
    DrbReady ready;
    ready.ebi = 5;
    ready.generation = 0;
    ready.ipv4 = {10, 45, 0, 2};
    REQUIRE(pair.ue->SendReady(ready));
    pair.Settle();
    REQUIRE(pair.readyAtEnb.has_value());
    CHECK(pair.readyAtEnb->ebi == 5);
    CHECK(pair.readyAtEnb->generation == 0);
    CHECK(pair.readyAtEnb->ipv4 == std::array<uint8_t, 4>{10, 45, 0, 2});

    const auto uplink5 = Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}, 8, 0x11);
    REQUIRE(pair.ue->SubmitIp(5, uplink5.data(), uplink5.size()));
    pair.Settle();
    REQUIRE(pair.uplinkAtEnb.size() == 1);
    CHECK(pair.uplinkAtEnb[0].first == 5);
    CHECK(pair.uplinkAtEnb[0].second == uplink5);

    const auto uplink6 = Ipv4({10, 45, 0, 2}, {10, 45, 0, 3}, 4, 0x22);
    REQUIRE(pair.ue->SubmitIp(6, uplink6.data(), uplink6.size()));
    pair.Settle();
    REQUIRE(pair.uplinkAtEnb.size() == 2);
    CHECK(pair.uplinkAtEnb[1].first == 6);
    CHECK(pair.uplinkAtEnb[1].second == uplink6);
    CHECK(pair.uplinkAtEnb[1].second != pair.uplinkAtEnb[0].second);

    const auto downlink5 = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 12, 0x33);
    REQUIRE(pair.enb->SubmitIp(5, downlink5.data(), downlink5.size()));
    pair.Settle();
    REQUIRE(pair.downlinkAtUe.size() == 1);
    CHECK(pair.downlinkAtUe[0].first == 5);
    CHECK(pair.downlinkAtUe[0].second == downlink5);

    const auto downlink6 = Ipv4({10, 45, 0, 3}, {10, 45, 0, 2}, 6, 0x44);
    REQUIRE(pair.enb->SubmitIp(6, downlink6.data(), downlink6.size()));
    pair.Settle();
    REQUIRE(pair.downlinkAtUe.size() == 2);
    CHECK(pair.downlinkAtUe[1].first == 6);
    CHECK(pair.downlinkAtUe[1].second == downlink6);

    const auto &ueCounters = pair.ue->Counters();
    CHECK(ueCounters.uplinkPackets == 2);
    CHECK(ueCounters.downlinkPackets == 2);
    CHECK(ueCounters.uplinkBytes == uplink5.size() + uplink6.size());
    CHECK(ueCounters.downlinkBytes == downlink5.size() + downlink6.size());
    CHECK(pair.enb->Counters().uplinkPackets == 2);
    CHECK(pair.enb->Counters().downlinkPackets == 2);

    // An unknown DRB identity never falls back to another bearer.
    uu::Frame stray;
    stray.association = DrbPair::Association;
    stray.direction = uu::Direction::UPLINK;
    stray.channel = uu::LogicalChannel::DTCH;
    stray.payload = {lte::rrc::DrbKindData, 9, 0x80, 0x00};
    REQUIRE_FALSE(pair.enb->OnFrame(stray));
    CHECK(pair.enb->Counters().unknownBearerDrops == 1);
    CHECK(pair.uplinkAtEnb.size() == 2);

    // A frame in the wrong direction is refused before any bearer is selected.
    CHECK_FALSE(pair.enb->OnFrame([] {
        uu::Frame frame;
        frame.association = DrbPair::Association;
        frame.direction = uu::Direction::DOWNLINK;
        frame.channel = uu::LogicalChannel::DTCH;
        frame.payload = {lte::rrc::DrbKindData, 5, 0x80, 0x00};
        return frame;
    }()));

    // An oversized SDU is refused and counted, never truncated.
    std::vector<uint8_t> oversized(lte::rrc::MaxDrbSduBytes + 1, 0x55);
    oversized[0] = 0x45;
    REQUIRE_FALSE(pair.ue->SubmitIp(5, oversized.data(), oversized.size()));
    CHECK(pair.ue->Bearer(5)->Counters().oversizedDrops == 1);

    // A second setup of the same EBI does not duplicate the bearer.
    CHECK_FALSE(pair.ue->AddBearer(BearerConfig(5, 0x40)));
    CHECK(pair.ue->Counters().duplicateSetups == 1);
    CHECK(pair.ue->BearerCount() == 2);
}

namespace
{

// The eNB side of the S1-U acceptance: one registry entry with a default
// bearer, the production S1uEndpoint, and a fake SGW-U on 127.0.0.9:2152 that
// receives and sends real GTP-U datagrams.
struct S1uLab
{
    static constexpr uint32_t UeId = 47101;
    static constexpr uint8_t Ebi = 5;

    udp::UdpServer ueLink{"127.0.0.1", 0};
    udp::UdpServer sgw{"127.0.0.9", 2152};
    lte::enb::UeRegistry registry{4};
    lte::enb::S1uEndpoint s1u{"127.0.0.1", 0, true, registry, ueLink};
    uu::Socket ueSocket;
    uu::Socket enbSocket;
    uint16_t uePort{0};
    uint16_t enbPort{0};
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> downlinkAtUe;
    std::optional<DrbReady> readyAtEnb;
    std::unique_ptr<DrbRuntime> ue;
    std::unique_ptr<DrbRuntime> enb;
    lte::enb::EnbUeEntry *entry{nullptr};
    uint32_t localTeid{0};
    static constexpr uint32_t SgwTeid = 0x51525354;

    S1uLab()
    {
        std::string why;
        auto ueBound = uu::Socket::BindLoopback(0, &why);
        REQUIRE_MESSAGE(ueBound.has_value(), why);
        ueSocket = std::move(*ueBound);
        auto enbBound = uu::Socket::BindLoopback(0, &why);
        REQUIRE_MESSAGE(enbBound.has_value(), why);
        enbSocket = std::move(*enbBound);
        uePort = ueSocket.Port();
        enbPort = enbSocket.Port();

        entry = &registry.registerPeer(UeId, InetAddress("127.0.0.1", uePort));
        entry->transport = lte::enb::RadioTransportKind::UuSrb1;
        localTeid = registry.allocateLocalTeid();
        entry->bearer.establish({Ebi, 9, UeId, {127, 0, 0, 9}, SgwTeid, localTeid});
        entry->bearer.activateUe(UeId, Ebi, {10, 45, 0, 2});
        registry.bindLocalTeid(*entry, entry->bearer, localTeid);
        entry->s1 = lte::enb::UeS1State::BEARER_ACTIVE;

        BuildDrbs(0x40);
    }

    void BuildDrbs(uint8_t seed)
    {
        ue = std::make_unique<DrbRuntime>(
            EndpointRole::UE, UeId,
            [this](const std::vector<uint8_t> &payload) {
                uu::Frame frame;
                frame.association = UeId;
                frame.direction = uu::Direction::UPLINK;
                frame.channel = uu::LogicalChannel::DTCH;
                frame.payload = payload;
                return ueSocket.Send(enbPort, frame, nullptr);
            },
            [this](uint8_t ebi, const std::vector<uint8_t> &packet) { downlinkAtUe.emplace_back(ebi, packet); });
        enb = std::make_unique<DrbRuntime>(
            EndpointRole::ENB, UeId,
            [this](const std::vector<uint8_t> &payload) {
                uu::Frame frame;
                frame.association = UeId;
                frame.direction = uu::Direction::DOWNLINK;
                frame.channel = uu::LogicalChannel::DTCH;
                frame.payload = payload;
                return enbSocket.Send(uePort, frame, nullptr);
            },
            [this](uint8_t ebi, const std::vector<uint8_t> &packet) {
                auto *entry2 = registry.find(UeId);
                auto *bearer = registry.findBearer(*entry2, ebi);
                try
                {
                    s1u.forwardUplink(*entry2, *bearer, packet.data(), packet.size());
                }
                catch (const std::exception &)
                {
                    // Counted by the S1-U endpoint and the bearer, never retried.
                }
            });
        enb->SetReadyHandler([this](const DrbReady &ready) {
            readyAtEnb = ready;
            return true;
        });
        REQUIRE(ue->AddBearer(BearerConfig(Ebi, seed)));
        REQUIRE(enb->AddBearer(BearerConfig(Ebi, seed)));

        s1u.SetUuDownlinkHandler(
            [this](lte::enb::EnbUeEntry &downEntry, lte::enb::BearerContext &bearer, const uint8_t *packet,
                   size_t size) {
                if (downEntry.radioUeId != UeId || enb == nullptr)
                    return false;
                return enb->SubmitIp(bearer.parameters().erabId, packet, size);
            });
    }

    void Settle(int rounds = 8)
    {
        for (int round = 0; round < rounds; ++round)
        {
            for (int budget = 0; budget < 32; ++budget)
            {
                uu::Frame frame;
                if (!ueSocket.Receive(frame, 2, nullptr))
                    break;
                ue->OnFrame(frame);
            }
            for (int budget = 0; budget < 32; ++budget)
            {
                uu::Frame frame;
                if (!enbSocket.Receive(frame, 2, nullptr))
                    break;
                enb->OnFrame(frame);
            }
            ue->Tick();
            enb->Tick();
        }
    }

    bool ReceiveGpdu(std::vector<uint8_t> &payload, uint32_t &teid)
    {
        std::array<uint8_t, 2048> buffer{};
        InetAddress peer;
        const int length = sgw.Receive(buffer.data(), buffer.size(), 20, peer);
        if (length <= 0)
            return false;
        try
        {
            const auto packet = lte::enb::gtpu::Decode(buffer.data(), static_cast<size_t>(length));
            if (packet.messageType != lte::enb::gtpu::TPdu)
                return false;
            teid = packet.teid;
            payload = packet.payload;
            return true;
        }
        catch (const std::exception &)
        {
            return false;
        }
    }

    bool SendDownlink(uint32_t teid, const std::vector<uint8_t> &payload)
    {
        const auto wire = lte::enb::gtpu::EncodeTPdu(teid, payload.data(), payload.size());
        return sgw.TrySend(s1u.localAddress(), wire.data(), wire.size());
    }
};

} // namespace

TEST_CASE("lte/drb/s1u: real GTP-U datagrams cross the production S1-U endpoint through the DRB")
{
    S1uLab lab;

    // Uplink: a UE DRB packet becomes a G-PDU with the bearer's SGW TEID.
    const auto uplink = Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}, 16, 0x5A);
    REQUIRE(lab.ue->SubmitIp(S1uLab::Ebi, uplink.data(), uplink.size()));
    lab.Settle();

    std::vector<uint8_t> received;
    uint32_t teid = 0;
    REQUIRE(lab.ReceiveGpdu(received, teid));
    CHECK(teid == S1uLab::SgwTeid);
    CHECK(received == uplink);
    CHECK(lab.entry->counters.s1uUplinkPackets == 1);
    CHECK(lab.entry->counters.s1uUplinkBytes == uplink.size());
    CHECK(lab.entry->bearer.counters().uplinkPackets == 1);

    // Downlink: a G-PDU naming the local TEID reaches the UE DRB and its SDU is
    // exactly the IP packet that was sent.
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 24, 0x6B);
    REQUIRE(lab.SendDownlink(lab.localTeid, downlink));
    REQUIRE(lab.s1u.poll(4));
    lab.Settle();
    REQUIRE(lab.downlinkAtUe.size() == 1);
    CHECK(lab.downlinkAtUe[0].first == S1uLab::Ebi);
    CHECK(lab.downlinkAtUe[0].second == downlink);
    CHECK(lab.entry->counters.s1uDownlinkPackets == 1);
    CHECK(lab.entry->counters.simulatedDownlinkPackets == 1);
    CHECK(lab.entry->bearer.counters().downlinkPackets == 1);

    // The wrong TEID reaches no UE and is classified, not counted as payload.
    const auto before = lab.downlinkAtUe.size();
    REQUIRE(lab.SendDownlink(lab.localTeid ^ 0xFFFFU, downlink));
    (void)lab.s1u.poll(4);
    lab.Settle(2);
    CHECK(lab.downlinkAtUe.size() == before);
    CHECK(lab.s1u.counters().unknownTeidDrops == 1);

    // The wrong UE address in an uplink is refused by the bearer, never sent.
    const auto wrongSource = Ipv4({10, 45, 0, 99}, {10, 45, 0, 1}, 4, 0x7C);
    // The DRB itself is transport-agnostic; the S1-U endpoint refuses the source.
    (void)lab.ue->SubmitIp(S1uLab::Ebi, wrongSource.data(), wrongSource.size());
    lab.Settle();
    CHECK(lab.entry->counters.malformedDrops == 1);
    std::vector<uint8_t> unexpected;
    uint32_t unexpectedTeid = 0;
    // The only G-PDU that may have crossed is the first uplink; a second one
    // would mean the invalid source was forwarded.
    CHECK_FALSE(lab.ReceiveGpdu(unexpected, unexpectedTeid));
}

TEST_CASE("lte/drb/ecm-idle: a released DRB and its old TEID carry no traffic and a restored access resumes")
{
    S1uLab lab;

    const auto firstUplink = Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}, 8, 0x01);
    REQUIRE(lab.ue->SubmitIp(S1uLab::Ebi, firstUplink.data(), firstUplink.size()));
    lab.Settle();
    std::vector<uint8_t> received;
    uint32_t teid = 0;
    REQUIRE(lab.ReceiveGpdu(received, teid));
    CHECK(received == firstUplink);

    const auto firstDownlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 8, 0x02);
    REQUIRE(lab.SendDownlink(lab.localTeid, firstDownlink));
    REQUIRE(lab.s1u.poll(4));
    lab.Settle();
    REQUIRE(lab.downlinkAtUe.size() == 1);
    const uint32_t oldLocalTeid = lab.localTeid;
    const uint32_t oldSgwTeid = S1uLab::SgwTeid;

    // ECM-IDLE: the access is released. The EPS bearer context is retained, the
    // DRB, PDCP and RLC entities of the access are gone, and the old local TEID
    // becomes retired.
    lab.ue.reset();
    lab.enb.reset();
    // The production ECM-IDLE transition: it retires the access TEID, drops the
    // bearer transport and advances the access generation, while the logical
    // EPS bearer context is retained.
    lab.registry.releaseS1(*lab.entry);
    REQUIRE(lab.entry->accessGeneration == 1);
    REQUIRE(lab.entry->s1 == lte::enb::UeS1State::IDLE_RETAINED);

    // A G-PDU that names the released TEID is classified as retired traffic and
    // reaches no UE.
    const auto lateDownlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 8, 0x03);
    REQUIRE(lab.SendDownlink(oldLocalTeid, lateDownlink));
    (void)lab.s1u.poll(4);
    CHECK(lab.downlinkAtUe.size() == 1);
    CHECK(lab.s1u.counters().retiredTeidDrops == 1);

    // Service Request restoration: a fresh local TEID, a fresh SGW TEID and a
    // fresh key. The same EPS bearer identity is restored on the new access.
    const uint32_t newLocalTeid = lab.registry.allocateLocalTeid();
    REQUIRE(newLocalTeid != oldLocalTeid);
    const uint32_t newSgwTeid = 0x61626364;
    REQUIRE(newSgwTeid != oldSgwTeid);
    lab.entry->bearer.establish({S1uLab::Ebi, 9, S1uLab::UeId, {127, 0, 0, 9}, newSgwTeid, newLocalTeid}, true);
    lab.entry->bearer.activateUe(S1uLab::UeId, S1uLab::Ebi, {10, 45, 0, 2});
    lab.registry.bindLocalTeid(*lab.entry, lab.entry->bearer, newLocalTeid);
    lab.entry->s1 = lte::enb::UeS1State::BEARER_ACTIVE;
    lab.localTeid = newLocalTeid;
    lab.downlinkAtUe.clear();
    lab.BuildDrbs(0x90);

    DrbReady ready;
    ready.ebi = S1uLab::Ebi;
    ready.generation = 1;
    ready.ipv4 = {10, 45, 0, 2};
    REQUIRE(lab.ue->SendReady(ready));
    lab.Settle();
    REQUIRE(lab.readyAtEnb.has_value());
    CHECK(lab.readyAtEnb->generation == 1);

    const auto restoredUplink = Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}, 32, 0x04);
    REQUIRE(lab.ue->SubmitIp(S1uLab::Ebi, restoredUplink.data(), restoredUplink.size()));
    lab.Settle();
    REQUIRE(lab.ReceiveGpdu(received, teid));
    CHECK(teid == newSgwTeid);
    CHECK(received == restoredUplink);

    const auto restoredDownlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}, 32, 0x05);
    REQUIRE(lab.SendDownlink(newLocalTeid, restoredDownlink));
    REQUIRE(lab.s1u.poll(4));
    lab.Settle();
    REQUIRE(lab.downlinkAtUe.size() == 1);
    CHECK(lab.downlinkAtUe[0].second == restoredDownlink);

    // The old TEID still carries nothing after the restoration.
    REQUIRE(lab.SendDownlink(oldLocalTeid, lateDownlink));
    (void)lab.s1u.poll(4);
    CHECK(lab.downlinkAtUe.size() == 1);
    CHECK(lab.s1u.counters().retiredTeidDrops == 2);
}
