//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/radio_link.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <set>
#include <vector>

namespace
{

using namespace lte::enb;

struct CapturedS1ap
{
    uint16_t stream{};
    std::vector<uint8_t> pdu;
};

class CaptureSender final : public IS1apSender
{
  public:
    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(CapturedS1ap{stream, pdu});
    }

    [[nodiscard]] size_t count(uint8_t procedureCode) const
    {
        size_t total = 0;
        for (const auto &item : sent)
        {
            auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
            if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == procedureCode)
                ++total;
        }
        return total;
    }

    std::vector<CapturedS1ap> sent;
};

EnbConfig TestEnbConfig()
{
    EnbConfig config{};
    config.plmn = {"460", "02"};
    config.enbId = 0x19B;
    config.tac = 1;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.2";
    config.mmePort = 36412;
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0; // ephemeral keeps concurrent test cases isolated
    config.s1uAddress = "127.0.0.1";
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

struct FakeUe
{
    explicit FakeUe(uint32_t id) : ueId(id)
    {
    }
    udp::UdpServer radio{"127.0.0.1", 0};
    uint32_t ueId;
};

struct FakeSgw
{
    udp::UdpServer socket;
    explicit FakeSgw(const std::string &address) : socket(address, 2152)
    {
    }
};

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, lte::ue::link::MessageType type, std::vector<uint8_t> payload)
{
    auto frame = lte::ue::link::Encode({type, ue.ueId, std::move(payload)});
    mux.handleRadioFrame(frame.data(), frame.size(), ue.radio.LocalAddress());
}

std::optional<lte::ue::link::Message> ReceiveRadio(udp::UdpServer &socket, int timeoutMs)
{
    uint8_t buffer[lte::ue::link::MaxDataPduSize + lte::ue::link::HeaderSize];
    InetAddress peer;
    const int received = socket.Receive(buffer, sizeof(buffer), timeoutMs, peer);
    if (received <= 0)
        return std::nullopt;
    return lte::ue::link::Decode(buffer, static_cast<size_t>(received));
}

// Non-blocking drain so later "nothing else arrived" assertions are honest.
std::vector<lte::ue::link::Message> DrainRadio(udp::UdpServer &socket)
{
    std::vector<lte::ue::link::Message> messages;
    while (auto message = ReceiveRadio(socket, 0))
        messages.push_back(std::move(*message));
    return messages;
}

s1ap::InitialContextSetupRequest ContextSetupRequest(uint32_t mmeId, uint32_t enbId, std::array<uint8_t, 4> sgwAddress,
                                                      uint32_t sgwTeid)
{
    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = mmeId;
    request.enbUeS1apId = enbId;
    request.ueAmbrDl = 1;
    request.ueAmbrUl = 1;
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x00, 0x20};
    s1ap::ErabToBeSetupItem erab{};
    erab.erabId = 5;
    erab.qci = 9;
    erab.transportLayerAddress = sgwAddress;
    erab.gtpTeid = TeidToBytes(sgwTeid);
    request.erabs.push_back(erab);
    return request;
}

// Drives Initial UE Message, Initial Context Setup and BEARER_READY for one UE.
void AttachUe(EnbMultiplexer &mux, FakeUe &ue, uint32_t mmeId, std::array<uint8_t, 4> sgwAddress, uint32_t sgwTeid,
              std::array<uint8_t, 4> ueIpv4)
{
    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});
    auto *entry = mux.registry().find(ue.ueId);
    REQUIRE(entry != nullptr);
    auto request = ContextSetupRequest(mmeId, entry->enbUeS1apId, sgwAddress, sgwTeid);
    request.erabs.front().nasPduPresent = true;
    request.erabs.front().nasPdu = {0x77, 0x27};
    auto wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    SendRadio(mux, ue, lte::ue::link::MessageType::BEARER_READY,
              {5, ueIpv4[0], ueIpv4[1], ueIpv4[2], ueIpv4[3]});
    DrainRadio(ue.radio); // the forwarded Attach Accept NAS is not under test here
}

std::vector<uint8_t> Ipv4(std::array<uint8_t, 4> source, std::array<uint8_t, 4> destination)
{
    std::vector<uint8_t> packet(20, 0);
    packet[0] = 0x45;
    packet[2] = 0x00;
    packet[3] = 0x14;
    packet[8] = 64;
    packet[9] = 1;
    std::copy(source.begin(), source.end(), packet.begin() + 12);
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    return packet;
}

void SendUplinkData(EnbMultiplexer &mux, FakeUe &ue, std::array<uint8_t, 4> source, std::array<uint8_t, 4> destination)
{
    auto packet = Ipv4(source, destination);
    SendRadio(mux, ue, lte::ue::link::MessageType::DATA_UPLINK, std::move(packet));
}

// Sends a downlink GTP-U T-PDU to the shared endpoint and drains one event turn.
void SendDownlink(EnbMultiplexer &mux, const FakeSgw &sgw, uint32_t teid, const std::vector<uint8_t> &packet)
{
    auto datagram = gtpu::EncodeTPdu(teid, packet.data(), packet.size());
    sgw.socket.Send(mux.s1uAddress(), datagram.data(), datagram.size());
    mux.poll(0, 4);
}

std::optional<gtpu::Packet> ReceiveS1u(udp::UdpServer &socket)
{
    uint8_t buffer[65536];
    InetAddress peer;
    const int received = socket.Receive(buffer, sizeof(buffer), 0, peer);
    if (received <= 0)
        return std::nullopt;
    return gtpu::Decode(buffer, static_cast<size_t>(received));
}

} // namespace

// ---------------------------------------------------------------------------
// Identity and registry (spec tests 1-8)
// ---------------------------------------------------------------------------

TEST_CASE("multi-ue/registry: distinct radio identities create independent entries")
{
    UeRegistry registry(8);
    InetAddress peerA("127.0.0.1", 40001);
    InetAddress peerB("127.0.0.1", 40002);
    auto &a = registry.registerPeer(1, peerA);
    auto &b = registry.registerPeer(2, peerB);
    CHECK(registry.size() == 2);
    CHECK(&a != &b);
    CHECK(registry.find(1) == &a);
    CHECK(registry.find(2) == &b);
    CHECK(registry.findByPeer(peerA) == &a);
    CHECK(registry.findByPeer(peerB) == &b);
    CHECK(registry.find(3) == nullptr);
    CHECK(registry.findByPeer(InetAddress("127.0.0.1", 40003)) == nullptr);
}

TEST_CASE("multi-ue/registry: duplicate identity, duplicate endpoint, zero identity and capacity are rejected")
{
    UeRegistry registry(2);
    InetAddress peerA("127.0.0.1", 40001);
    InetAddress peerB("127.0.0.1", 40002);
    InetAddress peerC("127.0.0.1", 40003);
    CHECK_THROWS(registry.registerPeer(0, peerA));
    (void)registry.registerPeer(1, peerA);
    CHECK_THROWS(registry.registerPeer(1, peerB)); // duplicate radio identity
    CHECK_THROWS(registry.registerPeer(2, peerA)); // endpoint claims another identity
    CHECK(registry.size() == 1);
    (void)registry.registerPeer(2, peerB);
    CHECK_THROWS(registry.registerPeer(3, peerC)); // capacity
    CHECK(registry.capacity() == 2);
}

TEST_CASE("multi-ue/registry: removing one UE does not erase another")
{
    UeRegistry registry(8);
    InetAddress peerA("127.0.0.1", 40001);
    InetAddress peerB("127.0.0.1", 40002);
    auto &a = registry.registerPeer(1, peerA);
    (void)registry.registerPeer(2, peerB);
    registry.remove(a);
    CHECK(registry.find(1) == nullptr);
    CHECK(registry.findByPeer(peerA) == nullptr);
    auto *b = registry.find(2);
    REQUIRE(b != nullptr);
    CHECK(b->radioUeId == 2);
    CHECK(registry.size() == 1);
}

TEST_CASE("multi-ue/registry: released S1 identifiers and TEIDs stop resolving without stale resurrection")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t enbId = registry.allocateEnbUeS1apId();
    registry.bindEnbUeS1apId(entry, enbId);
    registry.setMmeUeS1apId(entry, 0xABCDU);
    const uint32_t oldTeid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1, oldTeid});
    registry.bindLocalTeid(entry, oldTeid);
    REQUIRE(oldTeid != 0);

    registry.releaseS1(entry);
    CHECK(registry.findByEnbUeS1apId(enbId) == nullptr);
    CHECK(registry.findByMmeUeS1apId(0xABCDU) == nullptr);
    CHECK(registry.findByLocalTeid(oldTeid) == nullptr);
    CHECK(entry.s1 == UeS1State::IDLE_RETAINED);
    CHECK(entry.enbUeS1apId == 0);
    CHECK(entry.mmeUeS1apId == 0);

    const uint32_t freshId = registry.allocateEnbUeS1apId();
    CHECK(freshId != enbId);
    registry.bindEnbUeS1apId(entry, freshId);
    CHECK(registry.findByEnbUeS1apId(freshId) == &entry);
    const uint32_t freshTeid = registry.allocateLocalTeid();
    CHECK(freshTeid != oldTeid);
}

TEST_CASE("multi-ue/registry: S1AP identity ownership is exclusive and enforced")
{
    UeRegistry registry(8);
    auto &a = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    auto &b = registry.registerPeer(2, InetAddress("127.0.0.1", 40002));
    const uint32_t idA = registry.allocateEnbUeS1apId();
    const uint32_t idB = registry.allocateEnbUeS1apId();
    CHECK(idA != idB);
    registry.bindEnbUeS1apId(a, idA);
    CHECK_THROWS(registry.bindEnbUeS1apId(b, idA));
    CHECK_THROWS(registry.bindEnbUeS1apId(a, idB)); // already owns one
    CHECK_THROWS(registry.bindEnbUeS1apId(a, 0));
    registry.setMmeUeS1apId(a, 0x100);
    CHECK_THROWS(registry.setMmeUeS1apId(b, 0x100));
    registry.setMmeUeS1apId(b, 0x200);
    registry.setMmeUeS1apId(b, 0x201); // replaces its own mapping
    CHECK(registry.findByMmeUeS1apId(0x200) == nullptr);
    CHECK(registry.findByMmeUeS1apId(0x201) == &b);
}

TEST_CASE("multi-ue/registry: identifier allocation stays unique and non-zero across many contexts")
{
    UeRegistry registry(8);
    std::set<uint32_t> ids;
    for (int i = 0; i < 512; ++i)
    {
        const uint32_t id = registry.allocateEnbUeS1apId();
        CHECK(id != 0);
        CHECK(id <= 0xFFFFFFU);
        CHECK(ids.insert(id).second);
    }
    std::set<uint32_t> teids;
    for (int i = 0; i < 512; ++i)
    {
        const uint32_t teid = registry.allocateLocalTeid();
        CHECK(teid != 0);
        CHECK(teids.insert(teid).second);
    }
}

TEST_CASE("multi-ue/sctp-stream: per-UE stream assignment respects negotiated bounds")
{
    CHECK(SctpStreamForUe(1, 1) == 0);
    CHECK(SctpStreamForUe(1, 12345) == 0);
    for (uint32_t id = 1; id <= 40; ++id)
    {
        const uint16_t stream = SctpStreamForUe(10, id);
        CHECK(stream >= 1);
        CHECK(stream <= 9);
    }
    // Streams are stable per UE identity, preserving per-UE ordering.
    CHECK(SctpStreamForUe(4, 7) == SctpStreamForUe(4, 7));
    CHECK(SctpStreamForUe(4, 1) == 1);
    CHECK(SctpStreamForUe(4, 2) == 2);
    CHECK(SctpStreamForUe(4, 4) == 1); // wrap within the usable range
}

TEST_CASE("multi-ue/config: eNB maxUes and UE ueId are parsed and validated")
{
    const char *enbYaml = R"(
mcc: '460'
mnc: '02'
enbId: 0x19B
tac: 1
s1apIp: 127.0.0.1
pagingDrx: 128
maxUes: 16
mme:
  address: 127.0.0.2
  port: 36412
)";
    auto enb = lte::enb::ParseConfig(enbYaml);
    CHECK(enb.maxUes == 16);

    std::string beyond = enbYaml;
    beyond.replace(beyond.find("16"), 2, "65");
    CHECK_THROWS(lte::enb::ParseConfig(beyond));

    const char *ueYaml = R"(
imsi: '460020123456789'
mcc: '460'
mnc: '02'
k: '00112233445566778899AABBCCDDEEFF'
op: '102132435465768798A9BACBDCEDFE0F'
amf: '8000'
initialSqn: '000000000000'
enbLink:
  localAddress: 127.0.0.1
  localPort: 4999
  address: 127.0.0.1
  port: 4998
)";
    auto defaulted = lte::ue::ParseConfig(ueYaml);
    CHECK(defaulted.ueId == 1);

    std::string second = ueYaml;
    second.insert(0, "ueId: 2\n");
    auto ueB = lte::ue::ParseConfig(second);
    CHECK(ueB.ueId == 2);

    std::string zero = ueYaml;
    zero.insert(0, "ueId: 0\n");
    CHECK_THROWS(lte::ue::ParseConfig(zero));

    std::string huge = ueYaml;
    huge.insert(0, "ueId: 4294967296\n");
    CHECK_THROWS(lte::ue::ParseConfig(huge));
}

TEST_CASE("multi-ue/config: two independent UE configurations stay separable")
{
    const char *ueTemplate = R"(
imsi: '4600201234567%02d'
mcc: '460'
mnc: '02'
ueId: %u
k: '00112233445566778899AABBCCDDEEFF'
op: '102132435465768798A9BACBDCEDFE0F'
amf: '8000'
initialSqn: '000000000000'
enbLink:
  localAddress: 127.0.0.1
  localPort: %u
  address: 127.0.0.1
  port: 4998
)";
    char a[512], b[512];
    std::snprintf(a, sizeof(a), ueTemplate, 89, 1u, 4999u);
    std::snprintf(b, sizeof(b), ueTemplate, 90, 2u, 5000u);
    auto configA = lte::ue::ParseConfig(a);
    auto configB = lte::ue::ParseConfig(b);
    CHECK(configA.ueId != configB.ueId);
    CHECK(configA.link.localPort != configB.link.localPort);
    CHECK(configA.imsi != configB.imsi);

    // The configured identity is what the radio-link frames carry.
    auto frame = lte::ue::link::Encode({lte::ue::link::MessageType::NAS_UPLINK, configB.ueId, {0x07, 0x41}});
    auto decoded = lte::ue::link::Decode(frame.data(), frame.size());
    CHECK(decoded.ueId == configB.ueId);
}

// ---------------------------------------------------------------------------
// S1AP multiplexing (spec tests 9-18)
// ---------------------------------------------------------------------------

TEST_CASE("multi-ue/s1ap: concurrent Initial UE Messages use distinct eNB S1AP IDs")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    mux.setOutboundStreams(8);
    FakeUe ueA(1);
    FakeUe ueB(2);

    SendRadio(mux, ueA, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});
    SendRadio(mux, ueB, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});
    REQUIRE(sender.sent.size() == 2);
    CHECK(sender.count(12) == 2);

    auto *entryA = mux.registry().find(1);
    auto *entryB = mux.registry().find(2);
    REQUIRE(entryA != nullptr);
    REQUIRE(entryB != nullptr);
    CHECK(entryA->enbUeS1apId != entryB->enbUeS1apId);
    CHECK(entryA->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(entryB->s1 == UeS1State::CONTEXT_PENDING);
    for (const auto &item : sender.sent)
    {
        CHECK(item.stream >= 1);
        CHECK(item.stream <= 7);
    }
    CHECK(mux.registry().findByEnbUeS1apId(entryA->enbUeS1apId) == entryA);
    CHECK(mux.registry().findByEnbUeS1apId(entryB->enbUeS1apId) == entryB);
}

TEST_CASE("multi-ue/s1ap: independent contexts establish bearers with distinct local TEIDs")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);

    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});

    auto *entryA = mux.registry().find(1);
    auto *entryB = mux.registry().find(2);
    REQUIRE(entryA != nullptr);
    REQUIRE(entryB != nullptr);
    CHECK(entryA->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entryB->s1 == UeS1State::BEARER_ACTIVE);
    // Equal EBIs across UEs must not collide: distinct local receiving TEIDs.
    CHECK(entryA->bearer.parameters().erabId == 5);
    CHECK(entryB->bearer.parameters().erabId == 5);
    CHECK(entryA->bearer.parameters().localTeid != 0);
    CHECK(entryB->bearer.parameters().localTeid != 0);
    CHECK(entryA->bearer.parameters().localTeid != entryB->bearer.parameters().localTeid);
    CHECK(entryA->bearer.parameters().sgwTeid == 0xA1A1A1A1);
    CHECK(entryB->bearer.parameters().sgwTeid == 0xB2B2B2B2);
    CHECK(mux.registry().findByMmeUeS1apId(0x111) == entryA);
    CHECK(mux.registry().findByMmeUeS1apId(0x222) == entryB);
    CHECK(mux.registry().findByLocalTeid(entryA->bearer.parameters().localTeid) == entryA);
    CHECK(mux.registry().findByLocalTeid(entryB->bearer.parameters().localTeid) == entryB);
}

TEST_CASE("multi-ue/s1ap: Downlink NAS reaches only the addressed UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);

    auto *entryA = mux.registry().find(1);
    auto wire = s1ap::EncodeDownlinkNasTransport(0x111, entryA->enbUeS1apId, {0x77, 0x55});
    mux.handleS1ap(wire.data(), wire.size(), 1);

    auto down = ReceiveRadio(ueA.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->type == lte::ue::link::MessageType::NAS_DOWNLINK);
    CHECK(down->ueId == 1);
    CHECK(down->payload == std::vector<uint8_t>{0x77, 0x55});
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());

    auto *entryB = mux.registry().find(2);
    wire = s1ap::EncodeDownlinkNasTransport(0x222, entryB->enbUeS1apId, {0x77, 0x66});
    mux.handleS1ap(wire.data(), wire.size(), 2);
    down = ReceiveRadio(ueB.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->ueId == 2);
    CHECK(down->payload == std::vector<uint8_t>{0x77, 0x66});
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
}

TEST_CASE("multi-ue/s1ap: mismatched identity pairs fail closed")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);
    const size_t sentBefore = sender.sent.size();

    auto *entryA = mux.registry().find(1);
    // UE A's eNB ID paired with UE B's MME ID.
    auto wire = s1ap::EncodeDownlinkNasTransport(0x222, entryA->enbUeS1apId, {0x77, 0x55});
    mux.handleS1ap(wire.data(), wire.size(), 1);
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());

    // An MME ID owned by another UE may not be reassigned.
    auto request = ContextSetupRequest(0x222, 999, {127, 0, 0, 9}, 0x01020304);
    wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    CHECK(mux.registry().findByEnbUeS1apId(999) == nullptr);
    CHECK(sender.sent.size() == sentBefore);
}

TEST_CASE("multi-ue/s1ap: UE Context Release Command releases only the addressed UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);

    auto *entryA = mux.registry().find(1);
    auto *entryB = mux.registry().find(2);
    const uint32_t teidB = entryB->bearer.parameters().localTeid;

    auto wire = s1ap::EncodeUeContextReleaseCommand(0x111, entryA->enbUeS1apId, "nas", 0);
    mux.handleS1ap(wire.data(), wire.size(), 1);

    auto released = ReceiveRadio(ueA.radio, 1000);
    REQUIRE(released.has_value());
    CHECK(released->type == lte::ue::link::MessageType::S1_CONTEXT_RELEASED);
    CHECK(released->ueId == 1);
    CHECK(released->payload == lte::ue::link::EncodeBearerRestoration(5, 1));
    CHECK(entryA->s1 == UeS1State::IDLE_RETAINED);
    CHECK(entryA->bearer.parameters().localTeid == 0);
    CHECK_FALSE(entryB->bearer.parameters().localTeid == 0);
    CHECK(entryB->s1 == UeS1State::BEARER_ACTIVE);
    REQUIRE(sender.sent.size() == 5);
    auto complete = s1ap::ProbeS1apPdu(sender.sent.back().pdu.data(), sender.sent.back().pdu.size());
    CHECK(complete.kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    CHECK(complete.procedureCode == 23);
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());

    // The MME-only variant still resolves the right UE without guessing.
    wire = s1ap::EncodeUeContextReleaseCommand(0x222, std::nullopt, "radioNetwork", 20);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    released = ReceiveRadio(ueB.radio, 1000);
    REQUIRE(released.has_value());
    CHECK(released->ueId == 2);
    CHECK(entryB->s1 == UeS1State::IDLE_RETAINED);
    CHECK(mux.registry().findByLocalTeid(teidB) == nullptr);
}

TEST_CASE("multi-ue/s1ap: stale identifiers cannot consume later S1AP responses")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);

    auto *entryA = mux.registry().find(1);
    const uint32_t oldEnbId = entryA->enbUeS1apId;
    auto wire = s1ap::EncodeUeContextReleaseCommand(0x111, oldEnbId, "nas", 0);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio);
    const size_t sentAfterRelease = sender.sent.size();

    wire = s1ap::EncodeDownlinkNasTransport(0x111, oldEnbId, {0x77, 0x55});
    mux.handleS1ap(wire.data(), wire.size(), 1);
    auto request = ContextSetupRequest(0x111, oldEnbId, {127, 0, 0, 9}, 0x01020304);
    wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    wire = s1ap::EncodeUeContextReleaseCommand(0x111, oldEnbId, "nas", 0);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    CHECK(sender.sent.size() == sentAfterRelease);
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
    CHECK(mux.registry().find(1)->s1 == UeS1State::IDLE_RETAINED);
    CHECK(mux.registry().find(2)->s1 == UeS1State::BEARER_ACTIVE);
}

TEST_CASE("multi-ue/s1ap: Service Request opens a fresh context with a new identity")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    DrainRadio(ueA.radio);

    auto *entry = mux.registry().find(1);
    const uint32_t oldEnbId = entry->enbUeS1apId;
    auto wire = s1ap::EncodeUeContextReleaseCommand(0x111, oldEnbId, "nas", 0);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio);

    // MMEC(1) || M-TMSI || compact four-octet Service Request NAS.
    SendRadio(mux, ueA, lte::ue::link::MessageType::SERVICE_REQUEST, {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0, 0xAA, 0xBB});
    CHECK(entry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK(entry->enbUeS1apId != oldEnbId);
    CHECK(entry->enbUeS1apId != 0);
    CHECK(sender.count(12) == 2);
    CHECK(mux.registry().findByEnbUeS1apId(oldEnbId) == nullptr);

    // Duplicate Service Request while a context exists is rejected.
    const size_t before = sender.sent.size();
    SendRadio(mux, ueA, lte::ue::link::MessageType::SERVICE_REQUEST, {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0, 0xAA, 0xBB});
    CHECK(sender.sent.size() == before);
}

TEST_CASE("multi-ue/s1ap: per-UE uplink NAS preserves ordering on a stable stream")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    mux.setOutboundStreams(4);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    const size_t baseline = sender.sent.size();

    for (int i = 0; i < 4; ++i)
    {
        SendRadio(mux, ueA, lte::ue::link::MessageType::NAS_UPLINK, {0x57, static_cast<uint8_t>(i)});
        SendRadio(mux, ueB, lte::ue::link::MessageType::NAS_UPLINK, {0x58, static_cast<uint8_t>(i)});
    }
    REQUIRE(sender.sent.size() - baseline == 8);

    uint16_t streamA = 0xFFFF;
    uint16_t streamB = 0xFFFF;
    std::vector<uint8_t> orderA, orderB;
    for (size_t i = baseline; i < sender.sent.size(); ++i)
    {
        const auto &item = sender.sent[i];
        auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
        REQUIRE(pdu.procedureCode == 13);
        const auto tagA = std::vector<uint8_t>{0x57, static_cast<uint8_t>(orderA.size())};
        if (std::search(item.pdu.begin(), item.pdu.end(), tagA.begin(), tagA.end()) != item.pdu.end())
        {
            if (streamA == 0xFFFF)
                streamA = item.stream;
            CHECK(item.stream == streamA);
            orderA.push_back(0x57);
        }
        else
        {
            const auto tagB = std::vector<uint8_t>{0x58, static_cast<uint8_t>(orderB.size())};
            REQUIRE(std::search(item.pdu.begin(), item.pdu.end(), tagB.begin(), tagB.end()) != item.pdu.end());
            if (streamB == 0xFFFF)
                streamB = item.stream;
            CHECK(item.stream == streamB);
            orderB.push_back(0x58);
        }
    }
    CHECK(orderA.size() == 4);
    CHECK(orderB.size() == 4);
}

// ---------------------------------------------------------------------------
// Shared S1-U GTP-U endpoint (spec tests 19-31)
// ---------------------------------------------------------------------------

TEST_CASE("multi-ue/gtpu: concurrent uplink uses each UE's own SGW peer and TEID")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.9");
    FakeSgw sgwB("127.0.0.10");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});

    SendUplinkData(mux, ueA, {10, 45, 0, 2}, {10, 45, 0, 1});
    auto uplink = ReceiveS1u(sgwA.socket);
    REQUIRE(uplink.has_value());
    CHECK(uplink->teid == 0xA1A1A1A1);
    CHECK(uplink->payload == Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}));
    CHECK_FALSE(ReceiveS1u(sgwB.socket).has_value());

    SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
    uplink = ReceiveS1u(sgwB.socket);
    REQUIRE(uplink.has_value());
    CHECK(uplink->teid == 0xB2B2B2B2);
    CHECK_FALSE(ReceiveS1u(sgwA.socket).has_value());

    // A spoofed source address for another UE is dropped at the bearer.
    const size_t drops = mux.registry().find(2)->counters.malformedDrops;
    SendUplinkData(mux, ueB, {10, 45, 0, 2}, {10, 45, 0, 1});
    CHECK(mux.registry().find(2)->counters.malformedDrops == drops + 1);
    CHECK_FALSE(ReceiveS1u(sgwA.socket).has_value());
}

TEST_CASE("multi-ue/gtpu: downlink TEID routes only to the intended UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.9");
    FakeSgw sgwB("127.0.0.10");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 9}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 10}, 0xB2B2B2B2, {10, 45, 0, 3});
    const uint32_t teidA = mux.registry().find(1)->bearer.parameters().localTeid;
    const uint32_t teidB = mux.registry().find(2)->bearer.parameters().localTeid;

    SendDownlink(mux, sgwA, teidA, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    auto down = ReceiveRadio(ueA.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->type == lte::ue::link::MessageType::DATA_DOWNLINK);
    CHECK(down->ueId == 1);
    CHECK(down->payload == Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());

    SendDownlink(mux, sgwB, teidB, Ipv4({10, 45, 0, 1}, {10, 45, 0, 3}));
    down = ReceiveRadio(ueB.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->ueId == 2);
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());

    // A packet for UE A's address on UE B's TEID is rejected.
    const size_t drops = mux.registry().find(2)->counters.malformedDrops;
    SendDownlink(mux, sgwB, teidB, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    CHECK(mux.registry().find(2)->counters.malformedDrops == drops + 1);
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());
}

TEST_CASE("multi-ue/gtpu: unknown TEIDs are dropped and Echo needs no UE context")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeSgw sgwA("127.0.0.11");
    udp::UdpServer probe("127.0.0.1", 0);

    // Echo works at the shared endpoint before any UE exists.
    std::vector<uint8_t> echo{0x32, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00, 0x0E, 0x00};
    probe.Send(mux.s1uAddress(), echo.data(), echo.size());
    mux.poll(0, 4);
    auto response = ReceiveS1u(probe);
    REQUIRE(response.has_value());
    CHECK(response->messageType == gtpu::EchoResponse);
    REQUIRE(response->sequenceNumber.has_value());
    CHECK(*response->sequenceNumber == 0x1234);

    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwB("127.0.0.12");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 11}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 12}, 0xB2B2B2B2, {10, 45, 0, 3});
    const uint32_t teidA = mux.registry().find(1)->bearer.parameters().localTeid;

    // Unknown TEID from a valid peer is dropped silently.
    SendDownlink(mux, sgwA, teidA + 12345, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
    CHECK_FALSE(ReceiveRadio(ueB.radio, 200).has_value());

    // A T-PDU from a peer that is not the bearer's SGW is dropped.
    SendDownlink(mux, sgwB, teidA, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
    CHECK(mux.registry().find(1)->counters.unexpectedPeerDrops == 1);
}

TEST_CASE("multi-ue/gtpu: release invalidates one TEID while the shared endpoint stays operational")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.13");
    FakeSgw sgwB("127.0.0.14");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 13}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 14}, 0xB2B2B2B2, {10, 45, 0, 3});
    auto *entryA = mux.registry().find(1);
    const uint32_t teidA = entryA->bearer.parameters().localTeid;
    const uint32_t teidB = mux.registry().find(2)->bearer.parameters().localTeid;

    auto wire = s1ap::EncodeUeContextReleaseCommand(0x111, entryA->enbUeS1apId, "nas", 0);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio);

    // UE A's stale TEID is dropped; UE B keeps working on the same socket in
    // both directions.
    SendDownlink(mux, sgwA, teidA, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    CHECK_FALSE(ReceiveRadio(ueA.radio, 200).has_value());
    SendDownlink(mux, sgwB, teidB, Ipv4({10, 45, 0, 1}, {10, 45, 0, 3}));
    auto down = ReceiveRadio(ueB.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->ueId == 2);
    SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
    auto uplink = ReceiveS1u(sgwB.socket);
    REQUIRE(uplink.has_value());
    CHECK(uplink->teid == 0xB2B2B2B2);

    // Re-Attach of UE A receives a fresh TEID without stale aliasing.
    SendRadio(mux, ueA, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});
    auto request = ContextSetupRequest(0x333, entryA->enbUeS1apId, {127, 0, 0, 13}, 0xC3C3C3C3);
    wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio); // consumes the restored-context radio frame
    const uint32_t freshTeidA = entryA->bearer.parameters().localTeid;
    CHECK(freshTeidA != teidA);
    CHECK(freshTeidA != teidB);
    CHECK(mux.registry().findByLocalTeid(freshTeidA) == entryA);
    CHECK(mux.registry().findByLocalTeid(teidA) == nullptr);
    SendRadio(mux, ueA, lte::ue::link::MessageType::BEARER_READY, {5, 10, 45, 0, 2});
    SendDownlink(mux, sgwA, freshTeidA, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
    down = ReceiveRadio(ueA.radio, 1000);
    REQUIRE(down.has_value());
    CHECK(down->ueId == 1);
}

// ---------------------------------------------------------------------------
// Lifecycle isolation and failure isolation (spec tests 32-54)
// ---------------------------------------------------------------------------

TEST_CASE("multi-ue/lifecycle: ECM-IDLE release and Service Request restore isolate per UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.15");
    FakeSgw sgwB("127.0.0.16");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 15}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 16}, 0xB2B2B2B2, {10, 45, 0, 3});
    auto *entryA = mux.registry().find(1);
    auto *entryB = mux.registry().find(2);
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);

    // UE A requests the idle release; only its own context is released.
    SendRadio(mux, ueA, lte::ue::link::MessageType::S1_CONTEXT_RELEASE_REQUEST, {5});
    REQUIRE(sender.count(18) == 1);
    auto wire = s1ap::EncodeUeContextReleaseCommand(0x111, entryA->enbUeS1apId, "radioNetwork", 20);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio);
    CHECK(entryA->s1 == UeS1State::IDLE_RETAINED);
    CHECK(entryB->s1 == UeS1State::BEARER_ACTIVE);

    // UE B keeps forwarding during UE A's idle window.
    SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
    auto uplink = ReceiveS1u(sgwB.socket);
    REQUIRE(uplink.has_value());
    CHECK(uplink->teid == 0xB2B2B2B2);

    // UE A restores with a Service Request and receives a fresh context.
    SendRadio(mux, ueA, lte::ue::link::MessageType::SERVICE_REQUEST, {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0, 0xAA, 0xBB});
    auto request = ContextSetupRequest(0x111, entryA->enbUeS1apId, {127, 0, 0, 15}, 0xD4D4D4D4);
    wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    auto restored = ReceiveRadio(ueA.radio, 1000);
    REQUIRE(restored.has_value());
    CHECK(restored->type == lte::ue::link::MessageType::S1_CONTEXT_RESTORED);
    CHECK(restored->ueId == 1);
    CHECK(restored->payload == lte::ue::link::EncodeBearerRestoration(5, 1));
    SendRadio(mux, ueA, lte::ue::link::MessageType::BEARER_TRANSPORT_READY, restored->payload);
    CHECK(entryA->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entryB->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(mux.registry().findByMmeUeS1apId(0x111) == entryA);
    CHECK(mux.registry().findByMmeUeS1apId(0x222) == entryB);
}

TEST_CASE("multi-ue/lifecycle: an inactive bearer does not block another UE's user plane")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.17");
    FakeSgw sgwB("127.0.0.18");

    // UE A completes signaling but never sends BEARER_READY.
    SendRadio(mux, ueA, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});
    auto request = ContextSetupRequest(0x111, mux.registry().find(1)->enbUeS1apId, {127, 0, 0, 17}, 0xA1A1A1A1);
    auto wire = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(wire.data(), wire.size(), 1);
    DrainRadio(ueA.radio);
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 18}, 0xB2B2B2B2, {10, 45, 0, 3});

    const size_t inactive = mux.registry().find(1)->counters.bearerInactiveDrops;
    SendUplinkData(mux, ueA, {10, 45, 0, 2}, {10, 45, 0, 1});
    CHECK(mux.registry().find(1)->counters.bearerInactiveDrops == inactive + 1);
    CHECK_FALSE(ReceiveS1u(sgwA.socket).has_value());

    SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
    auto uplink = ReceiveS1u(sgwB.socket);
    REQUIRE(uplink.has_value());
    CHECK(uplink->teid == 0xB2B2B2B2);
}

TEST_CASE("multi-ue/failure: malformed traffic from one UE does not disturb another")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.19");
    FakeSgw sgwB("127.0.0.20");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 19}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 20}, 0xB2B2B2B2, {10, 45, 0, 3});
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);
    const size_t sentBefore = sender.sent.size();

    // Garbage datagram from UE A's endpoint.
    const uint8_t garbage[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    mux.handleRadioFrame(garbage, sizeof(garbage), ueA.radio.LocalAddress());
    // UE A's endpoint claiming UE B's identity.
    auto frame = lte::ue::link::Encode({lte::ue::link::MessageType::NAS_UPLINK, 2, {0x07, 0x41}});
    mux.handleRadioFrame(frame.data(), frame.size(), ueA.radio.LocalAddress());
    // Downlink frame sent uplink.
    SendRadio(mux, ueA, lte::ue::link::MessageType::DATA_DOWNLINK, Ipv4({10, 45, 0, 2}, {10, 45, 0, 1}));
    // Unknown UE identity cannot register with data.
    auto unknown = lte::ue::link::Encode({lte::ue::link::MessageType::DATA_UPLINK, 7, Ipv4({10, 45, 0, 9}, {10, 45, 0, 1})});
    mux.handleRadioFrame(unknown.data(), unknown.size(), InetAddress("127.0.0.1", 49990));

    CHECK(sender.sent.size() == sentBefore);
    CHECK(mux.registry().size() == 2);
    CHECK(mux.registry().find(7) == nullptr);
    auto *entryB = mux.registry().find(2);
    CHECK(entryB->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entryB->counters.malformedDrops == 0);

    // Both UEs keep forwarding afterwards.
    SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
    REQUIRE(ReceiveS1u(sgwB.socket).has_value());
    SendUplinkData(mux, ueA, {10, 45, 0, 2}, {10, 45, 0, 1});
    REQUIRE(ReceiveS1u(sgwA.socket).has_value());
}

TEST_CASE("multi-ue/data: interleaved traffic routes correctly with per-UE counters")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    FakeSgw sgwA("127.0.0.21");
    FakeSgw sgwB("127.0.0.22");
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 21}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 22}, 0xB2B2B2B2, {10, 45, 0, 3});
    const uint32_t teidA = mux.registry().find(1)->bearer.parameters().localTeid;
    const uint32_t teidB = mux.registry().find(2)->bearer.parameters().localTeid;
    DrainRadio(ueA.radio);
    DrainRadio(ueB.radio);

    for (int i = 0; i < 3; ++i)
    {
        SendUplinkData(mux, ueA, {10, 45, 0, 2}, {10, 45, 0, 1});
        SendUplinkData(mux, ueB, {10, 45, 0, 3}, {10, 45, 0, 1});
        SendDownlink(mux, sgwA, teidA, Ipv4({10, 45, 0, 1}, {10, 45, 0, 2}));
        SendDownlink(mux, sgwB, teidB, Ipv4({10, 45, 0, 1}, {10, 45, 0, 3}));
    }
    for (int i = 0; i < 3; ++i)
    {
        auto upA = ReceiveS1u(sgwA.socket);
        REQUIRE(upA.has_value());
        CHECK(upA->teid == 0xA1A1A1A1);
        auto upB = ReceiveS1u(sgwB.socket);
        REQUIRE(upB.has_value());
        CHECK(upB->teid == 0xB2B2B2B2);
    }
    CHECK_FALSE(ReceiveS1u(sgwA.socket).has_value());
    CHECK_FALSE(ReceiveS1u(sgwB.socket).has_value());
    for (int i = 0; i < 3; ++i)
    {
        auto down = ReceiveRadio(ueA.radio, 1000);
        REQUIRE(down.has_value());
        CHECK(down->ueId == 1);
        down = ReceiveRadio(ueB.radio, 1000);
        REQUIRE(down.has_value());
        CHECK(down->ueId == 2);
    }

    auto *entryA = mux.registry().find(1);
    auto *entryB = mux.registry().find(2);
    CHECK(entryA->counters.simulatedUplinkPackets == 3);
    CHECK(entryA->counters.s1uUplinkPackets == 3);
    CHECK(entryA->counters.s1uDownlinkPackets == 3);
    CHECK(entryA->counters.simulatedDownlinkPackets == 3);
    CHECK(entryB->counters.simulatedUplinkPackets == 3);
    CHECK(entryB->counters.s1uUplinkPackets == 3);
    CHECK(entryB->counters.s1uDownlinkPackets == 3);
    CHECK(entryB->counters.simulatedDownlinkPackets == 3);
}

TEST_CASE("multi-ue/shutdown: releases every UE context and keeps registry consistent")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);
    FakeUe ueB(2);
    AttachUe(mux, ueA, 0x111, {127, 0, 0, 23}, 0xA1A1A1A1, {10, 45, 0, 2});
    AttachUe(mux, ueB, 0x222, {127, 0, 0, 24}, 0xB2B2B2B2, {10, 45, 0, 3});

    mux.shutdown();
    CHECK(mux.registry().size() == 2); // radio identities retained, S1 released
    for (auto *entry : mux.registry().all())
    {
        CHECK(entry->s1 == UeS1State::IDLE_RETAINED);
        CHECK(entry->bearer.parameters().localTeid == 0);
        CHECK(mux.registry().findByEnbUeS1apId(entry->enbUeS1apId) == nullptr);
    }
}

TEST_CASE("multi-ue/codec: Downlink NAS Transport test encoder round-trips")
{
    auto wire = s1ap::EncodeDownlinkNasTransport(0x11223344U, 9, {0x77, 0x55});
    auto pdu = s1ap::ProbeS1apPdu(wire.data(), wire.size());
    CHECK(pdu.kind == s1ap::S1apPdu::Kind::INITIATING);
    CHECK(pdu.procedureCode == 11);
    auto decoded = s1ap::DecodeDownlinkNasTransport(wire.data(), wire.size());
    CHECK(decoded.mmeUeS1apId == 0x11223344U);
    CHECK(decoded.enbUeS1apId == 9);
    CHECK(decoded.nasPdu == std::vector<uint8_t>{0x77, 0x55});
    CHECK_THROWS(s1ap::EncodeDownlinkNasTransport(0, 9, {0x77}));
    CHECK_THROWS(s1ap::EncodeDownlinkNasTransport(1, 0, {0x77}));
}

