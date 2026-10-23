//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/gtpu.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ip_packet.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/tun.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <unistd.h>
#include <vector>

namespace
{
std::vector<uint8_t> Ipv4(std::array<uint8_t, 4> source = {10, 45, 0, 2},
                          std::array<uint8_t, 4> destination = {10, 45, 0, 1})
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

lte::enb::BearerParameters Parameters(uint32_t localTeid = 0x01020304)
{
    return {5, 9, 1, {192, 0, 2, 20}, 0xA1A2A3A4, localTeid};
}
} // namespace

TEST_CASE("lte/user-plane/gtpu: independent basic T-PDU wire vector has network-order length and TEID")
{
    const std::vector<uint8_t> ipv4{0x45, 0x00, 0x00, 0x04};
    const auto encoded = lte::enb::gtpu::EncodeTPdu(0x11223344, ipv4.data(), ipv4.size());
    CHECK(encoded == std::vector<uint8_t>{0x30, 0xFF, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44,
                                          0x45, 0x00, 0x00, 0x04});
    const auto decoded = lte::enb::gtpu::Decode(encoded.data(), encoded.size());
    CHECK(decoded.messageType == lte::enb::gtpu::TPdu);
    CHECK(decoded.teid == 0x11223344);
    CHECK(decoded.payload == ipv4);
}

TEST_CASE("lte/user-plane/gtpu: optional sequence and supported extension headers are skipped safely")
{
    auto ipv4 = Ipv4();
    std::vector<uint8_t> datagram{0x36, 0xFF, 0x00, 0x1C, 0x01, 0x02, 0x03, 0x04,
                                  0x12, 0x34, 0x00, 0xC0, 0x01, 0xAA, 0xBB, 0x00};
    datagram.insert(datagram.end(), ipv4.begin(), ipv4.end());
    auto decoded = lte::enb::gtpu::Decode(datagram.data(), datagram.size());
    REQUIRE(decoded.sequenceNumber.has_value());
    CHECK(*decoded.sequenceNumber == 0x1234);
    CHECK(decoded.extensionTypes == std::vector<uint8_t>{0xC0});
    CHECK(decoded.payload == ipv4);
}

TEST_CASE("lte/user-plane/gtpu: malformed flags, lengths, types and extension chains are rejected")
{
    auto ipv4 = Ipv4();
    auto valid = lte::enb::gtpu::EncodeTPdu(1, ipv4.data(), ipv4.size());
    auto bad = valid;
    bad[0] = 0x50;
    CHECK_THROWS(lte::enb::gtpu::Decode(bad.data(), bad.size()));
    bad = valid;
    bad[0] = 0x20;
    CHECK_THROWS(lte::enb::gtpu::Decode(bad.data(), bad.size()));
    bad = valid;
    bad[1] = 3;
    CHECK_THROWS(lte::enb::gtpu::Decode(bad.data(), bad.size()));
    CHECK_THROWS(lte::enb::gtpu::Decode(valid.data(), valid.size() - 1));
    bad = valid;
    bad[2] = 0x01;
    CHECK_THROWS(lte::enb::gtpu::Decode(bad.data(), bad.size()));

    std::vector<uint8_t> unknownExtension{0x34, 0xFF, 0x00, 0x18, 0, 0, 0, 1, 0, 0, 0, 0x99};
    unknownExtension.insert(unknownExtension.end(), ipv4.begin(), ipv4.end());
    CHECK_THROWS(lte::enb::gtpu::Decode(unknownExtension.data(), unknownExtension.size()));
    std::vector<uint8_t> malformedExtension{0x34, 0xFF, 0x00, 0x1C, 0, 0, 0, 1,
                                            0, 0, 0, 0xC0, 0, 0, 0, 0};
    malformedExtension.insert(malformedExtension.end(), ipv4.begin(), ipv4.end());
    CHECK_THROWS(lte::enb::gtpu::Decode(malformedExtension.data(), malformedExtension.size()));
}

TEST_CASE("lte/user-plane/gtpu: Echo Response preserves sequence and is not a T-PDU")
{
    auto response = lte::enb::gtpu::EncodeEchoResponse(0xBEEF);
    auto decoded = lte::enb::gtpu::Decode(response.data(), response.size());
    CHECK(decoded.messageType == lte::enb::gtpu::EchoResponse);
    REQUIRE(decoded.sequenceNumber.has_value());
    CHECK(*decoded.sequenceNumber == 0xBEEF);
    CHECK(decoded.teid == 0);
}

TEST_CASE("lte/user-plane/gtpu: local UDP peer receives the genuine encoded wire datagram")
{
    udp::UdpServer receiver("127.0.0.1", 0);
    udp::UdpServer sender("127.0.0.1", 0);
    auto ipv4 = Ipv4();
    auto encoded = lte::enb::gtpu::EncodeTPdu(0x10203040, ipv4.data(), ipv4.size());
    REQUIRE(sender.TrySend(receiver.LocalAddress(), encoded.data(), encoded.size()));
    std::vector<uint8_t> wire(256);
    InetAddress peer;
    const int received = receiver.Receive(wire.data(), wire.size(), 1000, peer);
    REQUIRE(received == static_cast<int>(encoded.size()));
    auto decoded = lte::enb::gtpu::Decode(wire.data(), static_cast<size_t>(received));
    CHECK(decoded.teid == 0x10203040);
    CHECK(decoded.payload == ipv4);
}

TEST_CASE("lte/user-plane/bearer: SGW TEID is uplink and eNB TEID is downlink")
{
    lte::enb::DefaultBearerContext bearer;
    bearer.establish(Parameters());
    bearer.activateUe(1, 5, {10, 45, 0, 2});
    auto uplink = Ipv4();
    auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2});
    CHECK_NOTHROW(bearer.validateUplink(1, uplink.data(), uplink.size()));
    CHECK_NOTHROW(bearer.validateDownlink(0x01020304, downlink.data(), downlink.size()));
    CHECK(bearer.parameters().sgwTeid == 0xA1A2A3A4);
    CHECK_THROWS(bearer.validateDownlink(0xA1A2A3A4, downlink.data(), downlink.size()));
}

TEST_CASE("lte/user-plane/bearer: identity, EBI, address, duplicate and released contexts fail closed")
{
    lte::enb::DefaultBearerContext bearer;
    bearer.establish(Parameters());
    CHECK_THROWS(bearer.establish(Parameters(9)));
    CHECK_THROWS(bearer.activateUe(2, 5, {10, 45, 0, 2}));
    CHECK_THROWS(bearer.activateUe(1, 6, {10, 45, 0, 2}));
    bearer.activateUe(1, 5, {10, 45, 0, 2});
    auto wrongSource = Ipv4({10, 45, 0, 3}, {10, 45, 0, 1});
    auto wrongDestination = Ipv4({10, 45, 0, 1}, {10, 45, 0, 3});
    CHECK_THROWS(bearer.validateUplink(1, wrongSource.data(), wrongSource.size()));
    CHECK_THROWS(bearer.validateDownlink(0x01020304, wrongDestination.data(), wrongDestination.size()));
    bearer.release();
    CHECK_FALSE(bearer.active());
    CHECK_THROWS(bearer.validateUplink(1, wrongSource.data(), wrongSource.size()));

    bearer.establish(Parameters(0x05060708));
    bearer.activateUe(1, 5, {10, 45, 0, 2});
    auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2});
    CHECK_THROWS(bearer.validateDownlink(0x01020304, downlink.data(), downlink.size()));
}

TEST_CASE("lte/user-plane/radio-link: NAS, data, readiness and direction remain distinct")
{
    using M = lte::ue::link::Message;
    using T = lte::ue::link::MessageType;
    for (const M &input : {M{T::NAS_UPLINK, 1, {1}}, M{T::NAS_DOWNLINK, 1, {2}},
                           M{T::DATA_UPLINK, 1, Ipv4()}, M{T::DATA_DOWNLINK, 1, Ipv4()},
                           M{T::BEARER_READY, 1, {5, 10, 45, 0, 2}}, M{T::BEARER_RELEASED, 1, {5}}})
    {
        auto wire = lte::ue::link::Encode(input);
        auto decoded = lte::ue::link::Decode(wire.data(), wire.size());
        CHECK(decoded.type == input.type);
        CHECK(decoded.payload == input.payload);
    }
    CHECK(lte::ue::link::IsUplink(T::DATA_UPLINK));
    CHECK_FALSE(lte::ue::link::IsUplink(T::DATA_DOWNLINK));
    CHECK(lte::ue::link::IsDownlink(T::DATA_DOWNLINK));
    CHECK_THROWS(lte::ue::link::Encode({T::BEARER_READY, 1, {5, 10}}));
    CHECK_THROWS(lte::ue::link::Encode({static_cast<T>(99), 1, {1}}));
    std::vector<uint8_t> oversized(lte::ue::link::MaxDataPduSize + 1, 0);
    CHECK_THROWS(lte::ue::link::Encode({T::DATA_UPLINK, 1, oversized}));
}

TEST_CASE("lte/user-plane/ipv4: header, lengths, addresses and fragments are validated")
{
    auto packet = Ipv4();
    auto info = lte::ip::Validate(packet.data(), packet.size());
    CHECK(info.source == std::array<uint8_t, 4>{10, 45, 0, 2});
    CHECK(info.destination == std::array<uint8_t, 4>{10, 45, 0, 1});
    CHECK_FALSE(info.fragmented);
    auto bad = packet;
    bad[0] = 0x65;
    CHECK_THROWS(lte::ip::Validate(bad.data(), bad.size()));
    bad = packet;
    bad[0] = 0x44;
    CHECK_THROWS(lte::ip::Validate(bad.data(), bad.size()));
    bad = packet;
    bad[3] = 21;
    CHECK_THROWS(lte::ip::Validate(bad.data(), bad.size()));
    packet[6] = 0x20;
    CHECK(lte::ip::Validate(packet.data(), packet.size()).fragmented);
}

TEST_CASE("lte/user-plane/tun: descriptor I/O preserves a complete packet without privileges")
{
    int descriptors[2]{};
    REQUIRE(pipe(descriptors) == 0);
    auto packet = Ipv4();
    REQUIRE(lte::ue::TunDevice::WriteToFd(descriptors[1], packet.data(), packet.size()));
    std::vector<uint8_t> received;
    REQUIRE(lte::ue::TunDevice::ReadFromFd(descriptors[0], received));
    CHECK(received == packet);
    close(descriptors[0]);
    close(descriptors[1]);
}
