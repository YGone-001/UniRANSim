//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/tft.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace
{

// Captured from a real Open5GS MME E-RAB Setup Request during Phase 7
// laboratory work. The enclosing NAS Activate Dedicated EPS Bearer Context
// Request carried EBI 6 linked to default EBI 5, QCI 7, and this TFT. Keeping
// the exact octets in the test means the decoder is validated against the
// network, not against the encoder's own idea of the format.
const std::vector<uint8_t> CapturedTft{0x22, 0x20, 0x00, 0x11, 0x30, 0x11, 0x10, 0x00, 0x00, 0x00,
                                       0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x40, 0x1B, 0x58, 0x50, 0x13,
                                       0x88, 0x11, 0x01, 0x08, 0x30, 0x11, 0x50, 0x1B, 0x58, 0x40,
                                       0x13, 0x88};

std::vector<uint8_t> UdpPacket(uint16_t sourcePort, uint16_t destinationPort,
                               std::array<uint8_t, 4> source = {10, 45, 0, 2},
                               std::array<uint8_t, 4> destination = {192, 168, 64, 128})
{
    std::vector<uint8_t> packet(28, 0);
    packet[0] = 0x45;
    packet[2] = 0x00;
    packet[3] = 0x1C;
    packet[8] = 64;
    packet[9] = 17;
    std::copy(source.begin(), source.end(), packet.begin() + 12);
    std::copy(destination.begin(), destination.end(), packet.begin() + 16);
    packet[20] = static_cast<uint8_t>(sourcePort >> 8U);
    packet[21] = static_cast<uint8_t>(sourcePort & 0xFFU);
    packet[22] = static_cast<uint8_t>(destinationPort >> 8U);
    packet[23] = static_cast<uint8_t>(destinationPort & 0xFFU);
    packet[24] = 0x00;
    packet[25] = 0x08;
    return packet;
}

std::vector<uint8_t> TcpPacket(uint16_t sourcePort, uint16_t destinationPort)
{
    auto packet = UdpPacket(sourcePort, destinationPort);
    packet[9] = 6;
    return packet;
}

} // namespace

TEST_CASE("lte/tft: a network-captured TFT decodes into two directed filters")
{
    const auto tft = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());

    CHECK(tft.operation == lte::tft::OperationCode::CREATE_NEW);
    CHECK_FALSE(tft.parametersPresent);
    REQUIRE(tft.filters.size() == 2);

    const auto &uplink = tft.filters[0];
    CHECK(uplink.identifier == 0);
    CHECK(uplink.precedence == 0);
    CHECK(uplink.direction == lte::tft::FilterDirection::UPLINK_ONLY);
    REQUIRE(uplink.hasProtocol);
    CHECK(uplink.protocol == 17);
    REQUIRE(uplink.hasRemoteAddress);
    CHECK(uplink.remoteAddress == std::array<uint8_t, 4>{0, 0, 0, 0});
    CHECK(uplink.remoteMask == std::array<uint8_t, 4>{255, 255, 255, 255});
    REQUIRE(uplink.hasLocalPort);
    CHECK(uplink.localPortLow == 7000);
    CHECK(uplink.localPortHigh == 7000);
    REQUIRE(uplink.hasRemotePort);
    CHECK(uplink.remotePortLow == 5000);
    CHECK(uplink.remotePortHigh == 5000);

    const auto &downlink = tft.filters[1];
    CHECK(downlink.identifier == 1);
    CHECK(downlink.precedence == 1);
    CHECK(downlink.direction == lte::tft::FilterDirection::DOWNLINK_ONLY);
    REQUIRE(downlink.hasProtocol);
    CHECK(downlink.protocol == 17);
    CHECK_FALSE(downlink.hasRemoteAddress);
    REQUIRE(downlink.hasLocalPort);
    CHECK(downlink.localPortLow == 5000);
    REQUIRE(downlink.hasRemotePort);
    CHECK(downlink.remotePortLow == 7000);
}

TEST_CASE("lte/tft: encode and decode round-trip the captured filter semantics")
{
    // The encoder emits components in a fixed order, so the octets need not be
    // byte-identical to the capture. What must survive is the meaning.
    const auto original = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());
    const auto encoded = lte::tft::Encode(original);
    const auto roundTripped = lte::tft::Decode(encoded.data(), encoded.size());

    CHECK(roundTripped.operation == original.operation);
    REQUIRE(roundTripped.filters.size() == original.filters.size());
    for (size_t i = 0; i < original.filters.size(); ++i)
    {
        const auto &a = original.filters[i];
        const auto &b = roundTripped.filters[i];
        CHECK(a.identifier == b.identifier);
        CHECK(a.precedence == b.precedence);
        CHECK(a.direction == b.direction);
        CHECK(a.hasProtocol == b.hasProtocol);
        CHECK(a.protocol == b.protocol);
        CHECK(a.hasRemoteAddress == b.hasRemoteAddress);
        CHECK(a.remoteAddress == b.remoteAddress);
        CHECK(a.remoteMask == b.remoteMask);
        CHECK(a.hasLocalPort == b.hasLocalPort);
        CHECK(a.localPortLow == b.localPortLow);
        CHECK(a.localPortHigh == b.localPortHigh);
        CHECK(a.hasRemotePort == b.hasRemotePort);
        CHECK(a.remotePortLow == b.remotePortLow);
        CHECK(a.remotePortHigh == b.remotePortHigh);
    }
}

TEST_CASE("lte/tft: the uplink filter selects only the matching uplink flow")
{
    const auto tft = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());

    // The captured uplink filter names local port 7000 and remote port 5000.
    const auto matching = UdpPacket(7000, 5000);
    const auto *filter = lte::tft::Classify(tft.filters, matching.data(), matching.size(), true);
    REQUIRE(filter != nullptr);
    CHECK(filter->identifier == 0);

    const auto wrongLocalPort = UdpPacket(7001, 5000);
    CHECK(lte::tft::Classify(tft.filters, wrongLocalPort.data(), wrongLocalPort.size(), true) == nullptr);

    const auto wrongRemotePort = UdpPacket(7000, 5001);
    CHECK(lte::tft::Classify(tft.filters, wrongRemotePort.data(), wrongRemotePort.size(), true) == nullptr);
}

TEST_CASE("lte/tft: a filter direction excludes the other direction")
{
    const auto tft = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());

    // The captured filters mirror each other: filter 0 is uplink-only with local
    // 7000 and remote 5000, filter 1 is downlink-only with local 5000 and remote
    // 7000. The same 5-tuple therefore resolves to a different filter per
    // direction, which is exactly the behaviour the direction field governs.
    const auto packet = UdpPacket(7000, 5000);

    const auto *uplink = lte::tft::Classify(tft.filters, packet.data(), packet.size(), true);
    REQUIRE(uplink != nullptr);
    CHECK(uplink->identifier == 0);

    const auto *downlink = lte::tft::Classify(tft.filters, packet.data(), packet.size(), false);
    REQUIRE(downlink != nullptr);
    CHECK(downlink->identifier == 1);

    const auto unrelated = UdpPacket(1111, 2222);
    CHECK(lte::tft::Classify(tft.filters, unrelated.data(), unrelated.size(), true) == nullptr);
    CHECK(lte::tft::Classify(tft.filters, unrelated.data(), unrelated.size(), false) == nullptr);
}

TEST_CASE("lte/tft: a non-UDP packet never matches a UDP filter")
{
    const auto tft = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());

    const auto tcp = TcpPacket(7000, 5000);
    CHECK(lte::tft::Classify(tft.filters, tcp.data(), tcp.size(), true) == nullptr);
}

TEST_CASE("lte/tft: duplicate packet filter identifiers are rejected")
{
    // Two filters that both claim identifier 1 inside one TFT.
    const std::vector<uint8_t> duplicated{0x22, 0x10, 0x00, 0x03, 0x30, 0x11,
                                          0x10, 0x01, 0x03, 0x30, 0x11};

    CHECK_THROWS_AS(lte::tft::Decode(duplicated.data(), duplicated.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: trailing octets after the packet filter list are rejected")
{
    auto extended = CapturedTft;
    extended.push_back(0x00);

    CHECK_THROWS_AS(lte::tft::Decode(extended.data(), extended.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: an unsupported operation code is rejected")
{
    auto invalid = CapturedTft;
    invalid[0] = static_cast<uint8_t>((0x07U << 5U) | 0x02U);

    CHECK_THROWS_AS(lte::tft::Decode(invalid.data(), invalid.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: a parameters list is rejected instead of being ignored")
{
    auto withParameters = CapturedTft;
    withParameters[0] = static_cast<uint8_t>(withParameters[0] | 0x10U);

    CHECK_THROWS_AS(lte::tft::Decode(withParameters.data(), withParameters.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: an unknown packet filter component is rejected")
{
    // One filter whose only component uses a type this implementation does not
    // support. Accepting it would silently widen the flow.
    const std::vector<uint8_t> unknown{0x11, 0x20, 0x00, 0x03, 0x99, 0x01, 0x00};

    CHECK_THROWS_AS(lte::tft::Decode(unknown.data(), unknown.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: a truncated component is rejected")
{
    // Filter claims a 5-octet component but only 2 octets follow.
    const std::vector<uint8_t> truncated{0x11, 0x20, 0x00, 0x05, 0x10, 0x00, 0x00};

    CHECK_THROWS_AS(lte::tft::Decode(truncated.data(), truncated.size()), lte::tft::TftError);
}

TEST_CASE("lte/tft: evaluation precedence decides between two matching filters")
{
    lte::tft::TrafficFlowTemplate tft;
    tft.operation = lte::tft::OperationCode::CREATE_NEW;

    lte::tft::PacketFilter high;
    high.identifier = 1;
    high.precedence = 5;
    high.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    high.hasProtocol = true;
    high.protocol = 17;

    lte::tft::PacketFilter low;
    low.identifier = 2;
    low.precedence = 1;
    low.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    low.hasProtocol = true;
    low.protocol = 17;

    // Both match every UDP uplink packet, so precedence alone decides.
    tft.filters = {high, low};

    const auto packet = UdpPacket(1234, 5678);
    const auto *filter = lte::tft::Classify(tft.filters, packet.data(), packet.size(), true);
    REQUIRE(filter != nullptr);
    CHECK(filter->identifier == 2);
}

TEST_CASE("lte/tft: a port range filter matches inside the range only")
{
    lte::tft::TrafficFlowTemplate tft;
    tft.operation = lte::tft::OperationCode::CREATE_NEW;

    lte::tft::PacketFilter ranged;
    ranged.identifier = 3;
    ranged.precedence = 0;
    ranged.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    ranged.hasLocalPort = true;
    ranged.localPortLow = 5000;
    ranged.localPortHigh = 5009;
    tft.filters = {ranged};

    const auto inside = UdpPacket(5005, 1);
    CHECK(lte::tft::Classify(tft.filters, inside.data(), inside.size(), true) != nullptr);

    const auto belowRange = UdpPacket(4999, 1);
    CHECK(lte::tft::Classify(tft.filters, belowRange.data(), belowRange.size(), true) == nullptr);

    const auto aboveRange = UdpPacket(5010, 1);
    CHECK(lte::tft::Classify(tft.filters, aboveRange.data(), aboveRange.size(), true) == nullptr);
}

TEST_CASE("lte/tft: a remote address filter is applied against the peer address")
{
    lte::tft::TrafficFlowTemplate tft;
    tft.operation = lte::tft::OperationCode::CREATE_NEW;

    lte::tft::PacketFilter addressed;
    addressed.identifier = 4;
    addressed.precedence = 0;
    addressed.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    addressed.hasRemoteAddress = true;
    addressed.remoteAddress = {192, 168, 64, 0};
    addressed.remoteMask = {255, 255, 255, 0};
    tft.filters = {addressed};

    const auto inSubnet = UdpPacket(1, 2, {10, 45, 0, 2}, {192, 168, 64, 77});
    CHECK(lte::tft::Classify(tft.filters, inSubnet.data(), inSubnet.size(), true) != nullptr);

    const auto outOfSubnet = UdpPacket(1, 2, {10, 45, 0, 2}, {192, 168, 65, 77});
    CHECK(lte::tft::Classify(tft.filters, outOfSubnet.data(), outOfSubnet.size(), true) == nullptr);
}

TEST_CASE("lte/tft: create new replaces a previously accumulated filter set")
{
    lte::tft::TftState state;

    auto first = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());
    state.apply(first);
    CHECK(state.size() == 2);

    lte::tft::TrafficFlowTemplate replacement;
    replacement.operation = lte::tft::OperationCode::CREATE_NEW;
    lte::tft::PacketFilter only;
    only.identifier = 9;
    only.precedence = 0;
    only.direction = lte::tft::FilterDirection::BIDIRECTIONAL;
    replacement.filters = {only};
    state.apply(replacement);

    REQUIRE(state.size() == 1);
    CHECK(state.filters()[0].identifier == 9);
}

TEST_CASE("lte/tft: add appends and delete removes exactly one filter")
{
    lte::tft::TftState state;
    auto initial = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());
    state.apply(initial);

    lte::tft::TrafficFlowTemplate added;
    added.operation = lte::tft::OperationCode::ADD_FILTERS;
    lte::tft::PacketFilter extra;
    extra.identifier = 7;
    extra.precedence = 2;
    extra.direction = lte::tft::FilterDirection::UPLINK_ONLY;
    added.filters = {extra};
    state.apply(added);
    CHECK(state.size() == 3);

    lte::tft::TrafficFlowTemplate deleted;
    deleted.operation = lte::tft::OperationCode::DELETE_FILTERS;
    deleted.filters = {extra};
    state.apply(deleted);

    REQUIRE(state.size() == 2);
    CHECK(std::none_of(state.filters().begin(), state.filters().end(),
                       [](const lte::tft::PacketFilter &filter) { return filter.identifier == 7; }));
}

TEST_CASE("lte/tft: adding a filter identifier that already exists is rejected")
{
    lte::tft::TftState state;
    auto initial = lte::tft::Decode(CapturedTft.data(), CapturedTft.size());
    state.apply(initial);

    lte::tft::TrafficFlowTemplate duplicate;
    duplicate.operation = lte::tft::OperationCode::ADD_FILTERS;
    duplicate.filters = {initial.filters[0]};

    CHECK_THROWS_AS(state.apply(duplicate), lte::tft::TftError);
    CHECK(state.size() == 2);
}
