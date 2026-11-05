//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "log_capture.hpp"

#include <ext/doctest/doctest.h>

#include <lte/enb/gtpu.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace
{

using lte::enb::BearerParameters;
using lte::enb::EnbUeEntry;
using lte::enb::RetiredTeidLedger;
using lte::enb::S1uEndpoint;
using lte::enb::UeRegistry;
namespace gtpu = lte::enb::gtpu;

// The exact eight octets of the genuine Open5GS SGW-U End Marker captured in
// the Phase 15 campaign (artifacts/p15-campaign/run-p15-20261103-131408/gtpu.pcap,
// frame 8). It is the reference for what this implementation must recognise:
// flags 0x30, message type 254, length 0, and the TEID of the tunnel being
// retired carried in the mandatory header.
const std::vector<uint8_t> GenuineOpen5gsEndMarker{0x30, 0xFE, 0x00, 0x00, 0xC6, 0xB5, 0x5B, 0x7A};

// An End Marker on the wire: the mandatory eight-octet header, then the
// optional information-element area, which holds only Private Extension.
std::vector<uint8_t> EndMarkerWire(uint32_t teid, std::vector<uint8_t> ies = {})
{
    std::vector<uint8_t> wire{0x30, gtpu::EndMarker, 0x00, 0x00,
                              static_cast<uint8_t>(teid >> 24U), static_cast<uint8_t>(teid >> 16U),
                              static_cast<uint8_t>(teid >> 8U), static_cast<uint8_t>(teid)};
    wire[2] = static_cast<uint8_t>((ies.size() >> 8U) & 0xFFU);
    wire[3] = static_cast<uint8_t>(ies.size() & 0xFFU);
    wire.insert(wire.end(), ies.begin(), ies.end());
    return wire;
}

// A Private Extension information element, TS 29.281 figure 8.6-1: Type, a
// 16-bit Length, a 16-bit Extension Identifier and the opaque Extension Value.
// Section 8.1 makes Length count everything after the Type and Length fields,
// so it is the Extension Identifier plus the Extension Value and is at least
// two. The whole element is therefore 3 + Length octets.
//
// This helper encodes that shape and nothing else. It is deliberately not used
// by the malformed-vector tests: those build their octets by hand so that a bug
// in a fixture can never be mistaken for the behaviour under test.
std::vector<uint8_t> PrivateExtension(uint16_t identifier, std::vector<uint8_t> value = {})
{
    const size_t length = 2 + value.size();
    std::vector<uint8_t> ie{gtpu::PrivateExtensionType, static_cast<uint8_t>((length >> 8U) & 0xFFU),
                            static_cast<uint8_t>(length & 0xFFU), static_cast<uint8_t>((identifier >> 8U) & 0xFFU),
                            static_cast<uint8_t>(identifier & 0xFFU)};
    ie.insert(ie.end(), value.begin(), value.end());
    return ie;
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

std::vector<uint8_t> GPduWire(uint32_t teid, const std::vector<uint8_t> &payload)
{
    return gtpu::EncodeTPdu(teid, payload.data(), payload.size());
}

// One eNB with a shared S1-U endpoint, a link towards its UEs, and two local
// UDP endpoints standing in for two radio UEs. Everything is loopback with
// ephemeral ports, so a datagram either reaches a UE endpoint or it does not.
struct Lab
{
    udp::UdpServer ueLink{"127.0.0.1", 0};
    udp::UdpServer ueA{"127.0.0.1", 0};
    udp::UdpServer ueB{"127.0.0.1", 0};
    // The identifiers this test wants are supplied *by the allocator*, not
    // assigned to a bearer by hand. `attach` queues the identifier it wants,
    // the registry's allocator returns it, and the binder accepts it because it
    // was reserved. A test can therefore still name a specific TEID on the wire
    // while the production allocation contract is the only route to a live
    // mapping.
    std::deque<uint32_t> teidQueue;
    // The retirement record is bounded. A test lowers that bound to reach the
    // eviction path on exactly the code a bearer runs, and the default is the
    // production capacity so that no other case sees a shorter memory than the
    // eNB does.
    explicit Lab(size_t retiredCapacity = lte::enb::RetiredTeidLedger::DefaultCapacity)
        : registry(8, [this] {
              if (teidQueue.empty())
                  throw lte::enb::TeidExhausted("the test TEID queue is empty");
              const uint32_t value = teidQueue.front();
              teidQueue.pop_front();
              return value;
          }, retiredCapacity)
    {
    }
    UeRegistry registry;
    S1uEndpoint s1u{"127.0.0.1", 0, true, registry, ueLink};

    static constexpr std::array<uint8_t, 4> SgwAddress{127, 0, 0, 9};
    static const InetAddress &SgwPeer()
    {
        static const InetAddress peer{"127.0.0.9", 2152};
        return peer;
    }

    EnbUeEntry &attach(uint32_t radioUeId, const InetAddress &uePeer, uint32_t localTeid)
    {
        teidQueue.push_back(localTeid);
        auto &entry = registry.registerPeer(radioUeId, uePeer);
        const uint32_t allocated = registry.allocateLocalTeid();
        entry.bearer.establish({5, 9, radioUeId, SgwAddress, 0xA1A2A3A4u, allocated});
        entry.bearer.activateUe(radioUeId, 5, {10, 45, 0, static_cast<uint8_t>(radioUeId)});
        registry.bindLocalTeid(entry, entry.bearer.parameters().localTeid);
        // What the multiplexer does once the default bearer is confirmed ready.
        entry.s1 = lte::enb::UeS1State::BEARER_ACTIVE;
        return entry;
    }

    // True when the UE endpoint has a datagram waiting. A GTP-U End Marker must
    // never make this true.
    static bool ueReceived(udp::UdpServer &ue)
    {
        std::array<uint8_t, 512> buffer{};
        InetAddress peer;
        return ue.Receive(buffer.data(), buffer.size(), 0, peer) > 0;
    }
};

// Occurrences of `needle` in a captured production log. The observability cases
// use it to prove that exactly one warning was emitted per dropped packet
// rather than assuming it.
size_t Occurrences(const std::string &text, const std::string &needle)
{
    size_t count = 0;
    for (size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + needle.size()))
        ++count;
    return count;
}

// Every cumulative value the production retired-TEID warning reported, in the
// order it reported them. The value is parsed out of what the real code logged;
// it is never read back from the counter it was printed from, so a case can
// show that the two agree instead of assuming they must.
std::vector<uint64_t> ReportedRetiredTotals(const std::string &text)
{
    const std::string key = "retired-total=";
    std::vector<uint64_t> totals;
    for (size_t at = text.find(key); at != std::string::npos; at = text.find(key, at + key.size()))
        totals.push_back(std::stoull(text.substr(at + key.size())));
    return totals;
}

} // namespace

TEST_CASE("lte/gtpu/end-marker: the genuine captured End Marker decodes as a named tunnel")
{
    const auto decoded = gtpu::Decode(GenuineOpen5gsEndMarker.data(), GenuineOpen5gsEndMarker.size());
    CHECK(decoded.messageType == gtpu::EndMarker);
    CHECK(decoded.teid == 0xC6B55B7AU);
    CHECK_FALSE(decoded.sequenceNumber.has_value());
    CHECK_FALSE(decoded.npduNumber.has_value());
    CHECK(decoded.extensionTypes.empty());
    // An End Marker carries no T-PDU, so it publishes no user-plane payload.
    CHECK(decoded.payload.empty());
    CHECK(decoded.messageType != gtpu::TPdu);
}

TEST_CASE("lte/gtpu/end-marker: an End Marker with a set S flag is refused under the strict LTE profile")
{
    // TS 29.281 V14.0.0 (Release 14) §5.1, Sequence number flag (S): "In an End
    // marker message the S flag shall be set to '0'." V9.3.0 (Release 9) §5.1
    // says nothing about the End Marker at all, so the requirement is a later
    // release's and is adopted here deliberately as the receive profile: a
    // conforming sender never sets it. There is no compatibility switch that
    // keeps the older, laxer reading.
    const std::vector<uint8_t> sequenced{0x32, gtpu::EndMarker, 0x00, 0x04, 0x00, 0x00, 0x10, 0x01,
                                         0x12, 0x34, 0x00, 0x00};
    CHECK_THROWS_AS(gtpu::Decode(sequenced.data(), sequenced.size()), gtpu::CodecError);

    // The same refusal with no optional block at all behind the flag.
    std::vector<uint8_t> bareFlag{0x32, gtpu::EndMarker, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01};
    CHECK_THROWS_AS(gtpu::Decode(bareFlag.data(), bareFlag.size()), gtpu::CodecError);

    // S combined with E is refused too, and so is S combined with PN.
    std::vector<uint8_t> withExtension{0x36, gtpu::EndMarker, 0x00, 0x08, 0x00, 0x00, 0x10, 0x01,
                                       0x00, 0x00, 0x00, 0xC0, 0x01, 0x00, 0x00, 0x00};
    CHECK_THROWS_AS(gtpu::Decode(withExtension.data(), withExtension.size()), gtpu::CodecError);
    std::vector<uint8_t> withNPdu{0x33, gtpu::EndMarker, 0x00, 0x04, 0x00, 0x00, 0x10, 0x01,
                                  0x00, 0x00, 0x7B, 0x00};
    CHECK_THROWS_AS(gtpu::Decode(withNPdu.data(), withNPdu.size()), gtpu::CodecError);

    // A malformed information-element area is still refused when the flag is
    // set: the flag rule is a header rule and is applied before anything else
    // is interpreted, so the outcome does not depend on which defect is found
    // first.
    std::vector<uint8_t> both{0x32, gtpu::EndMarker, 0x00, 0x02, 0x00, 0x00, 0x10, 0x01,
                              0xFF, 0x02};
    CHECK_THROWS_AS(gtpu::Decode(both.data(), both.size()), gtpu::CodecError);

    // The endpoint refuses it as a malformed datagram and no bearer moves.
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00001001U);
    lab.s1u.handleDatagram(sequenced.data(), sequenced.size(), Lab::SgwPeer());
    CHECK(lab.s1u.counters().malformedDrops == 1);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK(entry.bearer.active());
    CHECK_FALSE(lab.ueReceived(lab.ueA));

    // The rule is specific to the End Marker. A G-PDU and an Echo may carry a
    // sequence number, and their handling is unchanged.
    const auto payload = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto plain = gtpu::EncodeTPdu(0x00001001U, payload.data(), payload.size());
    std::vector<uint8_t> sequencedGpdu{0x32, gtpu::TPdu, 0x00, 0x04, 0x00, 0x00, 0x10, 0x01,
                                       0x00, 0x01, 0x00, 0x00};
    sequencedGpdu.insert(sequencedGpdu.end(), payload.begin(), payload.end());
    sequencedGpdu[2] = static_cast<uint8_t>(((sequencedGpdu.size() - 8) >> 8U) & 0xFFU);
    sequencedGpdu[3] = static_cast<uint8_t>((sequencedGpdu.size() - 8) & 0xFFU);
    const auto decodedGpdu = gtpu::Decode(sequencedGpdu.data(), sequencedGpdu.size());
    REQUIRE(decodedGpdu.sequenceNumber.has_value());
    CHECK(*decodedGpdu.sequenceNumber == 0x0001);
    CHECK(decodedGpdu.payload.size() == payload.size());
    (void)plain;
}

TEST_CASE("lte/gtpu/end-marker: the optional-header forms decode and the malformed header is rejected")
{
    // E flag with one supported extension header, then no information elements.
    std::vector<uint8_t> extended{0x34, gtpu::EndMarker, 0x00, 0x08, 0x00, 0x00, 0x10, 0x02,
                                  0x00, 0x00, 0x00, 0xC0, 0x01, 0x00, 0x00, 0x00};
    auto decoded = gtpu::Decode(extended.data(), extended.size());
    CHECK(decoded.extensionTypes == std::vector<uint8_t>{0xC0});
    CHECK(decoded.teid == 0x00001002U);
    CHECK(decoded.payload.empty());

    // PN flag with an N-PDU number. No End Marker-specific rule restricts it,
    // so the general §5.1 parsing stands.
    std::vector<uint8_t> npdu{0x31, gtpu::EndMarker, 0x00, 0x04, 0x00, 0x00, 0x10, 0x03,
                              0x00, 0x00, 0x7B, 0x00};
    decoded = gtpu::Decode(npdu.data(), npdu.size());
    REQUIRE(decoded.npduNumber.has_value());
    CHECK(*decoded.npduNumber == 0x7B);
    CHECK(decoded.payload.empty());

    auto wire = EndMarkerWire(0x00001003U);
    auto bad = wire;
    bad[4] = bad[5] = bad[6] = bad[7] = 0; // zero TEID
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);
    bad = wire;
    bad[2] = 0x01; // declared length disagrees with the datagram
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);
    CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size() - 1), gtpu::CodecError);
    bad = wire;
    bad[0] = 0x50; // unsupported version
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);
    bad = wire;
    bad[0] = 0x20; // protocol-type bit clear
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);
    bad = wire;
    bad[0] = 0x38; // reserved flag set
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);
    CHECK_THROWS_AS(gtpu::Decode(nullptr, 0), gtpu::CodecError);
    std::vector<uint8_t> truncated(7, 0x30);
    CHECK_THROWS_AS(gtpu::Decode(truncated.data(), truncated.size()), gtpu::CodecError);

    // The optional block is required exactly when one of E, S or PN is set.
    // PN is used here rather than S, because a set S flag on an End Marker is
    // already refused as a header rule of its own.
    bad = wire;
    bad[0] = 0x31;
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);

    // A declared optional block that is shorter than the four octets it needs.
    std::vector<uint8_t> shortOptional{0x31, gtpu::EndMarker, 0x00, 0x02, 0x00, 0x00, 0x10, 0x04,
                                       0x12, 0x34};
    CHECK_THROWS_AS(gtpu::Decode(shortOptional.data(), shortOptional.size()), gtpu::CodecError);

    // A datagram larger than any message the length field can describe.
    std::vector<uint8_t> oversized(70000, 0);
    oversized[0] = 0x30;
    oversized[1] = gtpu::EndMarker;
    CHECK_THROWS_AS(gtpu::Decode(oversized.data(), oversized.size()), gtpu::CodecError);
    oversized[1] = gtpu::TPdu;
    CHECK_THROWS_AS(gtpu::Decode(oversized.data(), oversized.size()), gtpu::CodecError);
}

// Builds an End Marker whose information-element area is exactly `ies`. The
// outer length is derived, so a test that wants a mismatch has to corrupt it on
// purpose.
std::vector<uint8_t> EndMarkerWith(std::vector<uint8_t> ies, uint32_t teid = 0x00001001U)
{
    return EndMarkerWire(teid, std::move(ies));
}

TEST_CASE("lte/gtpu/private-extension: a well-formed Private Extension decodes and never becomes user data")
{
    // Independent hard-coded wire vectors. They are written octet by octet
    // rather than produced by the fixture helper, so a defect in the helper
    // cannot pass as correct behaviour. All of these are synthetic protocol
    // vectors: none of them was observed in an Open5GS capture. The one vector
    // that was is GenuineOpen5gsEndMarker, and it carries no information
    // element at all.

    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00001001U);

    // A genuine eight-octet End Marker with no information element.
    const std::vector<uint8_t> noIe{0x30, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01};
    // The minimal valid Private Extension: Type 0xFF, Length 2, Extension
    // Identifier 0x1234, and an empty Extension Value. Octets 6-m of figure
    // 8.6-1 are absent because Length stops at the identifier.
    const std::vector<uint8_t> minimal{0x30, 0xFE, 0x00, 0x05, 0x00, 0x00, 0x10, 0x01,
                                       0xFF, 0x00, 0x02, 0x12, 0x34};
    // Length 4: the same identifier and a two-octet Extension Value. This is
    // the worked example the specification layout implies.
    const std::vector<uint8_t> withValue{0x30, 0xFE, 0x00, 0x07, 0x00, 0x00, 0x10, 0x01,
                                         0xFF, 0x00, 0x04, 0x12, 0x34, 0xAA, 0xBB};
    // Two complete Private Extensions concatenated, which 8.6 permits. The
    // first occupies 3 + 2 and the second 3 + 3 octets, so the information
    // element area is eleven octets long.
    const std::vector<uint8_t> twice{0x30, 0xFE, 0x00, 0x0B, 0x00, 0x00, 0x10, 0x01,
                                     0xFF, 0x00, 0x02, 0x00, 0x01, 0xFF, 0x00, 0x03, 0x00, 0x02, 0x07};

    for (const auto &wire : {noIe, minimal, withValue, twice})
    {
        const auto decoded = gtpu::Decode(wire.data(), wire.size());
        CHECK(decoded.messageType == gtpu::EndMarker);
        CHECK(decoded.teid == 0x00001001U);
        // The information-element area of a control message is not user-plane
        // payload and is never published as one.
        CHECK(decoded.payload.empty());

        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        CHECK_FALSE(lab.ueReceived(lab.ueA));
        // Not one byte of user-plane accounting moves for a control message.
        CHECK(entry.counters.s1uDownlinkPackets == 0);
        CHECK(entry.counters.s1uDownlinkBytes == 0);
        CHECK(entry.bearer.counters().downlinkPackets == 0);
        CHECK(entry.bearer.counters().endMarkers > 0);
    }
    CHECK(entry.bearer.active());
    CHECK(lab.s1u.counters().malformedDrops == 0);

    // The Extension Identifier is an IANA Private Enterprise Number in network
    // byte order. It is validated structurally and never interpreted, so what
    // is observable is that a well-formed network-order field is accepted and
    // that one octet short of it is not. That is tested below.
    const std::vector<uint8_t> enterprise{0x30, 0xFE, 0x00, 0x05, 0x00, 0x00, 0x10, 0x01,
                                          0xFF, 0x00, 0x02, 0xAB, 0xCD};
    CHECK_NOTHROW(gtpu::Decode(enterprise.data(), enterprise.size()));
}

TEST_CASE("lte/gtpu/private-extension: the 16-bit length is honoured at its octet boundary")
{
    // Length 255 (0x00FF): the Extension Identifier plus a 253-octet Extension
    // Value. The whole element is 3 + 255 = 258 octets.
    std::vector<uint8_t> at255{0x30, 0xFE, 0x01, 0x02, 0x00, 0x00, 0x10, 0x01,
                               0xFF, 0x00, 0xFF, 0x12, 0x34};
    at255.insert(at255.end(), 253, 0x5A);
    // Length 256 (0x0100): one octet more, which needs both length octets.
    std::vector<uint8_t> at256{0x30, 0xFE, 0x01, 0x03, 0x00, 0x00, 0x10, 0x01,
                               0xFF, 0x01, 0x00, 0x12, 0x34};
    at256.insert(at256.end(), 254, 0x5A);

    REQUIRE(at255.size() == 8 + 3 + 255);
    REQUIRE(at256.size() == 8 + 3 + 256);
    // The declared outer length is the whole information-element area.
    REQUIRE(at255[2] == 0x01);
    REQUIRE(at255[3] == 0x02);
    REQUIRE(at256[2] == 0x01);
    REQUIRE(at256[3] == 0x03);

    for (const auto &wire : {at255, at256})
    {
        const auto decoded = gtpu::Decode(wire.data(), wire.size());
        CHECK(decoded.payload.empty());
        CHECK(decoded.teid == 0x00001001U);
    }

    // The same two wires with the low length octet one smaller declare a value
    // one octet longer than what remains, and are refused.
    auto short255 = at255;
    short255[10] = 0xFE;
    CHECK_THROWS_AS(gtpu::Decode(short255.data(), short255.size()), gtpu::CodecError);
    auto short256 = at256;
    short256[10] = 0xFF;
    CHECK_THROWS_AS(gtpu::Decode(short256.data(), short256.size()), gtpu::CodecError);

    // The largest information-element area the 16-bit outer length can
    // describe: 3 + 0xFFFC = 0xFFFF octets of Private Extension.
    std::vector<uint8_t> largest{0x30, 0xFE, 0xFF, 0xFF, 0x00, 0x00, 0x10, 0x01,
                                 0xFF, 0xFF, 0xFC, 0x12, 0x34};
    largest.insert(largest.end(), 0xFFFCu - 2, 0x5A);
    REQUIRE(largest.size() == 8 + 0xFFFF);
    CHECK_NOTHROW(gtpu::Decode(largest.data(), largest.size()));
    // One octet beyond what the field can describe is refused.
    largest.push_back(0x00);
    CHECK_THROWS_AS(gtpu::Decode(largest.data(), largest.size()), gtpu::CodecError);
}

TEST_CASE("lte/gtpu/private-extension: a malformed Private Extension is refused and disturbs no state")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00001001U);

    // One live G-PDU first, so a later drop has something it must not disturb.
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto live = GPduWire(0x00001001U, downlink);
    lab.s1u.handleDatagram(live.data(), live.size(), Lab::SgwPeer());
    REQUIRE(lab.ueReceived(lab.ueA));
    REQUIRE(entry.counters.s1uDownlinkPackets == 1);
    REQUIRE(entry.bearer.counters().downlinkPackets == 1);

    // Octet by octet, independent of the fixture helper. Each is the
    // information-element area of an otherwise well-formed End Marker.
    const std::vector<std::vector<uint8_t>> malformed{
        // The Phase 16 fixture's shape: a one-octet length and no Extension
        // Identifier. Read against figure 8.6-1 its Length is 0x02AA, which
        // claims 682 octets that are not there.
        {0xFF, 0x02, 0xAA, 0xBB},
        // Type present, both Length octets absent.
        {0xFF},
        // Type and one Length octet present, the second absent.
        {0xFF, 0x00},
        // Length present, the Extension Identifier entirely absent.
        {0xFF, 0x00, 0x02},
        // Extension Identifier one octet short.
        {0xFF, 0x00, 0x02, 0x12},
        // Length zero: shorter than the Extension Identifier it must carry.
        {0xFF, 0x00, 0x00, 0x12, 0x34},
        // Length one: still shorter than the Extension Identifier.
        {0xFF, 0x00, 0x01, 0x12},
        // Declared value longer than what remains.
        {0xFF, 0x00, 0x04, 0x12, 0x34, 0xAA},
        // Extension Value one octet short of its declared length.
        {0xFF, 0x00, 0x05, 0x12, 0x34, 0xAA, 0xBB},
        // A length that claims the whole of the 16-bit space.
        {0xFF, 0xFF, 0xFF, 0x12, 0x34},
        // Wrong Type: a Recovery TV IE is not a Private Extension.
        {0x0E, 0x00, 0x02, 0x12, 0x34},
        // A well-formed Private Extension followed by an unsupported IE.
        {0xFF, 0x00, 0x02, 0x12, 0x34, 0x0E, 0x00, 0x02, 0x56, 0x78},
        // A well-formed Private Extension followed by an incomplete one.
        {0xFF, 0x00, 0x02, 0x12, 0x34, 0xFF},
        // A well-formed Private Extension followed by a truncated second one.
        {0xFF, 0x00, 0x02, 0x12, 0x34, 0xFF, 0x00, 0x02, 0x12},
        // Two complete Private Extensions and then one trailing octet.
        {0xFF, 0x00, 0x02, 0x12, 0x34, 0xFF, 0x00, 0x02, 0x56, 0x78, 0xAA},
    };

    for (const auto &ies : malformed)
    {
        const auto wire = EndMarkerWith(ies);
        CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size()), gtpu::CodecError);
        // The endpoint refuses it as malformed and nothing else moves.
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        CHECK_FALSE(lab.ueReceived(lab.ueA));
    }

    // A well-formed Private Extension embedded in a header that is itself
    // malformed. The header is refused first, and the valid-looking tail buys
    // it nothing.
    const std::vector<uint8_t> validIe{0xFF, 0x00, 0x02, 0x12, 0x34};
    for (const uint8_t flags : {uint8_t{0x20}, uint8_t{0x50}, uint8_t{0x38}, uint8_t{0x00}})
    {
        auto wire = EndMarkerWith(validIe);
        wire[0] = flags;
        CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size()), gtpu::CodecError);
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        CHECK_FALSE(lab.ueReceived(lab.ueA));
    }

    // The outer GTP-U length must describe the datagram exactly, information
    // elements and all.
    {
        auto wire = EndMarkerWith(validIe);
        wire[3] = static_cast<uint8_t>(wire[3] + 1);
        CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size()), gtpu::CodecError);
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        CHECK_FALSE(lab.ueReceived(lab.ueA));
    }
    {
        auto wire = EndMarkerWith(validIe);
        wire[3] = static_cast<uint8_t>(wire[3] - 1);
        CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size()), gtpu::CodecError);
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        CHECK_FALSE(lab.ueReceived(lab.ueA));
    }

    // Every malformed datagram was counted as one and left nothing behind: the
    // bearer is still the bearer it was and the live G-PDU is still counted.
    // Fifteen malformed information-element areas, four malformed flags and two
    // outer-length mismatches.
    CHECK(lab.s1u.counters().malformedDrops == malformed.size() + 6);
    CHECK(entry.counters.s1uDownlinkPackets == 1);
    CHECK(entry.counters.s1uDownlinkBytes == downlink.size());
    CHECK(entry.bearer.counters().downlinkPackets == 1);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK(entry.bearer.active());
    CHECK(entry.bearer.parameters().localTeid == 0x00001001U);
    CHECK(lab.registry.findBearerByLocalTeid(0x00001001U).entry == &entry);
}

TEST_CASE("lte/gtpu/end-marker: the largest T-PDU a length field can describe round-trips")
{
    std::vector<uint8_t> largest(0xFFFF, 0x41);
    largest[0] = 0x45;
    const auto encoded = gtpu::EncodeTPdu(0x00000101U, largest.data(), largest.size());
    const auto decoded = gtpu::Decode(encoded.data(), encoded.size());
    CHECK(decoded.payload.size() == 0xFFFF);
    CHECK(decoded.teid == 0x00000101U);
    // One octet beyond is refused by the encoder, and a datagram that claims
    // more than the field can carry is refused by the decoder.
    CHECK_THROWS_AS(gtpu::EncodeTPdu(0x00000101U, largest.data(), largest.size() + 1), gtpu::CodecError);
}

TEST_CASE("lte/gtpu/end-marker: unsupported message types are still refused"){
    for (const uint8_t type : {0x00, 0x03, 0x20, 0x21, 0x25, 0xFD, 0x0E})
    {
        std::vector<uint8_t> wire{0x30, type, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
        CHECK_THROWS_AS(gtpu::Decode(wire.data(), wire.size()), gtpu::CodecError);
    }
}

TEST_CASE("lte/enb/retired-teid: the ledger records and repeats and is never withdrawn")
{
    RetiredTeidLedger ledger(3);
    CHECK(ledger.capacity() == 3);
    CHECK_THROWS_AS(RetiredTeidLedger(0), std::invalid_argument);
    CHECK_THROWS_AS(ledger.retire(0), std::invalid_argument);

    CHECK(ledger.retire(11));
    CHECK(ledger.retire(12));
    CHECK(ledger.contains(11));
    CHECK(ledger.contains(12));
    CHECK_FALSE(ledger.contains(13));
    // A repeat is a duplicate or a reordered announcement and records nothing.
    CHECK_FALSE(ledger.retire(11));
    CHECK(ledger.size() == 2);
    CHECK(ledger.evictions() == 0);

    // There is deliberately no way to withdraw a record. A retirement stays
    // recorded for as long as the record lasts, so nothing can erase the
    // evidence that a tunnel ended in order to reuse its identifier.
    CHECK(ledger.contains(11));
    CHECK_FALSE(ledger.retire(11));
    CHECK(ledger.contains(11));

    CHECK(ledger.retire(13)); // the ledger is now full
    CHECK(ledger.size() == 3);
    CHECK(ledger.evictions() == 0);
    CHECK(ledger.retire(14)); // evicts the longest-retired record, which is 11
    CHECK(ledger.size() == 3);
    CHECK(ledger.evictions() == 1);
    CHECK_FALSE(ledger.contains(11));
    CHECK(ledger.contains(12));
    CHECK(ledger.contains(13));
    CHECK(ledger.contains(14));
    // The oldest surviving record is the next to go, so the record is an
    // ordered window over the tunnels that ended most recently.
    CHECK(ledger.retire(15));
    CHECK(ledger.size() == 3);
    CHECK(ledger.evictions() == 2);
    CHECK_FALSE(ledger.contains(12));
    CHECK(ledger.contains(13));
    CHECK(ledger.contains(14));
    CHECK(ledger.contains(15));
}

TEST_CASE("lte/enb/retired-teid: a retired identifier is refused as a live binding")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t teid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, teid});
    registry.bindLocalTeid(entry, teid);
    registry.releaseS1(entry);
    REQUIRE(registry.isRetiredTeid(teid));

    // Both binding overloads refuse it. The refusal is specifically the
    // retirement, not merely an unreserved value, and the record is not
    // withdrawn to make room.
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, teid}, true);
    auto refusal = [](const std::function<void()> &call) {
        try
        {
            call();
        }
        catch (const lte::enb::RegistryError &e)
        {
            return std::string(e.what());
        }
        return std::string();
    };
    CHECK(refusal([&] { registry.bindLocalTeid(entry, teid); }).find("retired") != std::string::npos);
    CHECK(refusal([&] { registry.bindLocalTeid(entry, entry.bearer, teid); }).find("retired") != std::string::npos);

    // Failure is atomic: the live index is unchanged and the retired identifier
    // stays unbound.
    CHECK(registry.isRetiredTeid(teid));
    CHECK(registry.findBearerByLocalTeid(teid).entry == nullptr);
    CHECK(registry.retiredTeids().size() == 1);
    CHECK(registry.size() == 1);
    CHECK(entry.s1 == lte::enb::UeS1State::IDLE_RETAINED);
}

TEST_CASE("lte/enb/retired-teid: an identifier this registry never allocated cannot be bound")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t teid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, teid});
    registry.bindLocalTeid(entry, teid);

    // A value chosen by hand is not an identifier this registry ever issued, so
    // it cannot become a live mapping. Without this the binder is an open
    // setter and the allocator's no-reissue guarantee is bypassed by anyone who
    // picks their own number.
    auto &other = registry.registerPeer(2, InetAddress("127.0.0.1", 40002));
    other.bearer.establish({5, 9, 2, {127, 0, 0, 9}, 0xA1A1A1A2u, 0x0000F002U});
    auto refusal = [](const std::function<void()> &call) {
        try
        {
            call();
        }
        catch (const lte::enb::RegistryError &e)
        {
            return std::string(e.what());
        }
        return std::string();
    };
    CHECK(refusal([&] { registry.bindLocalTeid(other, 0x0000F002U); }).find("reserved") != std::string::npos);
    CHECK(refusal([&] { registry.bindLocalTeid(other, other.bearer, 0x0000F002U); }).find("reserved") !=
          std::string::npos);
    // Zero is refused outright, and so is an identifier already owned.
    CHECK_THROWS_AS(registry.bindLocalTeid(other, 0), lte::enb::RegistryError);
    CHECK_THROWS_AS(registry.bindLocalTeid(entry, entry.bearer, teid), lte::enb::RegistryError);
    CHECK(registry.findBearerByLocalTeid(0x0000F002U).entry == nullptr);
    CHECK(registry.findBearerByLocalTeid(teid).entry == &entry);
}

TEST_CASE("lte/enb/retired-teid: release retires every local TEID of the access")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t defaultTeid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, defaultTeid});
    entry.bearer.activateUe(1, 5, {10, 45, 0, 2});
    registry.bindLocalTeid(entry, defaultTeid);
    auto &dedicated = registry.addDedicatedBearer(
        entry, {6, 7, 1, {127, 0, 0, 9}, 0xA1A1A1A2u, registry.allocateLocalTeid(), 5, {9, 15, false, false, {}}});
    const uint32_t dedicatedTeid = dedicated.parameters().localTeid;
    registry.bindLocalTeid(entry, dedicated, dedicatedTeid);
    REQUIRE_FALSE(registry.isRetiredTeid(defaultTeid));
    REQUIRE_FALSE(registry.isRetiredTeid(dedicatedTeid));

    registry.releaseS1(entry);
    CHECK(registry.findByLocalTeid(defaultTeid) == nullptr);
    CHECK(registry.findByLocalTeid(dedicatedTeid) == nullptr);
    CHECK(registry.isRetiredTeid(defaultTeid));
    CHECK(registry.isRetiredTeid(dedicatedTeid));
    // The logical EPS bearers survive the access release; only the transport
    // is retired.
    CHECK(entry.bearer.logicalExists());
    CHECK(dedicated.logicalExists());

    registry.deleteBearerContexts(entry);
    CHECK(registry.isRetiredTeid(defaultTeid));
    CHECK_FALSE(entry.bearer.logicalExists());
}

TEST_CASE("lte/enb/retired-teid: the allocator never offers a live or a retired identifier")
{
    // A deliberately pathological allocator that offers back values the
    // registry must refuse: zero, one that is already retired and one that is
    // still live. The production sequence can never do this — it is monotonic
    // and spends every step at most once — so the case exists to hold the
    // registry's own defence in place against an allocator that does.
    std::vector<uint32_t> offered{0, 7, 42, 0, 7, 42, 0, 100};
    size_t next = 0;
    UeRegistry registry(8, [&] {
        const uint32_t value = next < offered.size() ? offered[next] : 1000U + static_cast<uint32_t>(next);
        ++next;
        return value;
    });

    // The zero offer is skipped and the first real value is handed out.
    auto &first = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t retired = registry.allocateLocalTeid();
    CHECK(retired == 7);
    first.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, retired});
    registry.bindLocalTeid(first, retired);
    registry.releaseS1(first);
    REQUIRE(registry.isRetiredTeid(retired));

    // The next value is free and becomes a live tunnel on another UE.
    auto &second = registry.registerPeer(2, InetAddress("127.0.0.1", 40002));
    const uint32_t live = registry.allocateLocalTeid();
    CHECK(live == 42);
    second.bearer.establish({5, 9, 2, {127, 0, 0, 9}, 0xA1A1A1A2u, live});
    registry.bindLocalTeid(second, live);
    REQUIRE_FALSE(registry.isRetiredTeid(live));

    // Everything the allocator offers from here is zero, retired or live until
    // a free value is reached. None of the refused ones may be returned.
    const uint32_t fresh = registry.allocateLocalTeid();
    CHECK(fresh == 100);
    CHECK(fresh != retired);
    CHECK(fresh != live);
    CHECK(fresh != 0);
    CHECK_FALSE(registry.isRetiredTeid(fresh));
    CHECK(registry.findByLocalTeid(retired) == nullptr);
    CHECK(registry.findByLocalTeid(live) == &second);
}

TEST_CASE("lte/enb/retired-teid: an evicted tombstone still leaves its identifier unreusable")
{
    // A ledger that keeps a single record: retiring a second identifier evicts
    // the first tombstone, so the first is no longer remembered as retired at
    // all. That is the state a long-lived eNB reaches, and the point of this
    // case is that eviction changes nothing about eligibility. The retirement
    // record is an observation aid and the work order forbids leaning on
    // `contains()` alone, so the two things that actually hold are checked
    // instead: the reservation contract refuses the binding, and the allocator
    // never offers the value again.
    lte::enb::TeidSequence sequence{0x00001000U, 8};
    UeRegistry registry(8, [&sequence] { return sequence.next(); }, 1);

    auto &first = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t oldTeid = registry.allocateLocalTeid();
    first.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, oldTeid});
    first.bearer.activateUe(1, 5, {10, 45, 0, 1});
    registry.bindLocalTeid(first, oldTeid);
    registry.releaseS1(first);
    REQUIRE(registry.isRetiredTeid(oldTeid));

    // The second retirement evicts the first record.
    auto &second = registry.registerPeer(2, InetAddress("127.0.0.1", 40002));
    const uint32_t newerTeid = registry.allocateLocalTeid();
    second.bearer.establish({5, 9, 2, {127, 0, 0, 9}, 0xA1A1A1A2u, newerTeid});
    second.bearer.activateUe(2, 5, {10, 45, 0, 2});
    registry.bindLocalTeid(second, newerTeid);
    registry.releaseS1(second);
    REQUIRE(registry.isRetiredTeid(newerTeid));
    REQUIRE_FALSE(registry.isRetiredTeid(oldTeid));
    REQUIRE(registry.retiredTeids().size() == 1);
    REQUIRE(registry.retiredTeids().evictions() == 1);

    // The evicted identifier is still refused as a live binding. The refusal is
    // deliberately no longer the retirement check — that record is gone — but
    // the reservation contract: nothing ever reserves this value again.
    auto refusal = [](const std::function<void()> &call) {
        try
        {
            call();
        }
        catch (const lte::enb::RegistryError &e)
        {
            return std::string(e.what());
        }
        return std::string();
    };
    auto &third = registry.registerPeer(3, InetAddress("127.0.0.1", 40003));
    third.bearer.establish({5, 9, 3, {127, 0, 0, 9}, 0xA1A1A1A3u, oldTeid}, true);
    const std::string message = refusal([&] { registry.bindLocalTeid(third, oldTeid); });
    CHECK(message.find("reserved") != std::string::npos);
    CHECK(registry.findBearerByLocalTeid(oldTeid).entry == nullptr);

    // And the allocator never offers it again whatever the ledger now says. The
    // sequence is monotonic and has already spent that step, so the rest of its
    // window is a set of distinct values none of which is the old one.
    size_t remaining = 0;
    for (;;)
    {
        try
        {
            const uint32_t value = registry.allocateLocalTeid();
            CHECK(value != oldTeid);
            ++remaining;
        }
        catch (const lte::enb::TeidExhausted &)
        {
            break;
        }
    }
    CHECK(remaining == 6);
}

TEST_CASE("lte/enb/retired-teid: ageing a record out cannot disturb an unrelated live tunnel")
{
    RetiredTeidLedger ledger(2);
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t teid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, teid});
    entry.bearer.activateUe(1, 5, {10, 45, 0, 2});
    registry.bindLocalTeid(entry, teid);

    ledger.retire(1);
    ledger.retire(2);
    ledger.retire(3);
    CHECK(ledger.size() == 2);
    CHECK(ledger.evictions() == 1);
    // The live tunnel is untouched by any of it.
    CHECK(registry.findBearerByLocalTeid(teid).entry == &entry);
    CHECK(registry.findBearerByLocalTeid(teid).bearer->active());
}

TEST_CASE("lte/enb/teid-sequence: the whole issuance window is usable and nothing is issued twice")
{
    // The window is the guarantee. Exactly `window` steps are reserved, each
    // step names one 32-bit pattern, and no pattern is produced twice, so the
    // last allocation in the window is as safe as the first. A window that runs
    // into the reserved zero spends that step and does not return it, which is
    // why the returned values are checked for distinctness and non-zero rather
    // than counted blindly against the window.
    constexpr uint64_t window = 32;
    lte::enb::TeidSequence sequence{0x0000A000U, window};
    std::unordered_set<uint32_t> seen;
    for (uint64_t i = 0; i < window; ++i)
    {
        const uint32_t value = sequence.next();
        CHECK(value != 0);
        CHECK(seen.insert(value).second);
    }
    CHECK(seen.size() == window);
    CHECK(sequence.issued() == window);
    // Every value the window can name is inside its span and nothing outside it
    // was ever offered.
    for (const uint32_t value : seen)
    {
        const uint32_t offset = value - 0x0000A000U;
        CHECK(offset >= 1U);
        CHECK(offset <= window);
    }
}

TEST_CASE("lte/enb/teid-sequence: exhaustion fails closed and the window never reopens")
{
    // The step that would have produced the reserved zero is spent rather than
    // returned, so the sequence yields one value fewer than its window and then
    // refuses. That refusal is sticky: the counter is never advanced past the
    // end of the window, so the sequence cannot wrap open again and reissue an
    // identifier a released tunnel used.
    lte::enb::TeidSequence sequence{0xFFFFFFFEU, 4};
    // The four candidates are 0xFFFFFFFF, 0x00000000, 0x00000001 and
    // 0x00000002; the second is reserved and its step is spent.
    CHECK(sequence.next() == 0xFFFFFFFFU);
    CHECK(sequence.next() == 0x00000001U);
    CHECK(sequence.next() == 0x00000002U);
    CHECK(sequence.issued() == 4);

    // Exhaustion is immediate and repeatable: no identifier comes out, no busy
    // loop is entered, and the counter does not move while refusing.
    auto exhausted = [](const std::function<uint32_t()> &call) {
        try
        {
            (void)call();
        }
        catch (const lte::enb::TeidExhausted &)
        {
            return true;
        }
        return false;
    };
    CHECK(exhausted([&] { return sequence.next(); }));
    CHECK(exhausted([&] { return sequence.next(); }));
    CHECK(exhausted([&] { return sequence.next(); }));
    CHECK(sequence.issued() == 4);

    // A window of zero is a configuration error rather than a sequence that
    // quietly issues nothing for ever.
    CHECK_THROWS_AS(lte::enb::TeidSequence(1, 0), std::invalid_argument);
}

TEST_CASE("lte/enb/teid-sequence: concurrent callers never share or lose a step")
{
    // The sequence is the one part of the allocation path that is meant to be
    // shared, and each step is reserved by exactly one caller. The registry
    // around it is not a thread-safe container by design and is not exercised
    // here. Observations are collected first and asserted after the join, so no
    // assertion is made from a worker thread.
    constexpr uint64_t window = 4096;
    constexpr int threadCount = 8;
    lte::enb::TeidSequence sequence{0x0000B000U, window};
    std::vector<std::vector<uint32_t>> perThread(threadCount);
    std::vector<std::thread> workers;
    for (int i = 0; i < threadCount; ++i)
    {
        workers.emplace_back([&sequence, &perThread, i] {
            for (;;)
            {
                try
                {
                    perThread[i].push_back(sequence.next());
                }
                catch (const lte::enb::TeidExhausted &)
                {
                    return;
                }
            }
        });
    }
    for (auto &worker : workers)
        worker.join();

    std::unordered_set<uint32_t> seen;
    size_t total = 0;
    for (const auto &values : perThread)
    {
        for (const uint32_t value : values)
        {
            CHECK(value != 0);
            CHECK(seen.insert(value).second);
            ++total;
        }
    }
    // Every step of the window went to exactly one caller.
    CHECK(total == window);
    CHECK(seen.size() == window);
    CHECK(sequence.issued() == window);
}

TEST_CASE("lte/enb/retired-teid: a dedicated bearer is held to the same allocation contract as the default")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t defaultTeid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, defaultTeid});
    entry.bearer.activateUe(1, 5, {10, 45, 0, 1});
    registry.bindLocalTeid(entry, defaultTeid);

    // A dedicated bearer takes its identifier from the same allocator and binds
    // it through the same validated registration. Neither kind of bearer has a
    // route that skips either step.
    auto &dedicated = registry.addDedicatedBearer(
        entry, {6, 7, 1, {127, 0, 0, 9}, 0xA1A2A3A2u, registry.allocateLocalTeid(), 5, {9, 15, false, false, {}}});
    const uint32_t dedicatedTeid = dedicated.parameters().localTeid;
    REQUIRE(dedicatedTeid != defaultTeid);
    registry.bindLocalTeid(entry, dedicated, dedicatedTeid);

    auto refusal = [](const std::function<void()> &call) {
        try
        {
            call();
        }
        catch (const lte::enb::RegistryError &e)
        {
            return std::string(e.what());
        }
        return std::string();
    };

    // A value chosen by hand is refused for a dedicated bearer exactly as it is
    // for the default one.
    CHECK(refusal([&] { registry.bindLocalTeid(entry, dedicated, 0x0000D001U); }).find("reserved") !=
          std::string::npos);
    // A reserved value that names some other bearer is refused rather than
    // silently replacing the binding this one already holds.
    const uint32_t stray = registry.allocateLocalTeid();
    CHECK(refusal([&] { registry.bindLocalTeid(entry, dedicated, stray); }).find("different") != std::string::npos);
    CHECK(registry.findBearerByLocalTeid(defaultTeid).bearer == &entry.bearer);
    CHECK(registry.findBearerByLocalTeid(dedicatedTeid).bearer == &dedicated);
    CHECK(registry.findBearerByLocalTeid(stray).entry == nullptr);

    // Both kinds retire through the same path on an access release, and neither
    // can be rebound afterwards.
    registry.releaseS1(entry);
    CHECK(registry.isRetiredTeid(defaultTeid));
    CHECK(registry.isRetiredTeid(dedicatedTeid));
    CHECK(refusal([&] { registry.bindLocalTeid(entry, defaultTeid); }).find("retired") != std::string::npos);
    CHECK(refusal([&] { registry.bindLocalTeid(entry, dedicated, dedicatedTeid); }).find("retired") !=
          std::string::npos);
}

TEST_CASE("lte/enb/retired-teid: a failed establishment leaves no reservation and no half-built bearer")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));

    // The establishment reserves an identifier and then fails before it is
    // bound. The rollback drops the reservation without retiring anything: no
    // tunnel of this registry ever existed, so there is nothing to remember as
    // retired and nothing to leave half-built.
    const uint32_t teid = registry.allocateLocalTeid();
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, teid});
    registry.unbindLocalTeid(entry, teid);
    CHECK_FALSE(registry.isRetiredTeid(teid));
    CHECK(registry.findBearerByLocalTeid(teid).entry == nullptr);
    CHECK(registry.retiredTeids().size() == 0);
    CHECK(registry.retiredTeids().evictions() == 0);

    // The identifier is unusable rather than silently reusable: nothing else
    // ever reserved it, so it cannot be bound.
    auto refusal = [](const std::function<void()> &call) {
        try
        {
            call();
        }
        catch (const lte::enb::RegistryError &e)
        {
            return std::string(e.what());
        }
        return std::string();
    };
    CHECK(refusal([&] { registry.bindLocalTeid(entry, teid); }).find("reserved") != std::string::npos);

    // A rollback naming an identifier that is some other entry's live tunnel
    // must not disturb that tunnel at all.
    auto &other = registry.registerPeer(2, InetAddress("127.0.0.1", 40002));
    const uint32_t otherTeid = registry.allocateLocalTeid();
    other.bearer.establish({5, 9, 2, {127, 0, 0, 9}, 0xA1A1A1A2u, otherTeid});
    other.bearer.activateUe(2, 5, {10, 45, 0, 2});
    registry.bindLocalTeid(other, otherTeid);
    registry.unbindLocalTeid(entry, otherTeid);
    CHECK(registry.findBearerByLocalTeid(otherTeid).entry == &other);
    CHECK_FALSE(registry.isRetiredTeid(otherTeid));
    CHECK(other.bearer.active());

    // A rollback of this entry's own live mapping does retire it, because a
    // tunnel existed and its identifier must stop resolving as a known end.
    registry.unbindLocalTeid(other, otherTeid);
    CHECK(registry.isRetiredTeid(otherTeid));
    CHECK(registry.findBearerByLocalTeid(otherTeid).entry == nullptr);
}

TEST_CASE("lte/gtpu/dispatch: a G-PDU is delivered to the UE and an End Marker never is")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00001001U);
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});

    const auto first = GPduWire(0x00001001U, downlink);
    lab.s1u.handleDatagram(first.data(), first.size(), Lab::SgwPeer());
    REQUIRE(lab.ueReceived(lab.ueA));
    CHECK(entry.counters.s1uDownlinkPackets == 1);

    const auto endMarker = EndMarkerWire(0x00001001U);
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    CHECK_FALSE(lab.ueReceived(lab.ueA));
    // Not one byte of user-plane accounting moves for a control message.
    CHECK(entry.counters.s1uDownlinkPackets == 1);
    CHECK(entry.counters.s1uDownlinkBytes == downlink.size());
    CHECK(entry.bearer.counters().downlinkPackets == 1);
    CHECK(entry.bearer.counters().endMarkers == 1);
    CHECK(lab.s1u.counters().endMarkers == 1);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 1);
}

TEST_CASE("lte/gtpu/dispatch: an End Marker on an active tunnel releases nothing and drains nothing")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00002001U);
    const uint32_t generation = entry.accessGeneration;

    const auto endMarker = EndMarkerWire(0x00002001U);
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    // The tunnel is still exactly the tunnel it was. An End Marker is not a
    // release, not a handover and not a bearer transition.
    CHECK(entry.s1 == lte::enb::UeS1State::BEARER_ACTIVE);
    CHECK(entry.accessGeneration == generation);
    CHECK(entry.bearer.active());
    CHECK(entry.bearer.parameters().localTeid == 0x00002001U);
    CHECK(entry.bearer.parameters().sgwTeid == 0xA1A2A3A4U);
    CHECK(lab.registry.size() == 1);
    CHECK(lab.registry.findBearerByLocalTeid(0x00002001U).bearer == &entry.bearer);

    // A G-PDU after the End Marker is still forwarded. TS 29.281 7.3.2 permits
    // a receiver to discard one; this implementation deliberately does not,
    // because releasing an active tunnel on an End Marker alone is out of
    // scope. The choice is recorded here so the limit is testable rather than
    // implied.
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto wire = GPduWire(0x00002001U, downlink);
    lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueA));
    CHECK(entry.counters.s1uDownlinkPackets == 1);
}

TEST_CASE("lte/gtpu/dispatch: a duplicate End Marker on an active tunnel is idempotent")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00003001U);
    const auto endMarker = EndMarkerWire(0x00003001U);

    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    // The repeat is recognised as a repeat. Beyond the two observation counts
    // nothing at all has moved.
    CHECK(entry.bearer.counters().endMarkers == 3);
    CHECK(entry.bearer.counters().duplicateEndMarkers == 2);
    CHECK(entry.bearer.active());
    CHECK(entry.bearer.parameters().localTeid == 0x00003001U);
    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK(entry.counters.s1uUplinkPackets == 0);
    CHECK(entry.counters.simulatedDownlinkPackets == 0);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 3);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/gtpu/dispatch: an End Marker from an unexpected peer is rejected without effect")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00004001U);
    const auto endMarker = EndMarkerWire(0x00004001U);
    const InetAddress stranger{"127.0.0.7", 2152};

    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), stranger);
    CHECK(entry.counters.unexpectedPeerDrops == 1);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 0);
    CHECK(entry.bearer.active());
    CHECK_FALSE(lab.ueReceived(lab.ueA));

    // The right peer is still accepted afterwards, so the rejection disturbed
    // no state that a later legitimate message depends on.
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    CHECK(entry.bearer.counters().endMarkers == 1);
}

TEST_CASE("lte/gtpu/dispatch: a delayed G-PDU for a retired TEID is dropped without touching any state")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00005001U);
    lab.registry.releaseS1(entry);
    REQUIRE(lab.registry.isRetiredTeid(0x00005001U));

    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto wire = GPduWire(0x00005001U, downlink);
    lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().retiredTeidDrops == 1);
    CHECK(lab.s1u.counters().unknownTeidDrops == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
    // Nothing about the retained UE moved: no counters, no transport, no state.
    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK(entry.counters.simulatedDownlinkPackets == 0);
    CHECK(entry.bearer.counters().downlinkPackets == 0);
    CHECK(entry.s1 == lte::enb::UeS1State::IDLE_RETAINED);
    CHECK(entry.bearer.parameters().localTeid == 0);
    CHECK(lab.registry.findBearerByLocalTeid(0x00005001U).entry == nullptr);
}

TEST_CASE("lte/gtpu/dispatch: a delayed G-PDU cannot reach the tunnel a later access opened")
{
    Lab lab;
    auto &entryA = lab.attach(1, lab.ueA.LocalAddress(), 0x00006001U);
    lab.registry.releaseS1(entryA);
    REQUIRE(lab.registry.isRetiredTeid(0x00006001U));

    // A second UE is served on a different identifier. The delayed packet of
    // the first UE's retired tunnel must not reach it.
    auto &entryB = lab.attach(2, lab.ueB.LocalAddress(), 0x00006002U);
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2});
    const auto wire = GPduWire(0x00006001U, downlink);
    lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().retiredTeidDrops == 1);
    CHECK_FALSE(lab.ueReceived(lab.ueB));
    CHECK_FALSE(lab.ueReceived(lab.ueA));
    CHECK(entryB.counters.s1uDownlinkPackets == 0);
    CHECK(entryB.bearer.counters().downlinkPackets == 0);
    CHECK(entryB.bearer.active());
    // The new tunnel still works, so the drop did not damage it either.
    const auto live = GPduWire(0x00006002U, downlink);
    lab.s1u.handleDatagram(live.data(), live.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueB));
    CHECK(entryB.counters.s1uDownlinkPackets == 1);
}

TEST_CASE("lte/gtpu/dispatch: a delayed G-PDU for an evicted TEID still reaches no UE")
{
    // A ledger of one record, so the second retirement evicts the first
    // tombstone. Nothing about that eviction may make the old identifier
    // resolve again: the packet is dropped exactly as it was before the record
    // aged out, and the new tunnel on the same radio endpoint is untouched.
    //
    // The drop is classified as `unknownTeidDrops` rather than
    // `retiredTeidDrops` from here on, because the record that distinguished
    // the two has aged out. That is the documented limit of a bounded
    // observation aid and not a delivery failure.
    Lab lab(1);
    auto &entryA = lab.attach(1, lab.ueA.LocalAddress(), 0x0000B001U);
    lab.registry.releaseS1(entryA);
    REQUIRE(lab.registry.isRetiredTeid(0x0000B001U));
    auto &entryB = lab.attach(2, lab.ueB.LocalAddress(), 0x0000B002U);
    lab.registry.releaseS1(entryB);
    REQUIRE(lab.registry.isRetiredTeid(0x0000B002U));
    REQUIRE_FALSE(lab.registry.isRetiredTeid(0x0000B001U));
    REQUIRE(lab.registry.retiredTeids().evictions() == 1);

    // A new tunnel on the very endpoint the old one used.
    lab.registry.remove(entryA);
    auto &fresh = lab.attach(3, lab.ueA.LocalAddress(), 0x0000B003U);
    REQUIRE(lab.registry.findBearerByLocalTeid(0x0000B003U).entry == &fresh);

    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 3});
    const auto stale = GPduWire(0x0000B001U, downlink);
    lab.s1u.handleDatagram(stale.data(), stale.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().unknownTeidDrops == 1);
    CHECK(lab.s1u.counters().retiredTeidDrops == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
    CHECK(fresh.counters.s1uDownlinkPackets == 0);
    CHECK(fresh.bearer.counters().downlinkPackets == 0);
    CHECK(fresh.bearer.active());
    CHECK(lab.registry.findBearerByLocalTeid(0x0000B001U).entry == nullptr);

    // The new tunnel still carries traffic, so the drop cost it nothing.
    const auto live = GPduWire(0x0000B003U, downlink);
    lab.s1u.handleDatagram(live.data(), live.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueA));
    CHECK(fresh.counters.s1uDownlinkPackets == 1);
}

TEST_CASE("lte/gtpu/dispatch: a delayed End Marker for an evicted TEID moves nothing")
{
    // The same eviction as above, and an End Marker naming the identifier whose
    // record has aged out. An End Marker is an observation and never a state
    // change, so this one must not release the new bearer, not advance an
    // access generation and not start anything.
    Lab lab(1);
    auto &entryA = lab.attach(1, lab.ueA.LocalAddress(), 0x0000C001U);
    lab.registry.releaseS1(entryA);
    REQUIRE(lab.registry.isRetiredTeid(0x0000C001U));
    auto &entryB = lab.attach(2, lab.ueB.LocalAddress(), 0x0000C002U);
    lab.registry.releaseS1(entryB);
    REQUIRE_FALSE(lab.registry.isRetiredTeid(0x0000C001U));
    REQUIRE(lab.registry.retiredTeids().evictions() == 1);

    lab.registry.remove(entryA);
    auto &fresh = lab.attach(3, lab.ueA.LocalAddress(), 0x0000C003U);
    const uint32_t generation = fresh.accessGeneration;
    const auto marker = EndMarkerWire(0x0000C001U);
    lab.s1u.handleDatagram(marker.data(), marker.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().endMarkers == 1);
    CHECK(lab.s1u.counters().endMarkerUnknownTunnels == 1);
    CHECK(lab.s1u.counters().endMarkerRetiredTunnels == 0);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
    // Nothing about the new tunnel moved.
    CHECK(fresh.accessGeneration == generation);
    CHECK(fresh.s1 == lte::enb::UeS1State::BEARER_ACTIVE);
    CHECK(fresh.bearer.active());
    CHECK(fresh.bearer.counters().endMarkers == 0);
    CHECK(lab.registry.findBearerByLocalTeid(0x0000C003U).entry == &fresh);
}

TEST_CASE("lte/gtpu/dispatch: an End Marker for a retired tunnel is idempotent and changes nothing")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00007001U);
    lab.registry.releaseS1(entry);
    REQUIRE(lab.registry.isRetiredTeid(0x00007001U));

    const auto endMarker = EndMarkerWire(0x00007001U);
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().endMarkers == 3);
    CHECK(lab.s1u.counters().endMarkerRetiredTunnels == 3);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 0);
    CHECK(lab.registry.isRetiredTeid(0x00007001U));
    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK(entry.s1 == lte::enb::UeS1State::IDLE_RETAINED);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/gtpu/dispatch: an End Marker for an unknown TEID creates no state")
{
    Lab lab;
    lab.attach(1, lab.ueA.LocalAddress(), 0x00008001U);
    const auto endMarker = EndMarkerWire(0xDEADBEEFU);

    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    CHECK(lab.s1u.counters().endMarkerUnknownTunnels == 2);
    CHECK(lab.s1u.counters().endMarkerActiveTunnels == 0);
    CHECK(lab.s1u.counters().endMarkerRetiredTunnels == 0);
    // No bearer, no tunnel and no UE entry was created for it.
    CHECK(lab.registry.size() == 1);
    CHECK(lab.registry.findBearerByLocalTeid(0xDEADBEEFU).entry == nullptr);
    CHECK_FALSE(lab.registry.isRetiredTeid(0xDEADBEEFU));
    CHECK_FALSE(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/gtpu/isolation: an End Marker for one UE disturbs no other UE")
{
    Lab lab;
    auto &entryA = lab.attach(1, lab.ueA.LocalAddress(), 0x00009001U);
    auto &entryB = lab.attach(2, lab.ueB.LocalAddress(), 0x00009002U);
    const auto downlinkA = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto downlinkB = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2});
    const auto first = GPduWire(0x00009002U, downlinkB);
    lab.s1u.handleDatagram(first.data(), first.size(), Lab::SgwPeer());
    REQUIRE(lab.ueReceived(lab.ueB));

    const auto endMarker = EndMarkerWire(0x00009001U);
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    CHECK(entryA.bearer.counters().endMarkers == 1);
    CHECK(entryB.bearer.counters().endMarkers == 0);
    CHECK(entryB.bearer.active());
    CHECK(entryB.counters.s1uDownlinkPackets == 1);
    CHECK(entryB.counters.simulatedDownlinkPackets == 1);
    CHECK(entryB.bearer.counters().downlinkPackets == 1);
    CHECK_FALSE(lab.ueReceived(lab.ueB));
    CHECK_FALSE(lab.ueReceived(lab.ueA));

    // UE B's tunnel is unaffected and still carries traffic.
    const auto second = GPduWire(0x00009002U, downlinkB);
    lab.s1u.handleDatagram(second.data(), second.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueB));
    CHECK(entryB.counters.s1uDownlinkPackets == 2);

    // And UE A's own tunnel is still up, because an End Marker is not a release.
    const auto forA = GPduWire(0x00009001U, downlinkA);
    lab.s1u.handleDatagram(forA.data(), forA.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueA));
    CHECK(entryA.counters.s1uDownlinkPackets == 1);
}

TEST_CASE("lte/gtpu/isolation: a dedicated bearer's End Marker is scoped to that tunnel")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000A001U);
    // The dedicated tunnel's identifier is named on the wire below, so it is
    // queued for the allocator and then allocated: no route to a live mapping
    // picks a value by hand.
    lab.teidQueue.push_back(0x0000A002U);
    auto &dedicated = lab.registry.addDedicatedBearer(
        entry, {6, 7, 1, Lab::SgwAddress, 0xA1A2A3A5u, lab.registry.allocateLocalTeid(), 5, {9, 15, false, false, {}}});
    const uint32_t dedicatedTeid = dedicated.parameters().localTeid;
    REQUIRE(dedicatedTeid == 0x0000A002U);
    lab.registry.bindLocalTeid(entry, dedicated, dedicatedTeid);
    dedicated.activateUe(1, 6, entry.bearer.ueIpv4());

    const auto endMarker = EndMarkerWire(0x0000A002U);
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());
    CHECK(dedicated.counters().endMarkers == 1);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK(dedicated.active());
    CHECK(entry.bearer.active());

    // The default bearer still carries traffic after the dedicated tunnel's
    // End Marker, and so does the dedicated one.
    const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
    const auto onDefault = GPduWire(0x0000A001U, downlink);
    lab.s1u.handleDatagram(onDefault.data(), onDefault.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueA));
    const auto onDedicated = GPduWire(0x0000A002U, downlink);
    lab.s1u.handleDatagram(onDedicated.data(), onDedicated.size(), Lab::SgwPeer());
    CHECK(lab.ueReceived(lab.ueA));
    CHECK(dedicated.counters().downlinkPackets == 1);
}

TEST_CASE("lte/gtpu/dispatch: control messages are never counted as user-plane payload")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000B001U);
    // A well-formed Private Extension whose Extension Value is opaque vendor
    // data. None of it is user-plane payload and none of it may be counted.
    const auto endMarker = EndMarkerWire(0x0000B001U, PrivateExtension(0x1234, {0x11, 0x22, 0x33}));
    lab.s1u.handleDatagram(endMarker.data(), endMarker.size(), Lab::SgwPeer());

    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK(entry.counters.s1uDownlinkBytes == 0);
    CHECK(entry.counters.simulatedDownlinkPackets == 0);
    CHECK(entry.counters.simulatedDownlinkBytes == 0);
    CHECK(entry.bearer.counters().downlinkPackets == 0);
    CHECK(entry.bearer.counters().downlinkBytes == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/gtpu/end-marker: each message type carries its own TEID and payload rule")
{
    // The only G-PDU builder in the tree refuses to construct an invalid one,
    // so the wire form is laid out here to drive the decoder's rule directly
    // rather than the encoder's.
    auto gPduWire = [](uint32_t teid, const std::vector<uint8_t> &payload) {
        std::vector<uint8_t> wire{0x30, gtpu::TPdu,
                                  static_cast<uint8_t>((payload.size() >> 8U) & 0xFFU),
                                  static_cast<uint8_t>(payload.size() & 0xFFU),
                                  static_cast<uint8_t>(teid >> 24U), static_cast<uint8_t>(teid >> 16U),
                                  static_cast<uint8_t>(teid >> 8U), static_cast<uint8_t>(teid)};
        wire.insert(wire.end(), payload.begin(), payload.end());
        return wire;
    };
    const std::vector<uint8_t> payload{0x45, 0x00, 0x00, 0x14};

    // A G-PDU names a tunnel and carries a payload.
    const auto zeroTeid = gPduWire(0, payload);
    CHECK_THROWS_AS(gtpu::Decode(zeroTeid.data(), zeroTeid.size()), gtpu::CodecError);
    const auto noPayload = gPduWire(7, {});
    CHECK_THROWS_AS(gtpu::Decode(noPayload.data(), noPayload.size()), gtpu::CodecError);
    const auto valid = gPduWire(7, payload);
    CHECK_NOTHROW(gtpu::Decode(valid.data(), valid.size()));

    // The encoder refuses the same two cases, so the only builder of a G-PDU
    // cannot put one on the wire that the decoder would then have to reject.
    CHECK_THROWS_AS(gtpu::EncodeTPdu(0, payload.data(), payload.size()), gtpu::CodecError);
    CHECK_THROWS_AS(gtpu::EncodeTPdu(7, payload.data(), 0), gtpu::CodecError);
    CHECK_THROWS_AS(gtpu::EncodeTPdu(7, nullptr, payload.size()), gtpu::CodecError);

    // Echo is addressed to the endpoint itself and names no tunnel at all.
    const std::vector<uint8_t> echoRequest{0x30, gtpu::EchoRequest, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK_NOTHROW(gtpu::Decode(echoRequest.data(), echoRequest.size()));
    auto named = echoRequest;
    named[7] = 0x01;
    CHECK_THROWS_AS(gtpu::Decode(named.data(), named.size()), gtpu::CodecError);

    const std::vector<uint8_t> echoResponse{0x30, gtpu::EchoResponse, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK_NOTHROW(gtpu::Decode(echoResponse.data(), echoResponse.size()));
    named = echoResponse;
    named[6] = 0x01;
    CHECK_THROWS_AS(gtpu::Decode(named.data(), named.size()), gtpu::CodecError);
}

TEST_CASE("lte/gtpu/end-marker: the optional fields are checked against the flags that announce them")
{
    auto wire = [](uint8_t flags, const std::vector<uint8_t> &optional, uint32_t teid) {
        std::vector<uint8_t> out{flags, gtpu::EndMarker,
                                 static_cast<uint8_t>((optional.size() >> 8U) & 0xFFU),
                                 static_cast<uint8_t>(optional.size() & 0xFFU),
                                 static_cast<uint8_t>(teid >> 24U), static_cast<uint8_t>(teid >> 16U),
                                 static_cast<uint8_t>(teid >> 8U), static_cast<uint8_t>(teid)};
        out.insert(out.end(), optional.begin(), optional.end());
        return out;
    };

    // The N-PDU field is read when, and only when, the PN flag announces it.
    const auto npdu = wire(0x31, {0x00, 0x00, 0x7B, 0x00}, 0x00002001U);
    auto decoded = gtpu::Decode(npdu.data(), npdu.size());
    REQUIRE(decoded.npduNumber.has_value());
    CHECK(*decoded.npduNumber == 0x7B);
    CHECK(decoded.teid == 0x00002001U);
    CHECK(decoded.payload.empty());

    // A next-extension value with no E flag to announce it cannot be read.
    const auto strayNext = wire(0x32, {0x12, 0x34, 0x00, 0xC0}, 0x00002002U);
    CHECK_THROWS_AS(gtpu::Decode(strayNext.data(), strayNext.size()), gtpu::CodecError);

    // An E flag that announces an extension header must find one.
    const auto missingChain = wire(0x34, {0x00, 0x00, 0x00, 0x00}, 0x00002003U);
    CHECK_THROWS_AS(gtpu::Decode(missingChain.data(), missingChain.size()), gtpu::CodecError);

    // A chain that stops before the octets it declares itself.
    const auto truncated = wire(0x34, {0x00, 0x00, 0x00, 0xC0}, 0x00002004U);
    CHECK_THROWS_AS(gtpu::Decode(truncated.data(), truncated.size()), gtpu::CodecError);

    // Sixteen extension headers is the limit; the seventeenth is refused. The
    // four octets that follow the mandatory header are the optional block, so
    // the chain itself starts after them.
    std::vector<uint8_t> tail{0x00, 0x00, 0x00, 0xC0};
    for (int i = 0; i < 16; ++i)
        tail.insert(tail.end(), {0x01, 0x00, 0x00, 0xC0});
    const auto overrun = wire(0x34, tail, 0x00002005U);
    CHECK_THROWS_AS(gtpu::Decode(overrun.data(), overrun.size()), gtpu::CodecError);

    // Exactly sixteen is accepted, so the limit is a limit and not a guess.
    tail = {0x00, 0x00, 0x00, 0xC0};
    for (int i = 0; i < 15; ++i)
        tail.insert(tail.end(), {0x01, 0x00, 0x00, 0xC0});
    tail.insert(tail.end(), {0x01, 0x00, 0x00, 0x00});
    const auto sixteen = wire(0x34, tail, 0x00002006U);
    CHECK_NOTHROW(gtpu::Decode(sixteen.data(), sixteen.size()));
}

TEST_CASE("lte/gtpu/dispatch: the endpoint drops what the codec refuses and only answers Echo")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000C001U);

    // A datagram the codec cannot parse is dropped before any bearer is
    // selected, so it cannot reach the G-PDU path or any UE.
    const std::vector<uint8_t> malformed{0x30, gtpu::EndMarker, 0x00};
    lab.s1u.handleDatagram(malformed.data(), malformed.size(), Lab::SgwPeer());
    CHECK(lab.s1u.counters().malformedDrops == 1);
    CHECK(lab.s1u.counters().endMarkers == 0);
    CHECK(entry.bearer.counters().endMarkers == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));

    // An Echo Response is for this endpoint alone and is dropped without an
    // answer and without touching a bearer.
    const std::vector<uint8_t> echoResponse{0x32, gtpu::EchoResponse, 0x00, 0x04,
                                            0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00};
    lab.s1u.handleDatagram(echoResponse.data(), echoResponse.size(), Lab::SgwPeer());
    CHECK(lab.s1u.counters().echoRequests == 0);
    CHECK(lab.s1u.counters().malformedDrops == 1);
    CHECK(entry.bearer.counters().downlinkPackets == 0);

    // An Echo Request without a sequence number cannot be answered.
    const std::vector<uint8_t> noSequence{0x30, gtpu::EchoRequest, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    lab.s1u.handleDatagram(noSequence.data(), noSequence.size(), Lab::SgwPeer());
    CHECK(lab.s1u.counters().malformedDrops == 2);
    CHECK(lab.s1u.counters().echoRequests == 0);

    // One that carries a sequence number is answered, and that is the only
    // thing Echo handling does.
    const std::vector<uint8_t> echoRequest{0x32, gtpu::EchoRequest, 0x00, 0x04,
                                           0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x00};
    lab.s1u.handleDatagram(echoRequest.data(), echoRequest.size(), Lab::SgwPeer());
    CHECK(lab.s1u.counters().echoRequests == 1);
    CHECK(lab.s1u.counters().malformedDrops == 2);
    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/enb/s1u-endpoint: an unconfigured or unpermitted loopback address is refused")
{
    Lab lab;
    CHECK_THROWS_AS(S1uEndpoint("", 0, true, lab.registry, lab.ueLink), std::runtime_error);
    CHECK_THROWS_AS(S1uEndpoint("0.0.0.0", 0, true, lab.registry, lab.ueLink), std::runtime_error);
    // Loopback is only sound where the peer shares this network namespace, so
    // it is refused unless the configuration says it has been verified.
    CHECK_THROWS_AS(S1uEndpoint("127.0.0.1", 0, false, lab.registry, lab.ueLink), std::runtime_error);
    CHECK_NOTHROW(S1uEndpoint("127.0.0.1", 0, true, lab.registry, lab.ueLink));
}

TEST_CASE("lte/gtpu/dispatch: a G-PDU for a bearer that is not yet forwardable is counted and dropped")
{
    Lab lab;

    // Established, and its TEID resolves, but the UE has not yet confirmed
    // transport readiness, so the bearer is not forwardable. The identifier is
    // named on the wire below, so it is queued for the allocator and then
    // allocated rather than bound by hand.
    lab.teidQueue.push_back(0x0000D001U);
    auto &entry = lab.registry.registerPeer(5, lab.ueA.LocalAddress());
    const uint32_t teid = lab.registry.allocateLocalTeid();
    REQUIRE(teid == 0x0000D001U);
    entry.bearer.establish({5, 9, 5, Lab::SgwAddress, 0xA1A2A3A4u, teid});
    lab.registry.bindLocalTeid(entry, teid);
    REQUIRE_FALSE(entry.bearer.active());
    REQUIRE(lab.registry.findBearerByLocalTeid(teid).bearer == &entry.bearer);

    const auto downlink = Ipv4({10, 45, 0, 5}, {10, 45, 0, 5});
    const auto wire = GPduWire(0x0000D001U, downlink);
    lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());

    CHECK(entry.counters.bearerInactiveDrops == 1);
    CHECK(entry.counters.s1uDownlinkPackets == 0);
    CHECK_FALSE(lab.ueReceived(lab.ueA));

    // The same bearer forwards once the UE confirms readiness, so the drop
    // withheld the datagram and did not break the tunnel.
    entry.bearer.activateUe(5, 5, {10, 45, 0, 5});
    REQUIRE(entry.bearer.active());
    lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
    CHECK(entry.counters.bearerInactiveDrops == 1);
    CHECK(entry.counters.s1uDownlinkPackets == 1);
    CHECK(lab.ueReceived(lab.ueA));
}

TEST_CASE("lte/enb/retired-teid: an E-RAB release retires exactly the transport it names")
{
    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000E001U);
    // Both dedicated tunnels name their identifiers below, so each is queued
    // for the allocator and then allocated: no route to a live mapping picks a
    // value by hand.
    lab.teidQueue.push_back(0x0000E002U);
    auto &first = lab.registry.addDedicatedBearer(
        entry, {6, 7, 1, Lab::SgwAddress, 0xA1A2A3A5u, lab.registry.allocateLocalTeid(), 5, {9, 15, false, false, {}}});
    const uint32_t firstTeid = first.parameters().localTeid;
    lab.registry.bindLocalTeid(entry, first, firstTeid);
    lab.teidQueue.push_back(0x0000E003U);
    auto &second = lab.registry.addDedicatedBearer(
        entry, {7, 7, 1, Lab::SgwAddress, 0xA1A2A3A6u, lab.registry.allocateLocalTeid(), 5, {9, 15, false, false, {}}});
    const uint32_t secondTeid = second.parameters().localTeid;
    lab.registry.bindLocalTeid(entry, second, secondTeid);
    REQUIRE(firstTeid == 0x0000E002U);
    REQUIRE(secondTeid == 0x0000E003U);
    // The second addDedicatedBearer may have moved the vector, so the addresses
    // are read back through the index under test rather than held across it.
    auto *firstBearer = lab.registry.findBearerByLocalTeid(firstTeid).bearer;
    auto *secondBearer = lab.registry.findBearerByLocalTeid(secondTeid).bearer;
    REQUIRE(firstBearer != nullptr);
    REQUIRE(secondBearer != nullptr);
    REQUIRE(firstBearer != secondBearer);

    // Releasing one dedicated E-RAB retires that tunnel and nothing else. The
    // search for it steps over the dedicated bearers that are not it.
    lab.registry.releaseBearer(entry, 7);
    CHECK(lab.registry.isRetiredTeid(secondTeid));
    CHECK_FALSE(lab.registry.isRetiredTeid(firstTeid));
    CHECK_FALSE(lab.registry.isRetiredTeid(0x0000E001U));
    CHECK(lab.registry.findBearerByLocalTeid(secondTeid).bearer == nullptr);
    CHECK(lab.registry.findBearerByLocalTeid(firstTeid).bearer == firstBearer);
    CHECK(entry.dedicatedBearers.size() == 1);

    // Releasing the default E-RAB tears down the whole PDN connection: the
    // dedicated transports go with it and the default's own tunnel is retired
    // too. The logical session is not touched by an E-RAB release.
    lab.registry.releaseBearer(entry, 5);
    CHECK(lab.registry.isRetiredTeid(0x0000E001U));
    CHECK(lab.registry.isRetiredTeid(firstTeid));
    CHECK(lab.registry.findBearerByLocalTeid(0x0000E001U).bearer == nullptr);
    CHECK(lab.registry.findBearerByLocalTeid(firstTeid).bearer == nullptr);
    CHECK(entry.dedicatedBearers.empty());
    CHECK_FALSE(entry.bearer.signalingEstablished());

    // A release naming no bearer at all is refused rather than guessed at.
    CHECK_THROWS_AS(lab.registry.releaseBearer(entry, 9), lte::enb::RegistryError);
    CHECK(lab.registry.size() == 1);
}

TEST_CASE("lte/enb/retired-teid: the registry refuses an unusable allocator and an unusable identifier")
{
    // A registry with no allocator cannot allocate safely, so it is refused at
    // construction rather than failing later on a bearer.
    CHECK_THROWS_AS(UeRegistry(4, std::function<uint32_t()>()), lte::enb::RegistryError);

    Lab lab;
    auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000F001U);

    // A zero identifier names no tunnel.
    CHECK_THROWS_AS(lab.registry.bindLocalTeid(entry, 0), lte::enb::RegistryError);
    // This bearer already owns 0x0000F001U, so a different one is refused
    // rather than silently replacing the binding.
    CHECK_THROWS_AS(lab.registry.bindLocalTeid(entry, 0x0000F002U), lte::enb::RegistryError);
    CHECK(lab.registry.findBearerByLocalTeid(0x0000F001U).bearer == &entry.bearer);
    CHECK(lab.registry.findBearerByLocalTeid(0x0000F002U).bearer == nullptr);
}

// ---------------------------------------------------------------------------
// Runtime observability of the retired-TEID drop counter.
//
// The counter was always correct and was always asserted in process. What was
// missing was any runtime surface for it: an operator, and therefore a bounded
// live acceptance campaign, could not read it without shutting the endpoint
// down. These cases drive the real datagram path and assert on what the
// production code actually logged, so the reporting format is proven by
// generation rather than by assembling an expected string and comparing it.
//
// Each case records its observations into locals and closes the capture before
// the first assertion runs, so a failed check can never print into the captured
// buffer and become invisible.
// ---------------------------------------------------------------------------

TEST_CASE("lte/gtpu/observability: one retired-TEID drop reports a cumulative total of one")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    bool retired = false;
    bool ueGotPacket = true;
    {
        lte::test::LogCapture capture;
        Lab lab;
        auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00009001U);
        lab.registry.releaseS1(entry);
        retired = lab.registry.isRetiredTeid(0x00009001U);

        const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
        const auto wire = GPduWire(0x00009001U, downlink);
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());

        counters = lab.s1u.counters();
        ueGotPacket = lab.ueReceived(lab.ueA);
        log = capture.text();
    }

    // The access was released through the real registry lifecycle and the
    // identifier is retired, so the packet above is the event under test.
    REQUIRE(retired);
    // One retired event moves the counter from 0 to 1 and leaves the other two
    // drop families where they were.
    CHECK(counters.retiredTeidDrops == 1);
    CHECK(counters.unknownTeidDrops == 0);
    CHECK(counters.malformedDrops == 0);
    CHECK_FALSE(ueGotPacket);
    // The warning kept its prefix and its hexadecimal TEID and now carries the
    // cumulative count read from the very field the counter is.
    CHECK(Occurrences(log, "Dropped S1-U T-PDU for retired TEID 0x00009001 retired-total=1") == 1);
    CHECK(Occurrences(log, "Dropped S1-U T-PDU for retired TEID") == 1);
    const auto totals = ReportedRetiredTotals(log);
    REQUIRE(totals.size() == 1);
    CHECK(totals[0] == 1);
}

TEST_CASE("lte/gtpu/observability: repeated retired-TEID drops accumulate monotonically")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    bool retired = false;
    bool ueAGotPacket = true;
    bool ueBGotPacket = true;
    {
        lte::test::LogCapture capture;
        Lab lab;
        auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x0000A001U);
        lab.registry.releaseS1(entry);
        retired = lab.registry.isRetiredTeid(0x0000A001U);
        // A second UE stays live throughout, so a misrouted drop would show up
        // as traffic on a tunnel the packet never named.
        lab.attach(2, lab.ueB.LocalAddress(), 0x0000A002U);

        const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 2});
        const auto wire = GPduWire(0x0000A001U, downlink);
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());
        lab.s1u.handleDatagram(wire.data(), wire.size(), Lab::SgwPeer());

        counters = lab.s1u.counters();
        ueAGotPacket = lab.ueReceived(lab.ueA);
        ueBGotPacket = lab.ueReceived(lab.ueB);
        log = capture.text();
    }

    REQUIRE(retired);
    CHECK(counters.retiredTeidDrops == 2);
    CHECK(counters.unknownTeidDrops == 0);
    CHECK(counters.malformedDrops == 0);
    CHECK_FALSE(ueAGotPacket);
    CHECK_FALSE(ueBGotPacket);
    // Exactly one warning per dropped packet, and the totals they carry are the
    // running count in order rather than a constant repeated twice.
    CHECK(Occurrences(log, "Dropped S1-U T-PDU for retired TEID 0x0000A001 retired-total=1") == 1);
    CHECK(Occurrences(log, "Dropped S1-U T-PDU for retired TEID 0x0000A001 retired-total=2") == 1);
    const auto totals = ReportedRetiredTotals(log);
    REQUIRE(totals.size() == 2);
    CHECK(totals[0] == 1);
    CHECK(totals[1] == 2);
}

TEST_CASE("lte/gtpu/observability: an unknown TEID is reported apart from a retired one")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    bool retired = false;
    bool neverIssued = true;
    {
        lte::test::LogCapture capture;
        Lab lab;
        auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00009101U);
        lab.registry.releaseS1(entry);
        retired = lab.registry.isRetiredTeid(0x00009101U);
        neverIssued = !lab.registry.isRetiredTeid(0x00009102U) &&
                      lab.registry.findBearerByLocalTeid(0x00009102U).entry == nullptr;

        const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
        // A retired drop first, so a contamination would show against a
        // non-zero retired count instead of hiding behind a zero that cannot
        // move either way.
        const auto stale = GPduWire(0x00009101U, downlink);
        lab.s1u.handleDatagram(stale.data(), stale.size(), Lab::SgwPeer());
        // A TEID this process never issued and never retired.
        const auto stranger = GPduWire(0x00009102U, downlink);
        lab.s1u.handleDatagram(stranger.data(), stranger.size(), Lab::SgwPeer());

        counters = lab.s1u.counters();
        log = capture.text();
    }

    REQUIRE(retired);
    REQUIRE(neverIssued);
    CHECK(counters.unknownTeidDrops == 1);
    CHECK(counters.retiredTeidDrops == 1);
    CHECK(counters.malformedDrops == 0);
    // Each family produced its own message and neither borrowed the other's
    // count: the unknown drop is not reported as a retired event at all.
    CHECK(Occurrences(log, "Dropped S1-U T-PDU with unknown/stale TEID 0x00009102") == 1);
    CHECK(Occurrences(log, "Dropped S1-U T-PDU for retired TEID") == 1);
    const auto totals = ReportedRetiredTotals(log);
    REQUIRE(totals.size() == 1);
    CHECK(totals[0] == 1);
}

TEST_CASE("lte/gtpu/observability: a malformed datagram advances no retired or unknown count")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    bool retired = false;
    bool ueGotPacket = true;
    {
        lte::test::LogCapture capture;
        Lab lab;
        auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00009201U);
        lab.registry.releaseS1(entry);
        retired = lab.registry.isRetiredTeid(0x00009201U);

        // Truncated below the eight-octet mandatory header, so the codec
        // refuses it before any TEID can be read and no drop family above can
        // be chosen.
        const std::vector<uint8_t> truncated{0x30, 0xFF, 0x00, 0x01};
        lab.s1u.handleDatagram(truncated.data(), truncated.size(), Lab::SgwPeer());

        counters = lab.s1u.counters();
        ueGotPacket = lab.ueReceived(lab.ueA);
        log = capture.text();
    }

    REQUIRE(retired);
    CHECK(counters.malformedDrops == 1);
    CHECK(counters.retiredTeidDrops == 0);
    CHECK(counters.unknownTeidDrops == 0);
    CHECK_FALSE(ueGotPacket);
    CHECK(Occurrences(log, "Dropped malformed S1-U datagram") == 1);
    // No retired event, so no cumulative value is reported at all.
    CHECK(Occurrences(log, "retired-total") == 0);
}

TEST_CASE("lte/gtpu/observability: an active bearer is undisturbed and counts nothing retired")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    long downlinkAfterBoth = 0;
    bool ueGotFirst = true;
    bool ueGotSecond = true;
    bool bearerStillActive = false;
    {
        lte::test::LogCapture capture;
        Lab lab;
        auto &entry = lab.attach(1, lab.ueA.LocalAddress(), 0x00009301U);

        const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 1});
        // The positive control: a valid downlink from the bearer's own
        // configured SGW peer really is delivered.
        const auto good = GPduWire(0x00009301U, downlink);
        lab.s1u.handleDatagram(good.data(), good.size(), Lab::SgwPeer());
        ueGotFirst = lab.ueReceived(lab.ueA);

        // The same live TEID from a peer that is not its SGW. That is the
        // unexpected-peer branch, which is about the source and not about the
        // identifier, so it must not be reported as a retired-TEID drop.
        const InetAddress stranger{"127.0.0.8", 2152};
        const auto bad = GPduWire(0x00009301U, downlink);
        lab.s1u.handleDatagram(bad.data(), bad.size(), stranger);

        counters = lab.s1u.counters();
        ueGotSecond = lab.ueReceived(lab.ueA);
        downlinkAfterBoth = static_cast<long>(entry.counters.s1uDownlinkPackets);
        bearerStillActive = entry.bearer.active();
        log = capture.text();
    }

    CHECK(ueGotFirst);
    CHECK(downlinkAfterBoth == 1);
    CHECK(bearerStillActive);
    // The wrong-peer packet is refused by the peer check and reaches no UE, and
    // neither drop is credited to the retired counter.
    CHECK_FALSE(ueGotSecond);
    CHECK(counters.retiredTeidDrops == 0);
    CHECK(counters.unknownTeidDrops == 0);
    CHECK(counters.malformedDrops == 0);
    CHECK(Occurrences(log, "Dropped S1-U datagram from unexpected peer") == 1);
    CHECK(Occurrences(log, "retired-total") == 0);
}

TEST_CASE("lte/gtpu/observability: an evicted tombstone is reported as unknown and never as retired")
{
    std::string log;
    lte::enb::S1uEndpointCounters counters{};
    bool evicted = false;
    bool ueGotPacket = true;
    {
        lte::test::LogCapture capture;
        // A ledger of one record, so the second retirement evicts the first
        // tombstone exactly as the production bound does.
        Lab lab(1);
        auto &entryA = lab.attach(1, lab.ueA.LocalAddress(), 0x0000B101U);
        lab.registry.releaseS1(entryA);
        auto &entryB = lab.attach(2, lab.ueB.LocalAddress(), 0x0000B102U);
        lab.registry.releaseS1(entryB);
        evicted = !lab.registry.isRetiredTeid(0x0000B101U) && lab.registry.retiredTeids().evictions() == 1;

        // A new tunnel on the same radio endpoint, so a leak would have
        // somewhere to go.
        lab.registry.remove(entryA);
        lab.attach(3, lab.ueA.LocalAddress(), 0x0000B103U);

        const auto downlink = Ipv4({10, 45, 0, 1}, {10, 45, 0, 3});
        const auto stale = GPduWire(0x0000B101U, downlink);
        lab.s1u.handleDatagram(stale.data(), stale.size(), Lab::SgwPeer());

        counters = lab.s1u.counters();
        ueGotPacket = lab.ueReceived(lab.ueA);
        log = capture.text();
    }

    REQUIRE(evicted);
    // The record that distinguished this identifier from a never-issued one has
    // aged out, so the packet is reported as one that never had a tunnel. That
    // is the documented limit of a bounded observation aid, and the reporting
    // must say so rather than claim a retired event that cannot be shown.
    CHECK(counters.unknownTeidDrops == 1);
    CHECK(counters.retiredTeidDrops == 0);
    CHECK_FALSE(ueGotPacket);
    CHECK(Occurrences(log, "Dropped S1-U T-PDU with unknown/stale TEID 0x0000B101") == 1);
    CHECK(Occurrences(log, "retired-total") == 0);
}
