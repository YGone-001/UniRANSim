//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/gtpu.hpp>
#include <lte/enb/s1u_endpoint.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
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

// A Private Extension information element, TS 29.281 8.1: a TLV whose type
// carries the MSB that distinguishes it from a TV information element.
std::vector<uint8_t> PrivateExtension(std::vector<uint8_t> value)
{
    std::vector<uint8_t> ie{gtpu::PrivateExtensionType, static_cast<uint8_t>(value.size())};
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
    UeRegistry registry{8};
    S1uEndpoint s1u{"127.0.0.1", 0, true, registry, ueLink};

    static constexpr std::array<uint8_t, 4> SgwAddress{127, 0, 0, 9};
    static const InetAddress &SgwPeer()
    {
        static const InetAddress peer{"127.0.0.9", 2152};
        return peer;
    }

    EnbUeEntry &attach(uint32_t radioUeId, const InetAddress &uePeer, uint32_t localTeid)
    {
        auto &entry = registry.registerPeer(radioUeId, uePeer);
        entry.bearer.establish({5, 9, radioUeId, SgwAddress, 0xA1A2A3A4u, localTeid});
        entry.bearer.activateUe(radioUeId, 5, {10, 45, 0, static_cast<uint8_t>(radioUeId)});
        registry.bindLocalTeid(entry, localTeid);
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

TEST_CASE("lte/gtpu/end-marker: the optional-header forms decode and the malformed header is rejected")
{
    // S flag with a sequence number: valid, and the sequence is not a payload.
    std::vector<uint8_t> sequenced{0x32, gtpu::EndMarker, 0x00, 0x04, 0x00, 0x00, 0x10, 0x01,
                                   0x12, 0x34, 0x00, 0x00};
    auto decoded = gtpu::Decode(sequenced.data(), sequenced.size());
    REQUIRE(decoded.sequenceNumber.has_value());
    CHECK(*decoded.sequenceNumber == 0x1234);
    CHECK(decoded.teid == 0x00001001U);
    CHECK(decoded.payload.empty());

    // E flag with one supported extension header, then no information elements.
    std::vector<uint8_t> extended{0x34, gtpu::EndMarker, 0x00, 0x08, 0x00, 0x00, 0x10, 0x02,
                                  0x00, 0x00, 0x00, 0xC0, 0x01, 0x00, 0x00, 0x00};
    decoded = gtpu::Decode(extended.data(), extended.size());
    CHECK(decoded.extensionTypes == std::vector<uint8_t>{0xC0});
    CHECK(decoded.teid == 0x00001002U);
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
    bad = wire;
    bad[0] = 0x32;
    CHECK_THROWS_AS(gtpu::Decode(bad.data(), bad.size()), gtpu::CodecError);

    // A declared optional block that is shorter than the four octets it needs.
    std::vector<uint8_t> shortOptional{0x32, gtpu::EndMarker, 0x00, 0x02, 0x00, 0x00, 0x10, 0x04,
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

TEST_CASE("lte/gtpu/end-marker: only the optional Private Extension information element is accepted")
{
    CHECK_NOTHROW(gtpu::Decode(EndMarkerWire(7).data(), EndMarkerWire(7).size()));

    auto withExtension = EndMarkerWire(7, PrivateExtension({0xAA, 0xBB}));
    auto decoded = gtpu::Decode(withExtension.data(), withExtension.size());
    CHECK(decoded.messageType == gtpu::EndMarker);
    CHECK(decoded.teid == 7);
    // The information-element area of a control message is not user-plane
    // payload and is not published as one.
    CHECK(decoded.payload.empty());

    auto repeated = EndMarkerWire(7, [] {
        std::vector<uint8_t> ies = PrivateExtension({0x01});
        const auto more = PrivateExtension({0x02, 0x03});
        ies.insert(ies.end(), more.begin(), more.end());
        return ies;
    }());
    CHECK_NOTHROW(gtpu::Decode(repeated.data(), repeated.size()));

    // An information element of any other type cannot be interpreted.
    auto foreign = EndMarkerWire(7, {0x0E, 0x00});
    CHECK_THROWS_AS(gtpu::Decode(foreign.data(), foreign.size()), gtpu::CodecError);
    // A truncated type-length pair, and a value longer than what remains.
    auto truncatedType = EndMarkerWire(7, {0xFF});
    CHECK_THROWS_AS(gtpu::Decode(truncatedType.data(), truncatedType.size()), gtpu::CodecError);
    auto overrun = EndMarkerWire(7, {0xFF, 0x08, 0x01});
    CHECK_THROWS_AS(gtpu::Decode(overrun.data(), overrun.size()), gtpu::CodecError);
}

TEST_CASE("lte/gtpu/end-marker: the boundary lengths decode and the neighbouring ones do not")
{
    // The smallest End Marker: the mandatory header alone.
    CHECK_NOTHROW(gtpu::Decode(GenuineOpen5gsEndMarker.data(), GenuineOpen5gsEndMarker.size()));

    // An information-element area that exactly fills the message.
    const auto exact = EndMarkerWire(9, PrivateExtension({0x01, 0x02, 0x03}));
    CHECK_NOTHROW(gtpu::Decode(exact.data(), exact.size()));
    // The same message with the declared value length one longer than what
    // remains does not. Index 9 is the Private Extension length octet.
    std::vector<uint8_t> overrun = exact;
    overrun[9] = 4;
    CHECK_THROWS_AS(gtpu::Decode(overrun.data(), overrun.size()), gtpu::CodecError);

    // The largest payload a GTP-U length field can describe round-trips.
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

TEST_CASE("lte/enb/retired-teid: the ledger records, repeats, revives and ages out deterministically")
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

    ledger.revive(11);
    CHECK_FALSE(ledger.contains(11));
    CHECK(ledger.size() == 1);
    ledger.revive(11); // reviving an identifier with no record is not an error
    CHECK(ledger.size() == 1);

    CHECK(ledger.retire(13));
    CHECK(ledger.retire(14)); // the ledger is now full
    CHECK(ledger.size() == 3);
    CHECK(ledger.retire(15)); // evicts the longest-retired record, which is 12
    CHECK(ledger.size() == 3);
    CHECK(ledger.evictions() == 1);
    CHECK_FALSE(ledger.contains(12));
    CHECK(ledger.contains(13));
    CHECK(ledger.contains(14));
    CHECK(ledger.contains(15));
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
    // A deterministic allocator that comes back round to values the registry
    // must refuse: zero, one that is already retired and one that is still
    // live. This is the wraparound of the 32-bit sequence, which the
    // process-wide monotonic counter cannot reach on its own in a test.
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

TEST_CASE("lte/enb/retired-teid: a retirement record cannot shadow an active mapping")
{
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, 0x00000011u});
    registry.bindLocalTeid(entry, 0x00000011u);
    registry.releaseS1(entry);
    REQUIRE(registry.isRetiredTeid(0x00000011u));

    // A later access binds an identifier chosen by hand. It becomes live again
    // and the stale retirement record is dropped, so the live mapping is what
    // resolves and what the allocator is allowed to avoid.
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, 0x00000011u}, true);
    registry.bindLocalTeid(entry, 0x00000011u);
    CHECK_FALSE(registry.isRetiredTeid(0x00000011u));
    CHECK(registry.findBearerByLocalTeid(0x00000011u).entry == &entry);
    CHECK(registry.retiredTeids().size() == 0);
}

TEST_CASE("lte/enb/retired-teid: ageing a record out cannot disturb an unrelated live tunnel")
{
    RetiredTeidLedger ledger(2);
    UeRegistry registry(8);
    auto &entry = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1u, 0x00000021u});
    entry.bearer.activateUe(1, 5, {10, 45, 0, 2});
    registry.bindLocalTeid(entry, 0x00000021u);

    ledger.retire(1);
    ledger.retire(2);
    ledger.retire(3);
    CHECK(ledger.size() == 2);
    CHECK(ledger.evictions() == 1);
    // The live tunnel is untouched by any of it.
    CHECK(registry.findBearerByLocalTeid(0x00000021u).entry == &entry);
    CHECK(registry.findBearerByLocalTeid(0x00000021u).bearer->active());
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
    auto &dedicated = lab.registry.addDedicatedBearer(
        entry, {6, 7, 1, Lab::SgwAddress, 0xA1A2A3A5u, 0x0000A002U, 5, {9, 15, false, false, {}}});
    lab.registry.bindLocalTeid(entry, dedicated, 0x0000A002U);
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
    const auto endMarker = EndMarkerWire(0x0000B001U, PrivateExtension({0x11, 0x22, 0x33}));
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
    // transport readiness, so the bearer is not forwardable.
    auto &entry = lab.registry.registerPeer(5, lab.ueA.LocalAddress());
    entry.bearer.establish({5, 9, 5, Lab::SgwAddress, 0xA1A2A3A4u, 0x0000D001U});
    lab.registry.bindLocalTeid(entry, 0x0000D001U);
    REQUIRE_FALSE(entry.bearer.active());
    REQUIRE(lab.registry.findBearerByLocalTeid(0x0000D001U).bearer == &entry.bearer);

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
    auto &first = lab.registry.addDedicatedBearer(
        entry, {6, 7, 1, Lab::SgwAddress, 0xA1A2A3A5u, 0x0000E002U, 5, {9, 15, false, false, {}}});
    lab.registry.bindLocalTeid(entry, first, 0x0000E002U);
    auto &second = lab.registry.addDedicatedBearer(
        entry, {7, 7, 1, Lab::SgwAddress, 0xA1A2A3A6u, 0x0000E003U, 5, {9, 15, false, false, {}}});
    lab.registry.bindLocalTeid(entry, second, 0x0000E003U);
    // The second addDedicatedBearer may have moved the vector, so the addresses
    // are read back through the index under test rather than held across it.
    auto *firstBearer = lab.registry.findBearerByLocalTeid(0x0000E002U).bearer;
    auto *secondBearer = lab.registry.findBearerByLocalTeid(0x0000E003U).bearer;
    REQUIRE(firstBearer != nullptr);
    REQUIRE(secondBearer != nullptr);
    REQUIRE(firstBearer != secondBearer);

    // Releasing one dedicated E-RAB retires that tunnel and nothing else. The
    // search for it steps over the dedicated bearers that are not it.
    lab.registry.releaseBearer(entry, 7);
    CHECK(lab.registry.isRetiredTeid(0x0000E003U));
    CHECK_FALSE(lab.registry.isRetiredTeid(0x0000E002U));
    CHECK_FALSE(lab.registry.isRetiredTeid(0x0000E001U));
    CHECK(lab.registry.findBearerByLocalTeid(0x0000E003U).bearer == nullptr);
    CHECK(lab.registry.findBearerByLocalTeid(0x0000E002U).bearer == firstBearer);
    CHECK(entry.dedicatedBearers.size() == 1);

    // Releasing the default E-RAB tears down the whole PDN connection: the
    // dedicated transports go with it and the default's own tunnel is retired
    // too. The logical session is not touched by an E-RAB release.
    lab.registry.releaseBearer(entry, 5);
    CHECK(lab.registry.isRetiredTeid(0x0000E001U));
    CHECK(lab.registry.isRetiredTeid(0x0000E002U));
    CHECK(lab.registry.findBearerByLocalTeid(0x0000E001U).bearer == nullptr);
    CHECK(lab.registry.findBearerByLocalTeid(0x0000E002U).bearer == nullptr);
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
