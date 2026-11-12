//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-E: the isolated SGW's downlink forwarding map.
//
// These cases drive the map and the sender that consults it. The two cells are
// real UDP sockets this file owns, so a downlink that the map says should go to
// the target is a datagram the target's socket really received, with the TEID
// the map installed. Nothing here asserts that a Boolean changed.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <lib/udp/server.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/handover_core_path.hpp>
#include <lte/enb/handover_orchestration.hpp>
#include <lte/enb/user_plane.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;

constexpr uint16_t SgwPort = 2152;
const std::array<uint8_t, 4> SgwIp{127, 0, 0, 2};
const std::array<uint8_t, 4> SourceIp{127, 0, 0, 9};
const std::array<uint8_t, 4> TargetIp{127, 0, 0, 10};
constexpr uint8_t DefaultEbi = 5;
constexpr uint8_t DedicatedEbi = 6;
constexpr uint32_t SgwDefaultTeid = 30;
constexpr uint32_t SgwDedicatedTeid = 36;
constexpr uint32_t ElsewhereEnbId = 0x00ABCDEu;

IsolatedSessionKey Session(uint32_t mmeUeS1apId = 201)
{
    return IsolatedSessionKey{mmeUeS1apId, {10, 0, 0, 1}};
}

HandoverTransactionId Transaction(uint32_t mmeUeS1apId = 201, uint64_t epoch = 1, uint32_t sequence = 1)
{
    return HandoverTransactionId{mmeUeS1apId, epoch, sequence};
}

// A real UDP endpoint standing in for one cell's S1-U socket.
class Cell
{
  public:
    explicit Cell(const std::array<uint8_t, 4> &address) : m_socket(Ipv4ToString(address), 0) {}

    [[nodiscard]] uint16_t port() const { return m_socket.LocalAddress().getPort(); }

    struct Received
    {
        gtpu::Packet packet;
        InetAddress from;
    };

    std::vector<Received> drain()
    {
        std::vector<Received> out;
        for (int i = 0; i < 16; ++i)
        {
            uint8_t buffer[2048];
            InetAddress from;
            const int length = m_socket.Receive(buffer, sizeof(buffer), 5, from);
            if (length <= 0)
                break;
            out.push_back(Received{gtpu::Decode(buffer, static_cast<size_t>(length)), from});
        }
        return out;
    }

  private:
    udp::UdpServer m_socket;
};

AcceptedTargetEndpoint Bearer(uint8_t ebi, BearerRole role, std::optional<uint8_t> linked, uint32_t sgwTeid,
                              const IsolatedDownlinkEndpoint &endpoint)
{
    AcceptedTargetEndpoint bearer;
    bearer.ebi = ebi;
    bearer.role = role;
    bearer.linkedDefaultEbi = linked;
    bearer.sgwTeid = sgwTeid;
    bearer.endpoint = endpoint;
    return bearer;
}

// The source mapping every case starts from: default and dedicated, both
// pointing at the source cell's own socket and local TEIDs.
struct Fixture
{
    Cell sourceCell{SourceIp};
    Cell targetCell{TargetIp};
    IsolatedSgw sgw{ExecutionMode::ISOLATED_SIMULATOR, Ipv4ToString(SgwIp), SgwPort};

    const uint32_t sourceDefaultTeid = 0x1111;
    const uint32_t sourceDedicatedTeid = 0x2222;
    const uint32_t targetDefaultTeid = 0x3333;
    const uint32_t targetDedicatedTeid = 0x4444;

    IsolatedDownlinkEndpoint SourceDefault() const
    {
        return {SourceIp, sourceDefaultTeid, sourceCell.port()};
    }
    IsolatedDownlinkEndpoint SourceDedicated() const
    {
        return {SourceIp, sourceDedicatedTeid, sourceCell.port()};
    }
    IsolatedDownlinkEndpoint TargetDefault() const
    {
        return {TargetIp, targetDefaultTeid, targetCell.port()};
    }
    IsolatedDownlinkEndpoint TargetDedicated() const
    {
        return {TargetIp, targetDedicatedTeid, targetCell.port()};
    }

    std::vector<AcceptedTargetEndpoint> SourceBearers() const
    {
        return {Bearer(DefaultEbi, BearerRole::DEFAULT, std::nullopt, SgwDefaultTeid, SourceDefault()),
                Bearer(DedicatedEbi, BearerRole::DEDICATED, DefaultEbi, SgwDedicatedTeid, SourceDedicated())};
    }

    std::vector<AcceptedTargetEndpoint> TargetBearers() const
    {
        return {Bearer(DefaultEbi, BearerRole::DEFAULT, std::nullopt, SgwDefaultTeid, TargetDefault()),
                Bearer(DedicatedEbi, BearerRole::DEDICATED, DefaultEbi, SgwDedicatedTeid, TargetDedicated())};
    }

    IsolatedPathUpdateRequest Request(uint64_t expectedGeneration = 1,
                                      std::vector<AcceptedTargetEndpoint> bearers = {}) const
    {
        IsolatedPathUpdateRequest request;
        request.transaction = Transaction();
        request.session = Session();
        request.mmeAssociationEpoch = 1;
        request.targetEnbId = ElsewhereEnbId;
        request.targetS1uAddress = TargetIp;
        request.expectedGeneration = expectedGeneration;
        request.bearers = bearers.empty() ? TargetBearers() : std::move(bearers);
        return request;
    }

    Fixture()
    {
        CorePathRefusalRecord failure;
        REQUIRE(sgw.installSession(Session(), 1, SourceBearers(), &failure));
    }

    ~Fixture() = default;
};

} // namespace

TEST_CASE("lte/handover/core-path: a session is provisioned with one source destination per bearer")
{
    Fixture fixture;
    const auto generation = fixture.sgw.generationOf(Session());
    REQUIRE(generation.has_value());
    CHECK(*generation == 1);
    CHECK_FALSE(fixture.sgw.ownerOf(Session()).has_value());

    const auto installed = fixture.sgw.installed(Session());
    REQUIRE(installed.size() == 2);
    CHECK(installed[0].ebi == DefaultEbi);
    CHECK(installed[0].role == BearerRole::DEFAULT);
    CHECK(installed[0].endpoint == fixture.SourceDefault());
    // Nothing has moved, so the old path and the current one are the same path.
    CHECK(installed[0].originalSource == installed[0].endpoint);
    CHECK(installed[1].ebi == DedicatedEbi);
    CHECK(installed[1].linkedDefaultEbi == DefaultEbi);
    CHECK(installed[1].endpoint == fixture.SourceDedicated());
    CHECK(installed[1].sgwTeid == SgwDedicatedTeid);
}

TEST_CASE("lte/handover/core-path: an accepted two-bearer update is published atomically")
{
    Fixture fixture;
    const auto commit = fixture.sgw.apply(fixture.Request());

    REQUIRE(commit.committed);
    CHECK_FALSE(commit.replayed);
    CHECK(commit.pathGeneration == 2);
    REQUIRE(commit.installed.size() == 2);
    for (const auto &path : commit.installed)
    {
        CHECK(path.endpoint.address == TargetIp);
        CHECK(path.originalSource.address == SourceIp);
        CHECK(path.generation == 2);
        CHECK(path.owner == Transaction());
    }
    CHECK(*fixture.sgw.generationOf(Session()) == 2);
    CHECK(fixture.sgw.ownerOf(Session()) == Transaction());

    // The original source mapping is still recorded per bearer: it is what an
    // End Marker names and what a confirmation reports as replaced.
    const auto defaultPath = fixture.sgw.installed(Session(), DefaultEbi);
    REQUIRE(defaultPath.has_value());
    CHECK(defaultPath->originalSource == fixture.SourceDefault());
    CHECK(defaultPath->endpoint == fixture.TargetDefault());
    const auto dedicatedPath = fixture.sgw.installed(Session(), DedicatedEbi);
    REQUIRE(dedicatedPath.has_value());
    CHECK(dedicatedPath->originalSource == fixture.SourceDedicated());
    CHECK(dedicatedPath->endpoint == fixture.TargetDedicated());
}

TEST_CASE("lte/handover/core-path: the same update in reverse bearer order installs the same mapping")
{
    Fixture fixture;
    auto bearers = fixture.TargetBearers();
    std::reverse(bearers.begin(), bearers.end());
    const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));

    REQUIRE(commit.committed);
    const auto installed = fixture.sgw.installed(Session());
    REQUIRE(installed.size() == 2);
    // The map is indexed by EBI, so the request's order cannot change what was
    // installed. The default bearer is still the default bearer.
    CHECK(installed[0].ebi == DefaultEbi);
    CHECK(installed[0].role == BearerRole::DEFAULT);
    CHECK(installed[0].endpoint == fixture.TargetDefault());
    CHECK(installed[1].ebi == DedicatedEbi);
    CHECK(installed[1].endpoint == fixture.TargetDedicated());
}

TEST_CASE("lte/handover/core-path: a replacement that omits a bearer publishes nothing")
{
    Fixture fixture;
    auto partial = fixture.TargetBearers();
    partial.pop_back();
    const auto commit = fixture.sgw.apply(fixture.Request(1, partial));

    CHECK_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CorePathRefusal::BEARER_SET_MISMATCH);
    // Nothing moved: not the default bearer either.
    CHECK(*fixture.sgw.generationOf(Session()) == 1);
    CHECK(fixture.sgw.installed(Session(), DefaultEbi)->endpoint == fixture.SourceDefault());
    CHECK(fixture.sgw.installed(Session(), DedicatedEbi)->endpoint == fixture.SourceDedicated());
}

TEST_CASE("lte/handover/core-path: a wrong destination, TEID or role is refused whole")
{
    Fixture fixture;

    SUBCASE("a destination that is not on the target cell")
    {
        auto bearers = fixture.TargetBearers();
        bearers[0].endpoint.address = {127, 0, 0, 11};
        const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));
        CHECK_FALSE(commit.committed);
        REQUIRE(commit.refusal.has_value());
        CHECK(commit.refusal->refusal == CorePathRefusal::WRONG_TARGET_ENDPOINT);
        CHECK(fixture.sgw.installed(Session(), DefaultEbi)->endpoint == fixture.SourceDefault());
    }
    SUBCASE("a bearer whose SGW-side tunnel identity changed")
    {
        auto bearers = fixture.TargetBearers();
        bearers[1].sgwTeid = SgwDedicatedTeid + 1;
        const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::WRONG_SGW_TEID);
        CHECK(fixture.sgw.installed(Session(), DedicatedEbi)->endpoint == fixture.SourceDedicated());
    }
    SUBCASE("a bearer whose role was rewritten")
    {
        auto bearers = fixture.TargetBearers();
        bearers[1].role = BearerRole::DEFAULT;
        bearers[1].linkedDefaultEbi.reset();
        const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::BEARER_RELATIONSHIP_INVALID);
    }
    SUBCASE("a destination with no TEID")
    {
        auto bearers = fixture.TargetBearers();
        bearers[0].endpoint.teid = 0;
        const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::INCOMPLETE_ENDPOINT);
    }
    SUBCASE("the same EBI twice")
    {
        auto bearers = fixture.TargetBearers();
        bearers[1].ebi = DefaultEbi;
        const auto commit = fixture.sgw.apply(fixture.Request(1, bearers));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::DUPLICATE_EBI);
    }
}

TEST_CASE("lte/handover/core-path: two eNBs may hold the same numeric local TEID")
{
    Fixture fixture;
    // A second session on a second cell, whose local TEID happens to be the
    // same number as the first session's target TEID. An identifier is
    // eNB-local, so this is legitimate and the destination tuple is what tells
    // them apart.
    const IsolatedSessionKey other{202, {10, 0, 0, 2}};
    const std::array<uint8_t, 4> otherIp{127, 0, 0, 12};
    Cell otherCell{otherIp};
    CorePathRefusalRecord failure;
    REQUIRE(fixture.sgw.installSession(
        other, 1,
        {Bearer(DefaultEbi, BearerRole::DEFAULT, std::nullopt, SgwDefaultTeid,
                {otherIp, fixture.targetDefaultTeid, otherCell.port()})},
        &failure));

    // The first session moves to the target, which holds the same numeric TEID
    // as the other session's source cell.
    const auto commit = fixture.sgw.apply(fixture.Request());
    REQUIRE(commit.committed);

    CHECK(fixture.sgw.installed(Session(), DefaultEbi)->endpoint == fixture.TargetDefault());
    // The other session is untouched: same cell, same TEID, same generation.
    CHECK(*fixture.sgw.generationOf(other) == 1);
    CHECK(fixture.sgw.installed(other, DefaultEbi)->endpoint.address == otherIp);
    CHECK(fixture.sgw.installed(other, DefaultEbi)->endpoint.teid == fixture.targetDefaultTeid);

    // And the sender follows the map: one bearer's downlink goes to the target
    // cell and the other's to the cell that still serves it.
    const std::vector<uint8_t> payload{0x45, 0x00, 0x00, 0x00};
    REQUIRE(fixture.sgw.sendDownlink(Session(), DefaultEbi, payload.data(), payload.size()));
    REQUIRE(fixture.sgw.sendDownlink(other, DefaultEbi, payload.data(), payload.size()));

    const auto targetReceived = fixture.targetCell.drain();
    REQUIRE(targetReceived.size() == 1);
    CHECK(targetReceived.front().packet.teid == fixture.targetDefaultTeid);
    const auto otherReceived = otherCell.drain();
    REQUIRE(otherReceived.size() == 1);
    CHECK(otherReceived.front().packet.teid == fixture.targetDefaultTeid);
    CHECK(fixture.sourceCell.drain().empty());
}

TEST_CASE("lte/handover/core-path: a duplicate update is replayed without a second publication")
{
    Fixture fixture;
    REQUIRE(fixture.sgw.apply(fixture.Request()).committed);

    const auto replay = fixture.sgw.apply(fixture.Request(2));
    REQUIRE(replay.committed);
    CHECK(replay.replayed);
    CHECK(replay.pathGeneration == 2);
    CHECK(*fixture.sgw.generationOf(Session()) == 2);
}

TEST_CASE("lte/handover/core-path: a conflicting duplicate or a second transaction is refused")
{
    Fixture fixture;
    REQUIRE(fixture.sgw.apply(fixture.Request()).committed);

    SUBCASE("the same transaction with another replacement")
    {
        auto bearers = fixture.TargetBearers();
        bearers[0].endpoint.teid = 0x9999;
        const auto commit = fixture.sgw.apply(fixture.Request(2, bearers));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::CONFLICTING_REPLACEMENT);
        CHECK(fixture.sgw.installed(Session(), DefaultEbi)->endpoint == fixture.TargetDefault());
    }
    SUBCASE("another transaction asking to switch the same session")
    {
        auto request = fixture.Request(2);
        request.transaction = Transaction(201, 1, 2);
        const auto commit = fixture.sgw.apply(request);
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::CONFLICTING_TRANSACTION);
        CHECK(*fixture.sgw.generationOf(Session()) == 2);
    }
}

TEST_CASE("lte/handover/core-path: a stale generation or association epoch is refused")
{
    Fixture fixture;
    SUBCASE("a request written against generation zero")
    {
        const auto commit = fixture.sgw.apply(fixture.Request(0));
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::STALE_GENERATION);
    }
    SUBCASE("a request written under another association epoch")
    {
        auto request = fixture.Request();
        request.mmeAssociationEpoch = 7;
        const auto commit = fixture.sgw.apply(request);
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::STALE_ASSOCIATION);
    }
    SUBCASE("a session the map does not hold")
    {
        auto request = fixture.Request();
        request.session = Session(999);
        const auto commit = fixture.sgw.apply(request);
        CHECK_FALSE(commit.committed);
        CHECK(commit.refusal->refusal == CorePathRefusal::UNKNOWN_SESSION);
    }
}

TEST_CASE("lte/handover/core-path: the sender consults the installed map before and after the update")
{
    Fixture fixture;
    const std::vector<uint8_t> payload{0x45, 0x00, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04};

    // Before: one downlink per bearer, both to the source cell's own socket and
    // on the source's own local TEIDs.
    REQUIRE(fixture.sgw.sendDownlink(Session(), DefaultEbi, payload.data(), payload.size()));
    REQUIRE(fixture.sgw.sendDownlink(Session(), DedicatedEbi, payload.data(), payload.size()));
    // Both datagrams land on the same cell socket, so one drain holds both.
    const auto before = fixture.sourceCell.drain();
    REQUIRE(before.size() == 2);
    std::vector<uint32_t> beforeTeids;
    for (const auto &datagram : before)
    {
        CHECK(datagram.packet.messageType == gtpu::TPdu);
        CHECK(datagram.packet.payload == payload);
        beforeTeids.push_back(datagram.packet.teid);
    }
    std::sort(beforeTeids.begin(), beforeTeids.end());
    CHECK(beforeTeids == std::vector<uint32_t>{fixture.sourceDefaultTeid, fixture.sourceDedicatedTeid});
    CHECK(fixture.targetCell.drain().empty());

    REQUIRE(fixture.sgw.apply(fixture.Request()).committed);

    // After: the same call, with the same arguments, now goes to the target's
    // own local TEID because the map says so. The caller names a bearer and
    // never a destination.
    REQUIRE(fixture.sgw.sendDownlink(Session(), DefaultEbi, payload.data(), payload.size()));
    REQUIRE(fixture.sgw.sendDownlink(Session(), DedicatedEbi, payload.data(), payload.size()));
    const auto after = fixture.targetCell.drain();
    REQUIRE(after.size() == 2);
    std::vector<uint32_t> teids;
    for (const auto &datagram : after)
    {
        CHECK(datagram.packet.messageType == gtpu::TPdu);
        CHECK(datagram.packet.payload == payload);
        teids.push_back(datagram.packet.teid);
    }
    std::sort(teids.begin(), teids.end());
    CHECK(teids == std::vector<uint32_t>{fixture.targetDefaultTeid, fixture.targetDedicatedTeid});
    CHECK(fixture.sourceCell.drain().empty());

    // The observation record shows the destination came from the map and which
    // generation it came from.
    REQUIRE(fixture.sgw.sendRecords().size() == 4);
    CHECK(fixture.sgw.sendRecords().back().generation == 2);
    CHECK(fixture.sgw.sendRecords().back().destination.address == TargetIp);
}

TEST_CASE("lte/handover/core-path: a confirmation is read back out of the installed map")
{
    Fixture fixture;
    const auto request = fixture.Request();
    REQUIRE(fixture.sgw.apply(request).committed);

    const auto confirmation = ReadIsolatedPathState(fixture.sgw, request.session, request.mmeAssociationEpoch);
    REQUIRE(confirmation.has_value());
    CHECK(confirmation->session == request.session);
    CHECK(confirmation->transaction == request.transaction);
    CHECK(confirmation->pathGeneration == 2);
    REQUIRE(confirmation->installed.size() == 2);
    for (const auto &path : confirmation->installed)
        CHECK(path.originalSource.complete());

    const auto result = VerifyIsolatedPathConfirmation(request, *confirmation);
    CHECK(result.confirmed());
    CHECK(result.verdict == CorePathConfirmationRefusal::CONFIRMED);
}

TEST_CASE("lte/handover/core-path: a confirmation that does not match the request is refused")
{
    Fixture fixture;
    auto request = fixture.Request();
    REQUIRE(fixture.sgw.apply(request).committed);
    const auto confirmation = *ReadIsolatedPathState(fixture.sgw, request.session, request.mmeAssociationEpoch);

    SUBCASE("another session")
    {
        auto copy = confirmation;
        copy.session = Session(999);
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::WRONG_SESSION);
    }
    SUBCASE("another transaction")
    {
        auto copy = confirmation;
        copy.transaction = Transaction(201, 1, 9);
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict ==
              CorePathConfirmationRefusal::WRONG_TRANSACTION);
    }
    SUBCASE("another association epoch")
    {
        auto copy = confirmation;
        copy.mmeAssociationEpoch = 9;
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict ==
              CorePathConfirmationRefusal::WRONG_ASSOCIATION_EPOCH);
    }
    SUBCASE("a generation this request could not have produced")
    {
        auto copy = confirmation;
        copy.pathGeneration = 4;
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::STALE_GENERATION);
    }
    SUBCASE("a missing EBI")
    {
        auto copy = confirmation;
        copy.installed.pop_back();
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::MISSING_EBI);
    }
    SUBCASE("another destination")
    {
        auto copy = confirmation;
        copy.installed[0].endpoint.teid = 0x7777;
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::WRONG_ENDPOINT);
    }
    SUBCASE("another SGW-side tunnel identity")
    {
        auto copy = confirmation;
        copy.installed[1].sgwTeid = 999;
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::WRONG_SGW_TEID);
    }
    SUBCASE("an endpoint that is not on the target cell")
    {
        auto copy = confirmation;
        copy.installed[0].endpoint.address = {127, 0, 0, 11};
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict == CorePathConfirmationRefusal::WRONG_ENDPOINT);
    }
    SUBCASE("a role the accepted set never stated")
    {
        auto copy = confirmation;
        copy.installed[1].role = BearerRole::DEFAULT;
        CHECK(VerifyIsolatedPathConfirmation(request, copy).verdict ==
              CorePathConfirmationRefusal::BEARER_RELATIONSHIP_INVALID);
    }
}

TEST_CASE("lte/handover/core-path: an end marker names the old tunnel and moves nothing")
{
    Fixture fixture;
    REQUIRE(fixture.sgw.apply(fixture.Request()).committed);

    REQUIRE(fixture.sgw.sendEndMarker(Session(), DefaultEbi));
    const auto received = fixture.sourceCell.drain();
    REQUIRE(received.size() == 1);
    const auto &packet = received.front().packet;
    CHECK(packet.messageType == gtpu::EndMarker);
    CHECK(packet.teid == fixture.sourceDefaultTeid);
    CHECK(packet.payload.empty());
    CHECK(received.front().from == InetAddress(Ipv4ToString(SgwIp), SgwPort));
    // The End Marker went to the old path only.
    CHECK(fixture.targetCell.drain().empty());
    // And it changed nothing here: the map still holds the new destination.
    CHECK(*fixture.sgw.generationOf(Session()) == 2);
    CHECK(fixture.sgw.installed(Session(), DefaultEbi)->endpoint == fixture.TargetDefault());
    CHECK(fixture.sgw.endMarkersSent() == 1);
}

TEST_CASE("lte/handover/core-path: an end marker before any update is refused")
{
    Fixture fixture;
    CHECK_FALSE(fixture.sgw.sendEndMarker(Session(), DefaultEbi));
    CHECK(fixture.sourceCell.drain().empty());
    CHECK(fixture.sgw.endMarkersSent() == 0);
}

TEST_CASE("lte/handover/core-path: a live-mode instance refuses every operation")
{
    IsolatedSgw sgw{ExecutionMode::LIVE_EPC, Ipv4ToString(SgwIp), SgwPort};
    CHECK_FALSE(sgw.enabled());

    CorePathRefusalRecord failure;
    CHECK_FALSE(sgw.installSession(Session(), 1,
                                   {Bearer(DefaultEbi, BearerRole::DEFAULT, std::nullopt, SgwDefaultTeid,
                                           {SourceIp, 1, 2152})},
                                   &failure));
    CHECK(failure.refusal == CorePathRefusal::LIVE_MODE_DISABLED);

    IsolatedPathUpdateRequest request;
    request.transaction = Transaction();
    request.session = Session();
    request.mmeAssociationEpoch = 1;
    request.targetEnbId = ElsewhereEnbId;
    request.targetS1uAddress = TargetIp;
    request.expectedGeneration = 1;
    request.bearers = {Bearer(DefaultEbi, BearerRole::DEFAULT, std::nullopt, SgwDefaultTeid, {TargetIp, 1, 2152})};
    const auto commit = sgw.apply(request);
    CHECK_FALSE(commit.committed);
    REQUIRE(commit.refusal.has_value());
    CHECK(commit.refusal->refusal == CorePathRefusal::LIVE_MODE_DISABLED);
    CHECK_FALSE(sgw.sendDownlink(Session(), DefaultEbi, nullptr, 0));
}
