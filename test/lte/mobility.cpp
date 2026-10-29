//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALI GUNGOR.
//
// ECM-IDLE inter-eNB cell reselection at the simulated radio and eNB boundary:
// how a mobility uplink reaches the MME, and how it differs from a fresh Attach.

#include <ext/doctest/doctest.h>

#include <algorithm>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/radio_link.hpp>
#include <lib/udp/server.hpp>

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
    config.ueLinkPort = 0;
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

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, lte::ue::link::MessageType type, std::vector<uint8_t> payload,
               const InetAddress &from)
{
    auto frame = lte::ue::link::Encode({type, ue.ueId, std::move(payload)});
    mux.handleRadioFrame(frame.data(), frame.size(), from);
}

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, lte::ue::link::MessageType type, std::vector<uint8_t> payload)
{
    SendRadio(mux, ue, type, std::move(payload), ue.radio.LocalAddress());
}

// MMEC || M-TMSI || protected NAS, the identity prefix a mobility uplink carries.
std::vector<uint8_t> MobilityNas(const std::vector<uint8_t> &nas, uint32_t mTmsi = 0x12345678)
{
    std::vector<uint8_t> payload{0x05,
                                 static_cast<uint8_t>(mTmsi >> 24U), static_cast<uint8_t>(mTmsi >> 16U),
                                 static_cast<uint8_t>(mTmsi >> 8U), static_cast<uint8_t>(mTmsi)};
    payload.insert(payload.end(), nas.begin(), nas.end());
    return payload;
}

const std::vector<uint8_t> ProtectedTauRequest{0x37, 0x01, 0x02, 0x03, 0x04, 0x00, 0x07, 0x48};

// A UE whose EPS session is fully established on this cell: confirmed default
// bearer plus two confirmed dedicated contexts, an S1 connection and access
// transport, exactly as one left behind by an earlier Attach. The identity and
// the transport TEIDs are spaced so several UEs can be established at once.
EnbUeEntry &Establish(EnbMultiplexer &mux, const FakeUe &ue, uint32_t &enbUeS1apId, uint32_t &defaultLocalTeid)
{
    auto &entry = mux.registry().registerPeer(ue.ueId, ue.radio.LocalAddress());
    mux.registry().bindEnbUeS1apId(entry, 100 + ue.ueId);
    mux.registry().setMmeUeS1apId(entry, 200 + ue.ueId);
    entry.s1 = UeS1State::BEARER_ACTIVE;
    entry.accessGeneration = 3;
    const uint32_t base = 400 + ue.ueId * 10;
    entry.bearer.establish({5, 9, ue.ueId, {127, 0, 0, 2}, 30 + ue.ueId, base + 5});
    entry.bearer.activateUe(ue.ueId, 5, {10, 45, 0, static_cast<uint8_t>(ue.ueId)});
    mux.registry().bindLocalTeid(entry, base + 5);
    defaultLocalTeid = base + 5;
    for (uint8_t ebi : {6, 7})
    {
        auto &dedicated = mux.registry().addDedicatedBearer(
            entry, {ebi, 7, ue.ueId, {127, 0, 0, 2}, 30 + ue.ueId + ebi, base + ebi, 5});
        dedicated.activateUe(ue.ueId, ebi, entry.bearer.ueIpv4());
        mux.registry().bindLocalTeid(entry, dedicated, base + ebi);
    }
    enbUeS1apId = 100 + ue.ueId;
    return entry;
}

bool Contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}
} // namespace

TEST_CASE("lte/mobility: a mobility uplink opens a fresh S1 connection and keeps the retained EPS bearers")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    uint32_t sourceEnbUeS1apId = 0, sourceTeid = 0;
    auto &entry = Establish(mux, ue, sourceEnbUeS1apId, sourceTeid);
    mux.registry().releaseS1(entry);
    REQUIRE(entry.s1 == UeS1State::IDLE_RETAINED);
    REQUIRE(entry.bearer.logicalConfirmed());
    REQUIRE(entry.dedicatedBearers.size() == 2);
    sender.sent.clear();

    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));

    // The MME saw one Initial UE Message carrying the protected TAU Request and
    // an S-TMSI the target cell can route on.
    REQUIRE(sender.count(12) == 1);
    CHECK(Contains(sender.sent.front().pdu, ProtectedTauRequest));
    CHECK(entry.s1 == UeS1State::CONTEXT_PENDING);
    CHECK(entry.enbUeS1apId != 0);
    CHECK(entry.enbUeS1apId != sourceEnbUeS1apId);

    // The logical EPS session is not the access. A reselected cell is a new
    // access to the same session, so nothing about the bearer contexts is torn
    // down and the access epoch restarts alongside the new access. That epoch
    // is a real one, numbered one: zero is reserved for "no epoch at all" and
    // every generation-bound message carrying it is refused. The access
    // transport itself is still gone and is restored later by the network, so
    // the default bearer is not signalling-established again yet.
    CHECK(entry.bearer.logicalConfirmed());
    CHECK(entry.bearer.logicalExists());
    CHECK_FALSE(entry.bearer.signalingEstablished());
    CHECK(entry.dedicatedBearers.size() == 2);
    CHECK(entry.accessGeneration == 1);
}

TEST_CASE("lte/mobility: a fresh Attach uplink still tears down the previous logical session")
{
    // The contrast the routing depends on: the same entry state reached by an
    // ordinary uplink Attach is a new logical session, so the retained EPS
    // bearer contexts go away rather than being reconciled with the network.
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    uint32_t sourceEnbUeS1apId = 0, sourceTeid = 0;
    auto &entry = Establish(mux, ue, sourceEnbUeS1apId, sourceTeid);
    mux.registry().releaseS1(entry);
    REQUIRE(entry.bearer.logicalConfirmed());
    REQUIRE(entry.dedicatedBearers.size() == 2);

    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK, {0x07, 0x41});

    REQUIRE(sender.count(12) == 1);
    CHECK(entry.s1 == UeS1State::CONTEXT_PENDING);
    CHECK_FALSE(entry.bearer.logicalConfirmed());
    CHECK(entry.dedicatedBearers.empty());
    CHECK(entry.accessGeneration == 0);
}

TEST_CASE("lte/mobility: a mobility uplink cannot replace an active S1 connection")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    uint32_t id = 0, teid = 0;
    auto &entry = Establish(mux, ue, id, teid);
    REQUIRE(entry.s1Active());
    sender.sent.clear();
    const auto rejected = mux.recoveryCounters().staleMessagesRejected;

    // A reselection only opens an S1 connection where none exists. Replacing a
    // live one would drop the MME's UE context without telling it.
    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));
    CHECK(mux.recoveryCounters().staleMessagesRejected == rejected + 1);
    CHECK(sender.sent.empty());
    CHECK(entry.s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entry.enbUeS1apId == id);
}

TEST_CASE("lte/mobility: a mobility uplink with no protected NAS cannot be sent or received")
{
    // The identity prefix alone is not a procedure: with no protected NAS there
    // is nothing to route, so such a frame is refused on both ends of the link
    // and can never reach a cell at all.
    const std::vector<uint8_t> identityOnly{0x05, 0x12, 0x34, 0x56, 0x78};
    CHECK_THROWS(lte::ue::link::Encode({lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, 1, identityOnly}));

    // The same frame hand-built, because no encoder will produce it: the header
    // of a valid mobility uplink with its length rewritten to the prefix alone.
    auto frame = lte::ue::link::Encode({lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, 1,
                                        MobilityNas(ProtectedTauRequest)});
    frame[7] = static_cast<uint8_t>(identityOnly.size());
    frame.resize(lte::ue::link::HeaderSize + identityOnly.size());
    CHECK_THROWS(lte::ue::link::Decode(frame.data(), frame.size()));

    // A zero M-TMSI is not an identity the network can associate with any
    // session, and the cell refuses it rather than opening an S1 connection.
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    uint32_t id = 0, teid = 0;
    auto &entry = Establish(mux, ue, id, teid);
    mux.registry().releaseS1(entry);
    sender.sent.clear();
    const auto rejected = mux.recoveryCounters().staleMessagesRejected;

    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest, 0));
    CHECK(mux.recoveryCounters().staleMessagesRejected == rejected + 1);
    CHECK(sender.sent.empty());
    CHECK(entry.s1 == UeS1State::IDLE_RETAINED);
    CHECK(entry.bearer.logicalConfirmed());
}

TEST_CASE("lte/mobility: a reselected cell allocates its own S1 identity and never reuses the source cell's")
{
    CaptureSender sourceSender;
    EnbMultiplexer source(TestEnbConfig(), sourceSender);
    FakeUe ue(1);
    uint32_t sourceEnbUeS1apId = 0, sourceTeid = 0;
    auto &sourceEntry = Establish(source, ue, sourceEnbUeS1apId, sourceTeid);

    // The target is a different eNB with its own registry. It has never seen
    // this UE, so it owns no S1 identity, no access TEID and no bearer context
    // for it: whatever the source cell was using is not presented here.
    CaptureSender targetSender;
    EnbMultiplexer target(TestEnbConfig(), targetSender);
    SendRadio(target, ue, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));

    auto *targetEntry = target.registry().find(1);
    REQUIRE(targetEntry != nullptr);
    REQUIRE(targetSender.count(12) == 1);
    CHECK(targetEntry->enbUeS1apId != 0);
    CHECK(targetEntry->enbUeS1apId != sourceEnbUeS1apId);
    CHECK(targetEntry->s1 == UeS1State::CONTEXT_PENDING);
    CHECK_FALSE(targetEntry->bearer.logicalExists());
    CHECK(targetEntry->dedicatedBearers.empty());
    CHECK(target.registry().findByLocalTeid(sourceTeid) == nullptr);

    // The source cell still holds exactly what it held; the move did not reach
    // across and rewrite it.
    CHECK(sourceEntry.enbUeS1apId == sourceEnbUeS1apId);
    CHECK(sourceEntry.s1 == UeS1State::BEARER_ACTIVE);
    CHECK(sourceEntry.bearer.logicalConfirmed());
    CHECK(source.registry().findByLocalTeid(sourceTeid) == &sourceEntry);
}

TEST_CASE("lte/mobility: a target eNB that cannot transmit discards the provisional S1 context")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    uint32_t id = 0, teid = 0;
    auto &entry = Establish(mux, ue, id, teid);
    mux.registry().releaseS1(entry);
    sender.sent.clear();
    mux.armLossBeforeNextS1apSend();

    // Nothing reached the MME, so no S1 procedure exists. The provisional
    // context is discarded instead of lingering in CONTEXT_PENDING and blocking
    // a later attempt, and the failure is counted rather than swallowed.
    SendRadio(mux, ue, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));
    CHECK(mux.injectionTriggered());
    CHECK(sender.sent.empty());
    CHECK(entry.s1 == UeS1State::IDLE_RETAINED);
    CHECK(entry.enbUeS1apId == 0);
    // The session survives a failed access attempt.
    CHECK(entry.bearer.logicalConfirmed());
    CHECK(entry.dedicatedBearers.size() == 2);
}

TEST_CASE("lte/mobility: a mobility uplink is refused from an endpoint that does not own the UE identity")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe owner(1), stranger(9);
    uint32_t id = 0, teid = 0;
    Establish(mux, owner, id, teid);
    sender.sent.clear();
    const auto rejected = mux.recoveryCounters().staleMessagesRejected;

    // A reselection is a decision the UE makes about a configured target cell.
    // It is never a decision a datagram can make on the UE's behalf, so a
    // foreign endpoint cannot open an S1 connection in this UE's name.
    SendRadio(mux, owner, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest),
              stranger.radio.LocalAddress());
    // Nor may an endpoint that owns one identity borrow another.
    SendRadio(mux, stranger, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest),
              owner.radio.LocalAddress());

    CHECK(mux.recoveryCounters().staleMessagesRejected == rejected + 2);
    CHECK(sender.sent.empty());
    CHECK(mux.registry().find(1)->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(mux.registry().find(1)->enbUeS1apId == id);
    CHECK(mux.registry().find(9) == nullptr);
}

TEST_CASE("lte/mobility: one UE's failed mobility leaves the other UEs of the cell untouched")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1), ueB(2);
    uint32_t idA = 0, teidA = 0, idB = 0, teidB = 0;
    auto &a = Establish(mux, ueA, idA, teidA);
    auto &b = Establish(mux, ueB, idB, teidB);
    mux.registry().releaseS1(a);
    sender.sent.clear();
    mux.armLossBeforeNextS1apSend();

    // UE A's target access cannot be established at all.
    SendRadio(mux, ueA, lte::ue::link::MessageType::NAS_UPLINK_MOBILITY, MobilityNas(ProtectedTauRequest));
    CHECK(mux.injectionTriggered());
    CHECK(sender.sent.empty());
    CHECK(a.s1 == UeS1State::IDLE_RETAINED);

    // UE B keeps its own identity, its own S1 mapping and its own access
    // transport: a failure on one UE is not evidence about another.
    CHECK(b.s1 == UeS1State::BEARER_ACTIVE);
    CHECK(b.enbUeS1apId == idB);
    CHECK(b.bearer.logicalConfirmed());
    CHECK(b.dedicatedBearers.size() == 2);
    CHECK(mux.registry().findByLocalTeid(teidB) == &b);
    CHECK(mux.registry().findByLocalTeid(teidA) == nullptr);
    CHECK(mux.registry().find(2) == &b);
}
