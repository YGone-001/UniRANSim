//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 6: S1AP Paging decoding, non-UE-associated eNB dispatch, simulated
// radio paging delivery and UE-side paging/Service-Request behaviour.

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/types.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/paging.hpp>
#include <lte/ue/radio_link.hpp>
#include <lib/udp/server.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using namespace lte::enb;

std::vector<uint8_t> FromHex(const std::string &hex)
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
        result.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return result;
}

// One real Open5GS 2.8 MME Paging PDU captured on the laboratory S1 interface
// while the target UE was ECM-IDLE. The S-TMSI is a radio-level identity
// assigned by the lab MME; it is not a subscriber secret. The bytes were
// independently decoded with the reference ASN.1 dissector, which reported
// UEIdentityIndexValue=1, s-TMSI MMEC=1 / M-TMSI=0xC00007C4, ps-domain and one
// TAI 460/02/TAC=1.
const char *LiveOpen5gsPagingPdu =
    "000A4027000004005040020040002B40060010C00007C4006D400100002E400B00002F40060064F0200001";

constexpr uint32_t LiveMTmsi = 0xC00007C4u;

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
            const auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
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

std::optional<lte::ue::link::Message> ReceiveRadio(udp::UdpServer &socket, int timeoutMs)
{
    uint8_t buffer[lte::ue::link::MaxDataPduSize + lte::ue::link::HeaderSize];
    InetAddress peer;
    const int received = socket.Receive(buffer, sizeof(buffer), timeoutMs, peer);
    if (received <= 0)
        return std::nullopt;
    return lte::ue::link::Decode(buffer, static_cast<size_t>(received));
}

s1ap::PagingMessage Page(uint16_t index, uint8_t mmeCode, uint32_t mTmsi, uint16_t tac,
                         std::optional<uint8_t> drx = std::nullopt)
{
    s1ap::PagingMessage message{};
    message.ueIdentityIndexValue = index;
    message.identity = s1ap::PagingMessage::Identity::S_TMSI;
    message.sTmsi = {mmeCode, mTmsi};
    message.cnDomain = 0;
    message.taiList = {{{"460", "02"}, tac}};
    message.pagingDrx = drx;
    return message;
}

// --- UE mobility helpers ------------------------------------------------------

std::array<uint8_t, 11> Guti(uint8_t mmeCode, uint32_t mTmsi)
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x02, mmeCode, static_cast<uint8_t>(mTmsi >> 24U),
            static_cast<uint8_t>(mTmsi >> 16U), static_cast<uint8_t>(mTmsi >> 8U), static_cast<uint8_t>(mTmsi)};
}

// TS 24.301 9.9.3.33 type 2, element count - 1 = 0, one TAI 460/02/TAC=1. This
// is the exact assignment a live Open5GS MME sent in Attach Accept.
std::vector<uint8_t> AssignedTaiList()
{
    return {0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
}

lte::ue::MobilityContext Registered(const std::array<uint8_t, 11> &guti)
{
    lte::ue::MobilityContext context;
    context.ecm = lte::ue::EcmState::CONNECTED;
    context.securityContextValid = true;
    context.onAttachComplete(5, {10, 45, 0, 9}, guti, AssignedTaiList(), 0x30);
    context.onUserPlaneReady();
    return context;
}

lte::ue::MobilityContext IdleRegistered(const std::array<uint8_t, 11> &guti)
{
    auto context = Registered(guti);
    context.onS1ContextReleased();
    return context;
}

lte::ue::SecurityContext ActiveSecurity(uint32_t count = 7)
{
    lte::ue::SecurityContext security{};
    security.valid = true;
    security.keysDerived = true;
    security.securityActive = true;
    security.ksi = 3;
    security.integrity = lte::ue::IntegrityAlgorithm::EIA2;
    security.ulNasCount = count;
    return security;
}

lte::ue::link::PagingNotification Notification(uint8_t mmeCode, uint32_t mTmsi, uint16_t tac = 1)
{
    return {mmeCode, mTmsi, tac};
}

// Builds the S1AP envelope around a raw Paging payload so a test can perform
// byte surgery on the IE container while keeping the lengths consistent.
std::vector<uint8_t> WrapPagingPayload(const std::vector<uint8_t> &payload)
{
    std::vector<uint8_t> pdu{0x00, 0x0A, 0x40, static_cast<uint8_t>(payload.size())};
    pdu.insert(pdu.end(), payload.begin(), payload.end());
    return pdu;
}

std::vector<uint8_t> PagingPayload(const std::vector<uint8_t> &pdu)
{
    return std::vector<uint8_t>(pdu.begin() + 4, pdu.end());
}

} // namespace

// --- S1AP Paging codec --------------------------------------------------------

TEST_CASE("lte/paging/codec: a live Open5GS Paging PDU decodes to the verified fields")
{
    const auto fixture = FromHex(LiveOpen5gsPagingPdu);
    const auto page = s1ap::DecodePaging(fixture.data(), fixture.size());
    CHECK(page.ueIdentityIndexValue == 1);
    CHECK(page.identity == s1ap::PagingMessage::Identity::S_TMSI);
    CHECK(page.sTmsi.mmeCode == 1);
    CHECK(page.sTmsi.mTmsi == LiveMTmsi);
    CHECK(page.cnDomain == 0);
    REQUIRE(page.taiList.size() == 1);
    CHECK(page.taiList[0].plmn.mcc == "460");
    CHECK(page.taiList[0].plmn.mnc == "02");
    CHECK(page.taiList[0].tac == 1);
    CHECK_FALSE(page.pagingDrx.has_value());
}

TEST_CASE("lte/paging/codec: the PDU probes as non-UE-associated Paging procedure 10")
{
    const auto fixture = FromHex(LiveOpen5gsPagingPdu);
    const auto probe = s1ap::ProbeS1apPdu(fixture.data(), fixture.size());
    CHECK(probe.kind == s1ap::S1apPdu::Kind::INITIATING);
    CHECK(probe.procedureCode == 10);
}

TEST_CASE("lte/paging/codec: the fixture encoder reproduces the live MME Paging PDU byte for byte")
{
    auto page = Page(1, 1, LiveMTmsi, 1);
    const auto encoded = s1ap::EncodePaging(page);
    CHECK(encoded == FromHex(LiveOpen5gsPagingPdu));
    const auto decoded = s1ap::DecodePaging(encoded.data(), encoded.size());
    CHECK(decoded.sTmsi.mTmsi == LiveMTmsi);
}

TEST_CASE("lte/paging/codec: a multiple-item TAI list round-trips with every TAI validated")
{
    auto page = Page(1, 1, LiveMTmsi, 1);
    page.taiList.push_back({{"460", "02"}, 2});
    page.taiList.push_back({{"460", "02"}, 0x1234});
    page.pagingDrx = 2;
    const auto encoded = s1ap::EncodePaging(page);
    const auto decoded = s1ap::DecodePaging(encoded.data(), encoded.size());
    REQUIRE(decoded.taiList.size() == 3);
    CHECK(decoded.taiList[0].tac == 1);
    CHECK(decoded.taiList[1].tac == 2);
    CHECK(decoded.taiList[2].tac == 0x1234);
    REQUIRE(decoded.pagingDrx.has_value());
    CHECK(*decoded.pagingDrx == 2);
}

TEST_CASE("lte/paging/codec: a TAI list for another tracking area still decodes and is filtered later")
{
    const auto encoded = s1ap::EncodePaging(Page(1, 1, LiveMTmsi, 7));
    const auto decoded = s1ap::DecodePaging(encoded.data(), encoded.size());
    REQUIRE(decoded.taiList.size() == 1);
    CHECK(decoded.taiList[0].tac == 7);
}

TEST_CASE("lte/paging/codec: every truncation of the live Paging PDU is rejected")
{
    const auto fixture = FromHex(LiveOpen5gsPagingPdu);
    for (size_t length = 0; length < fixture.size(); ++length)
        CHECK_THROWS(s1ap::DecodePaging(fixture.data(), length));
}

TEST_CASE("lte/paging/codec: a wrong procedure code is rejected")
{
    auto fixture = FromHex(LiveOpen5gsPagingPdu);
    fixture[1] = 11; // Downlink NAS Transport
    CHECK_THROWS(s1ap::DecodePaging(fixture.data(), fixture.size()));
}

TEST_CASE("lte/paging/codec: a non-initiating PDU kind is rejected")
{
    auto fixture = FromHex(LiveOpen5gsPagingPdu);
    fixture[0] = 0x40; // PDU CHOICE = successfulOutcome
    CHECK_THROWS(s1ap::DecodePaging(fixture.data(), fixture.size()));
}

TEST_CASE("lte/paging/codec: a wrong procedure criticality is rejected")
{
    auto fixture = FromHex(LiveOpen5gsPagingPdu);
    fixture[2] = 0x00; // reject instead of the specified ignore
    CHECK_THROWS(s1ap::DecodePaging(fixture.data(), fixture.size()));
}

TEST_CASE("lte/paging/codec: a missing mandatory information element is rejected")
{
    // Drop the CN Domain field (id 0x006D, criticality 0x40, length 1, value)
    // from the IE container and fix up the count and open-type length.
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    REQUIRE(payload.size() == 39);
    payload.erase(payload.begin() + 19, payload.begin() + 24); // the 5 CN Domain octets
    payload[2] = 0x03;                                        // IE count 4 -> 3
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS_WITH_AS(s1ap::DecodePaging(pdu.data(), pdu.size()),
                         "Paging is missing a mandatory information element", s1ap::CodecError);
}

TEST_CASE("lte/paging/codec: a duplicate mandatory information element is rejected")
{
    // Duplicate the UE Identity Index value field (7 octets) and fix the count.
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    const std::vector<uint8_t> indexField(payload.begin() + 3, payload.begin() + 10);
    payload.insert(payload.begin() + 10, indexField.begin(), indexField.end());
    payload[2] = 0x05;
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: an unexpected IE criticality is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    payload[5] = 0x00; // stamp UE Identity Index value as reject-critical
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: a non-canonical ten-bit identity index value is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    payload[8] = 0x41; // set an APER pad bit that must be zero
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: a zero M-TMSI in the paging identity is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    payload[15] = payload[16] = payload[17] = payload[18] = 0x00;
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: an extended paging identity choice is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    payload[13] = 0x80; // extension bit of the UEPagingIdentity CHOICE
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: an IMSI paging identity is classified and kept, not mistaken for S-TMSI")
{
    s1ap::PagingMessage page = Page(42, 0, LiveMTmsi, 1);
    page.identity = s1ap::PagingMessage::Identity::IMSI;
    page.imsi = {0x64, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0xF1}; // 460020000000001 TBCD
    const auto encoded = s1ap::EncodePaging(page);
    const auto decoded = s1ap::DecodePaging(encoded.data(), encoded.size());
    CHECK(decoded.identity == s1ap::PagingMessage::Identity::IMSI);
    CHECK(decoded.imsi == page.imsi);
    CHECK(decoded.ueIdentityIndexValue == 42);
}

TEST_CASE("lte/paging/codec: an IMSI paging identity with a non-decimal digit is rejected")
{
    s1ap::PagingMessage page = Page(42, 0, LiveMTmsi, 1);
    page.identity = s1ap::PagingMessage::Identity::IMSI;
    page.imsi = {0x64, 0x0E, 0x20, 0x00, 0x00, 0x00, 0x00, 0xF1};
    CHECK_THROWS(s1ap::EncodePaging(page));
}

TEST_CASE("lte/paging/codec: an unknown ignore-criticality IE is skipped safely")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    const std::vector<uint8_t> optional{0x03, 0xE7, 0x40, 0x01, 0x00}; // id 999, ignore, len 1
    payload.insert(payload.end(), optional.begin(), optional.end());
    payload[2] = 0x05;
    const auto pdu = WrapPagingPayload(payload);
    const auto page = s1ap::DecodePaging(pdu.data(), pdu.size());
    CHECK(page.sTmsi.mTmsi == LiveMTmsi);
}

TEST_CASE("lte/paging/codec: an unknown reject-criticality IE fails the decode")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    const std::vector<uint8_t> unsupported{0x03, 0xE7, 0x00, 0x01, 0x00}; // id 999, reject
    payload.insert(payload.end(), unsupported.begin(), unsupported.end());
    payload[2] = 0x05;
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: an oversized TAI list count is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    // Claim 16 tracking areas while the encoded length holds only one.
    payload[28] = 0xF0;
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

TEST_CASE("lte/paging/codec: a TAI list item with the wrong identifier is rejected")
{
    auto payload = PagingPayload(FromHex(LiveOpen5gsPagingPdu));
    payload[30] = 0x2E; // id-TAIItem 47 -> 46
    const auto pdu = WrapPagingPayload(payload);
    CHECK_THROWS(s1ap::DecodePaging(pdu.data(), pdu.size()));
}

// --- eNB dispatch and fanout --------------------------------------------------

TEST_CASE("lte/paging/enb: Paging is accepted without any active S1AP UE identity")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000101u, 1));

    CHECK_NOTHROW(mux.handleS1ap(pdu.data(), pdu.size(), 0));
    CHECK(mux.pagingCounters().received == 1);
    CHECK(mux.pagingCounters().valid == 1);
    CHECK(mux.pagingCounters().invalid == 0);
    CHECK(mux.pagingCounters().notificationsDelivered == 0);
    CHECK(mux.registry().size() == 0);
    CHECK(sender.sent.empty());
}

TEST_CASE("lte/paging/enb: Paging on a UE-associated stream is rejected, not attached to a UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;
    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000102u, 1));

    CHECK_NOTHROW(mux.handleS1ap(pdu.data(), pdu.size(), 3));
    CHECK(mux.pagingCounters().invalid == 1);
    CHECK(mux.pagingCounters().notificationsDelivered == 0);
    CHECK_FALSE(ReceiveRadio(ue.radio, 50).has_value());
    CHECK(mux.registry().find(1)->s1 == UeS1State::IDLE_RETAINED);
}

TEST_CASE("lte/paging/enb: Paging does not allocate an S1AP UE context or an S1-U bearer")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;
    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000103u, 1));

    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    const auto *stored = mux.registry().find(1);
    REQUIRE(stored != nullptr);
    CHECK(stored->enbUeS1apId == 0);
    CHECK(stored->mmeUeS1apId == 0);
    CHECK_FALSE(stored->s1Active());
    CHECK_FALSE(stored->bearer.signalingEstablished());
    CHECK_FALSE(mux.registry().findByLocalTeid(0x1234) != nullptr);
    CHECK(sender.count(12) == 0); // no Initial UE Message was produced
    CHECK(sender.sent.empty());
}

TEST_CASE("lte/paging/enb: a page for the served tracking area reaches the retained idle UE")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000104u, 1));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);

    const auto message = ReceiveRadio(ue.radio, 500);
    REQUIRE(message.has_value());
    CHECK(message->type == lte::ue::link::MessageType::PAGING_INDICATION);
    CHECK(message->ueId == 1);
    const auto notification =
        lte::ue::link::DecodePagingNotification(message->payload.data(), message->payload.size());
    CHECK(notification.mmeCode == 1);
    CHECK(notification.mTmsi == 0xC0000104u);
    CHECK(notification.tac == 1);
    CHECK(mux.pagingCounters().notificationsDelivered == 1);
    CHECK(mux.registry().find(1)->pagingNotifications == 1);
}

TEST_CASE("lte/paging/enb: a page for another tracking area is filtered out")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000105u, 3));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    CHECK(mux.pagingCounters().valid == 1);
    CHECK(mux.pagingCounters().filteredByTac == 1);
    CHECK(mux.pagingCounters().notificationsDelivered == 0);
    CHECK_FALSE(ReceiveRadio(ue.radio, 100).has_value());
}

TEST_CASE("lte/paging/enb: a page for another PLMN with the served TAC is filtered out")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;

    auto page = Page(1, 1, 0xC0000106u, 1);
    page.taiList[0].plmn = {"310", "260"};
    const auto pdu = s1ap::EncodePaging(page);
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    CHECK(mux.pagingCounters().filteredByTac == 1);
    CHECK_FALSE(ReceiveRadio(ue.radio, 100).has_value());
}

TEST_CASE("lte/paging/enb: only retained idle UEs receive the notification")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe idle(1);
    FakeUe active(2);
    FakeUe never(3);
    mux.registry().registerPeer(1, idle.radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;
    auto &activeEntry = mux.registry().registerPeer(2, active.radio.LocalAddress());
    activeEntry.s1 = UeS1State::BEARER_ACTIVE;
    mux.registry().registerPeer(3, never.radio.LocalAddress()).s1 = UeS1State::NO_S1;

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000107u, 1));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);

    const auto idleMessage = ReceiveRadio(idle.radio, 500);
    REQUIRE(idleMessage.has_value());
    CHECK(idleMessage->type == lte::ue::link::MessageType::PAGING_INDICATION);
    CHECK_FALSE(ReceiveRadio(active.radio, 100).has_value());
    CHECK_FALSE(ReceiveRadio(never.radio, 100).has_value());
    CHECK(mux.pagingCounters().notificationsDelivered == 1);
}

TEST_CASE("lte/paging/enb: duplicate pages leave the UE registry indexes intact")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    auto &entry = mux.registry().registerPeer(1, ue.radio.LocalAddress());
    entry.s1 = UeS1State::IDLE_RETAINED;
    mux.registry().bindEnbUeS1apId(entry, 41);
    mux.registry().setMmeUeS1apId(entry, 42);

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000108u, 1));
    for (int i = 0; i < 4; ++i)
        mux.handleS1ap(pdu.data(), pdu.size(), 0);

    CHECK(mux.pagingCounters().received == 4);
    CHECK(mux.pagingCounters().notificationsDelivered == 4);
    CHECK(mux.registry().find(1) == &entry);
    CHECK(mux.registry().findByPeer(ue.radio.LocalAddress()) == &entry);
    CHECK(mux.registry().findByEnbUeS1apId(41) == &entry);
    CHECK(mux.registry().findByMmeUeS1apId(42) == &entry);
    CHECK(entry.pagingNotifications == 4);
}

TEST_CASE("lte/paging/enb: Paging leaves an active UE context completely unchanged")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe idle(1);
    FakeUe active(2);
    mux.registry().registerPeer(1, idle.radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;
    auto &entry = mux.registry().registerPeer(2, active.radio.LocalAddress());
    const uint32_t localTeid = mux.registry().allocateLocalTeid();
    entry.bearer.establish({5, 9, 2, {10, 10, 0, 139}, 0x0000A018u, localTeid});
    entry.bearer.activateUe(2, 5, {10, 45, 0, 42});
    mux.registry().bindLocalTeid(entry, localTeid);
    mux.registry().bindEnbUeS1apId(entry, 7);
    mux.registry().setMmeUeS1apId(entry, 8);
    entry.sgwPeer = InetAddress("10.10.0.139", 2152);
    entry.s1 = UeS1State::BEARER_ACTIVE;

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC0000109u, 1));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);

    CHECK(entry.s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entry.enbUeS1apId == 7);
    CHECK(entry.mmeUeS1apId == 8);
    CHECK(entry.bearer.active());
    CHECK(entry.bearer.parameters().localTeid == localTeid);
    CHECK(mux.registry().findByLocalTeid(localTeid) == &entry);
    CHECK(entry.pagingNotifications == 0);
}

TEST_CASE("lte/paging/enb: a malformed page is rejected without disturbing later signalling")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    mux.registry().registerPeer(1, ue.radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;

    auto malformed = FromHex(LiveOpen5gsPagingPdu);
    malformed.resize(malformed.size() - 6);
    CHECK_NOTHROW(mux.handleS1ap(malformed.data(), malformed.size(), 0));
    CHECK(mux.pagingCounters().invalid == 1);

    // The same object still serves a valid page and still holds the UE index.
    const auto valid = s1ap::EncodePaging(Page(1, 1, 0xC000010Au, 1));
    CHECK_NOTHROW(mux.handleS1ap(valid.data(), valid.size(), 0));
    CHECK(mux.pagingCounters().valid == 1);
    const auto message = ReceiveRadio(ue.radio, 500);
    REQUIRE(message.has_value());
    CHECK(message->type == lte::ue::link::MessageType::PAGING_INDICATION);
}

TEST_CASE("lte/paging/enb: a CS-domain page is not delivered to an EPS bearer")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    mux.registry().registerPeer(1, ue.radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;

    auto page = Page(1, 1, 0xC000010Bu, 1);
    page.cnDomain = 1;
    const auto pdu = s1ap::EncodePaging(page);
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    CHECK(mux.pagingCounters().csDomainIgnored == 1);
    CHECK(mux.pagingCounters().notificationsDelivered == 0);
    CHECK_FALSE(ReceiveRadio(ue.radio, 100).has_value());
}

TEST_CASE("lte/paging/enb: an IMSI page is counted as unsupported and never fanned out")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ue(1);
    mux.registry().registerPeer(1, ue.radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;

    auto page = Page(1, 0, LiveMTmsi, 1);
    page.identity = s1ap::PagingMessage::Identity::IMSI;
    page.imsi = {0x64, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0xF1};
    const auto pdu = s1ap::EncodePaging(page);
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    CHECK(mux.pagingCounters().valid == 1);
    CHECK(mux.pagingCounters().unsupportedIdentity == 1);
    CHECK(mux.pagingCounters().notificationsDelivered == 0);
    CHECK_FALSE(ReceiveRadio(ue.radio, 100).has_value());
}

TEST_CASE("lte/paging/enb: the fanout stays within the configured maxUes bound")
{
    EnbConfig config = TestEnbConfig();
    config.maxUes = 2;
    CaptureSender sender;
    EnbMultiplexer mux(config, sender);
    std::vector<std::unique_ptr<FakeUe>> ues;
    for (uint32_t id = 1; id <= 2; ++id)
    {
        ues.push_back(std::make_unique<FakeUe>(id));
        mux.registry().registerPeer(id, ues.back()->radio.LocalAddress()).s1 = UeS1State::IDLE_RETAINED;
    }

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC000010Cu, 1));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    CHECK(mux.pagingCounters().notificationsDelivered == 2);
    for (auto &ue : ues)
    {
        const auto message = ReceiveRadio(ue->radio, 500);
        REQUIRE(message.has_value());
        CHECK(message->type == lte::ue::link::MessageType::PAGING_INDICATION);
    }
}

TEST_CASE("lte/paging/enb: the simulated notification frame rejects a malformed payload")
{
    const std::vector<uint8_t> shortPayload{0x01, 0x00, 0x00, 0x00, 0x01};
    CHECK_THROWS(lte::ue::link::DecodePagingNotification(shortPayload.data(), shortPayload.size()));
    CHECK_THROWS(lte::ue::link::EncodePagingNotification({1, 0, 1}));
    CHECK_THROWS(lte::ue::link::Encode({lte::ue::link::MessageType::PAGING_INDICATION, 1, shortPayload}));
}

// --- UE identity and state ----------------------------------------------------

TEST_CASE("lte/paging/ue: the S-TMSI is re-derived from the assigned GUTI, MMEC included")
{
    const auto guti = Guti(1, 0xC00007C4u);
    const auto derived = lte::ue::STmsiFromGuti(guti);
    REQUIRE(derived.has_value());
    CHECK(derived->mmeCode == 1);
    CHECK(derived->mTmsi == 0xC00007C4u);

    auto wrongType = guti;
    wrongType[0] = 0xF5; // not an EPS GUTI type octet
    CHECK_FALSE(lte::ue::STmsiFromGuti(wrongType).has_value());
}

TEST_CASE("lte/paging/ue: a matching page in ECM-IDLE is accepted")
{
    const auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::ACCEPTED);
}

TEST_CASE("lte/paging/ue: a wrong MMEC is rejected even with a matching M-TMSI")
{
    const auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(2, 0xC00007C4u)) ==
          lte::ue::PagingMatch::IDENTITY_MISMATCH);
}

TEST_CASE("lte/paging/ue: a wrong M-TMSI is rejected even with a matching MMEC")
{
    const auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C5u)) ==
          lte::ue::PagingMatch::IDENTITY_MISMATCH);
}

TEST_CASE("lte/paging/ue: an absent GUTI causes a safe rejection")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.guti.reset();
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::NO_IDENTITY);
}

TEST_CASE("lte/paging/ue: an EMM-DEREGISTERED UE ignores paging")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.startDetach();
    context.onDetachAccepted();
    CHECK(context.emm == lte::ue::EmmState::DEREGISTERED);
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::NOT_REGISTERED);
}

TEST_CASE("lte/paging/ue: an ECM-CONNECTED UE does not start a needless Service Request")
{
    const auto context = Registered(Guti(1, 0xC00007C4u));
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::CONNECTED);
}

TEST_CASE("lte/paging/ue: a UE without an EPS security context cannot answer")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.securityContextValid = false;
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::NO_SECURITY);
}

TEST_CASE("lte/paging/ue: a pending Detach prevents paging-triggered restoration")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.startDetach();
    auto security = ActiveSecurity();
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::PROCEDURE_PENDING);
    CHECK_FALSE(lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security)
                    .has_value());
    CHECK(security.ulNasCount == 7);
}

TEST_CASE("lte/paging/ue: a pending TAU does not start a conflicting Service Request")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.startTau(true);
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::PROCEDURE_PENDING);
}

TEST_CASE("lte/paging/ue: a page outside the assigned TAI list is ignored")
{
    const auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u, 7)) ==
          lte::ue::PagingMatch::AREA_MISMATCH);
}

TEST_CASE("lte/paging/ue: an unparseable TAI list cannot authorize a response")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    context.taiList = {0x40, 0x64}; // truncated assignment
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::AREA_MISMATCH);
    CHECK_FALSE(lte::ue::TaiListContains({}, {"460", "02"}, 1));
    CHECK_FALSE(lte::ue::TaiListContains({0x00}, {"460", "02"}, 1));
}

TEST_CASE("lte/paging/ue: the TAI list parser accepts the Open5GS single-TAI assignment")
{
    CHECK(lte::ue::TaiListContains(AssignedTaiList(), {"460", "02"}, 1));
    CHECK_FALSE(lte::ue::TaiListContains(AssignedTaiList(), {"460", "02"}, 2));
    CHECK_FALSE(lte::ue::TaiListContains(AssignedTaiList(), {"460", "01"}, 1));
}

TEST_CASE("lte/paging/ue: a valid page produces a genuine compact EPS Service Request")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    auto security = ActiveSecurity(5);
    const auto nas = lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security);
    REQUIRE(nas.has_value());
    REQUIRE(nas->size() == 4);
    CHECK((*nas)[0] == 0xC7);              // compact security header
    CHECK(((*nas)[1] >> 5U) == security.ksi); // KSI in the short sequence field
    CHECK(context.pending == lte::ue::PendingProcedure::SERVICE_REQUEST);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK_FALSE(context.canForwardUserPlane());
}

TEST_CASE("lte/paging/ue: one accepted page advances the uplink NAS COUNT exactly once")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    auto security = ActiveSecurity(5);
    REQUIRE(lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security).has_value());
    CHECK(security.ulNasCount == 6);
}

TEST_CASE("lte/paging/ue: a duplicate page neither duplicates the request nor the COUNT")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    auto security = ActiveSecurity(5);
    const auto first = lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security);
    REQUIRE(first.has_value());
    const auto countAfterFirst = security.ulNasCount;

    for (int i = 0; i < 3; ++i)
        CHECK_FALSE(
            lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security).has_value());
    CHECK(security.ulNasCount == countAfterFirst);
    CHECK(context.pending == lte::ue::PendingProcedure::SERVICE_REQUEST);
}

TEST_CASE("lte/paging/ue: a paging Service Request timeout keeps the bounded retry policy intact")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    auto security = ActiveSecurity();
    REQUIRE(lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security).has_value());

    // A network rejection clears the pending procedure and restores the EPS
    // registration without silently re-arming a Service Request.
    context.onProcedureRejected();
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK(context.emm == lte::ue::EmmState::REGISTERED);
    CHECK(lte::ue::EvaluatePaging(context, {"460", "02"}, Notification(1, 0xC00007C4u)) ==
          lte::ue::PagingMatch::ACCEPTED);
}

TEST_CASE("lte/paging/ue: restoration completes the paging-triggered procedure and resumes forwarding")
{
    auto context = IdleRegistered(Guti(1, 0xC00007C4u));
    auto security = ActiveSecurity();
    REQUIRE(lte::ue::RespondToPaging(context, {"460", "02"}, Notification(1, 0xC00007C4u), security).has_value());
    context.onServiceRestored(0xA1u, 0xB2u, 0xC3u, 0xD4u);
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
    CHECK(context.ecm == lte::ue::EcmState::CONNECTED);
    CHECK(context.canForwardUserPlane());
    CHECK(context.enbTeid == 0xC3u);
    CHECK(context.sgwTeid == 0xD4u);
}

// --- Multi-UE paging isolation ------------------------------------------------

TEST_CASE("lte/paging/multi: a page for UE A never matches UE B")
{
    const auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    const auto b = IdleRegistered(Guti(1, 0xC0000B02u));
    CHECK(lte::ue::EvaluatePaging(a, {"460", "02"}, Notification(1, 0xC0000A01u)) ==
          lte::ue::PagingMatch::ACCEPTED);
    CHECK(lte::ue::EvaluatePaging(b, {"460", "02"}, Notification(1, 0xC0000A01u)) ==
          lte::ue::PagingMatch::IDENTITY_MISMATCH);
}

TEST_CASE("lte/paging/multi: both idle UEs identify their own page independently")
{
    const auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    const auto b = IdleRegistered(Guti(2, 0xC0000B02u));
    CHECK(lte::ue::EvaluatePaging(a, {"460", "02"}, Notification(1, 0xC0000A01u)) ==
          lte::ue::PagingMatch::ACCEPTED);
    CHECK(lte::ue::EvaluatePaging(b, {"460", "02"}, Notification(2, 0xC0000B02u)) ==
          lte::ue::PagingMatch::ACCEPTED);
    // A page with UE A's M-TMSI but UE B's MMEC matches neither.
    CHECK(lte::ue::EvaluatePaging(a, {"460", "02"}, Notification(2, 0xC0000A01u)) ==
          lte::ue::PagingMatch::IDENTITY_MISMATCH);
    CHECK(lte::ue::EvaluatePaging(b, {"460", "02"}, Notification(2, 0xC0000A01u)) ==
          lte::ue::PagingMatch::IDENTITY_MISMATCH);
}

TEST_CASE("lte/paging/multi: only the paged UE consumes a NAS COUNT and enters restoration")
{
    auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    auto b = IdleRegistered(Guti(1, 0xC0000B02u));
    auto securityA = ActiveSecurity(11);
    auto securityB = ActiveSecurity(23);

    REQUIRE(lte::ue::RespondToPaging(a, {"460", "02"}, Notification(1, 0xC0000A01u), securityA).has_value());
    CHECK(securityA.ulNasCount == 12);
    CHECK(securityB.ulNasCount == 23);
    CHECK(b.pending == lte::ue::PendingProcedure::NONE);
    CHECK(b.bearer == lte::ue::EpsBearerState::SIGNALING_ESTABLISHED);
    CHECK(b.ecm == lte::ue::EcmState::IDLE);
}

TEST_CASE("lte/paging/multi: UE B stays fully idle while UE A restores and then pages independently")
{
    auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    auto b = IdleRegistered(Guti(1, 0xC0000B02u));
    auto securityA = ActiveSecurity(1);
    auto securityB = ActiveSecurity(1);

    REQUIRE(lte::ue::RespondToPaging(a, {"460", "02"}, Notification(1, 0xC0000A01u), securityA).has_value());
    a.onServiceRestored(0x10u, 0x11u, 0x12u, 0x13u);
    CHECK(b.ecm == lte::ue::EcmState::IDLE);
    CHECK(b.pending == lte::ue::PendingProcedure::NONE);
    CHECK(securityB.ulNasCount == 1);

    // UE B's own page is still accepted while A is connected.
    REQUIRE(lte::ue::RespondToPaging(b, {"460", "02"}, Notification(1, 0xC0000B02u), securityB).has_value());
    CHECK(securityB.ulNasCount == 2);
    CHECK(a.ecm == lte::ue::EcmState::CONNECTED);
}

TEST_CASE("lte/paging/multi: a page with an unknown S-TMSI resumes no UE")
{
    const auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    const auto b = IdleRegistered(Guti(1, 0xC0000B02u));
    const auto unknown = Notification(1, 0xC000FFFFu);
    CHECK(lte::ue::EvaluatePaging(a, {"460", "02"}, unknown) == lte::ue::PagingMatch::IDENTITY_MISMATCH);
    CHECK(lte::ue::EvaluatePaging(b, {"460", "02"}, unknown) == lte::ue::PagingMatch::IDENTITY_MISMATCH);
}

TEST_CASE("lte/paging/multi: a detached UE ignores a stale page while its neighbour stays operational")
{
    auto a = IdleRegistered(Guti(1, 0xC0000A01u));
    auto b = IdleRegistered(Guti(1, 0xC0000B02u));
    a.startDetach();
    a.onDetachAccepted();
    auto securityA = ActiveSecurity();
    CHECK_FALSE(lte::ue::RespondToPaging(a, {"460", "02"}, Notification(1, 0xC0000A01u), securityA).has_value());
    CHECK(securityA.ulNasCount == 7);
    CHECK(lte::ue::EvaluatePaging(b, {"460", "02"}, Notification(1, 0xC0000B02u)) ==
          lte::ue::PagingMatch::ACCEPTED);
}

TEST_CASE("lte/paging/multi: restoration allocates a fresh eNB TEID and invalidates the released one")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe ueA(1);

    // Attach-style S1 context for UE A with a first local TEID.
    auto &entry = mux.registry().registerPeer(1, ueA.radio.LocalAddress());
    const uint32_t firstTeid = mux.registry().allocateLocalTeid();
    mux.registry().bindEnbUeS1apId(entry, 11);
    mux.registry().setMmeUeS1apId(entry, 22);
    entry.bearer.establish({5, 9, 1, {10, 10, 0, 139}, 0x0000A001u, firstTeid});
    entry.bearer.activateUe(1, 5, {10, 45, 0, 2});
    mux.registry().bindLocalTeid(entry, firstTeid);
    entry.sgwPeer = InetAddress("10.10.0.139", 2152);
    entry.s1 = UeS1State::BEARER_ACTIVE;

    // Legitimate S1 release through the MME command.
    const auto release = s1ap::EncodeUeContextReleaseCommand(22, 11, "radioNetwork", 20);
    mux.handleS1ap(release.data(), release.size(), 1);
    CHECK(mux.registry().findByLocalTeid(firstTeid) == nullptr);
    CHECK(entry.s1 == UeS1State::IDLE_RETAINED);

    // Paging then restores a brand-new context with a brand-new TEID.
    const auto page = s1ap::EncodePaging(Page(1, 1, 0xC000010Du, 1));
    mux.handleS1ap(page.data(), page.size(), 0);

    // The matching UE answers with a compact Service Request over the radio
    // link; the eNB allocates a fresh eNB-UE-S1AP-ID for the new S1 context.
    const std::vector<uint8_t> serviceRequest{0x01, 0xC0, 0x00, 0x01, 0x0D, 0xC7, 0x00, 0x00, 0x00};
    const auto radio = lte::ue::link::Encode({lte::ue::link::MessageType::SERVICE_REQUEST, 1, serviceRequest});
    mux.handleRadioFrame(radio.data(), radio.size(), ueA.radio.LocalAddress());
    const uint32_t freshEnbId = entry.enbUeS1apId;
    CHECK(freshEnbId != 0);
    CHECK(freshEnbId != 11);
    CHECK(sender.count(12) == 1); // one Initial UE Message

    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = 33;
    request.enbUeS1apId = freshEnbId;
    request.ueAmbrUl = 1000000;
    request.ueAmbrDl = 2000000;
    request.encryptionAlgorithms = {0x00, 0x00};
    request.integrityAlgorithms = {0x20, 0x00};
    s1ap::ErabToBeSetupItem erab{};
    erab.erabId = 5;
    erab.qci = 9;
    erab.transportLayerAddress = {10, 10, 0, 139};
    erab.gtpTeid = TeidToBytes(0x0000A002u);
    request.erabs.push_back(erab);
    const auto setup = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(setup.data(), setup.size(), 1);

    CHECK(entry.s1 == UeS1State::CONTEXT_ESTABLISHED);
    CHECK(entry.bearer.parameters().localTeid != firstTeid);
    CHECK(mux.registry().findByLocalTeid(firstTeid) == nullptr);
    CHECK(mux.registry().findByLocalTeid(entry.bearer.parameters().localTeid) == &entry);
    CHECK(entry.enbUeS1apId == freshEnbId);
    CHECK(entry.mmeUeS1apId == 33);
}

TEST_CASE("lte/paging/multi: per-UE paging counters stay independent across a fanout")
{
    CaptureSender sender;
    EnbMultiplexer mux(TestEnbConfig(), sender);
    FakeUe a(1);
    FakeUe b(2);
    auto &entryA = mux.registry().registerPeer(1, a.radio.LocalAddress());
    auto &entryB = mux.registry().registerPeer(2, b.radio.LocalAddress());
    entryA.s1 = UeS1State::IDLE_RETAINED;
    entryB.s1 = UeS1State::IDLE_RETAINED;

    const auto pdu = s1ap::EncodePaging(Page(1, 1, 0xC000010Eu, 1));
    mux.handleS1ap(pdu.data(), pdu.size(), 0);
    mux.handleS1ap(pdu.data(), pdu.size(), 0);

    CHECK(entryA.pagingNotifications == 2);
    CHECK(entryB.pagingNotifications == 2);
    CHECK(mux.pagingCounters().notificationsDelivered == 4);
    CHECK(entryA.s1 == UeS1State::IDLE_RETAINED);
    CHECK(entryB.s1 == UeS1State::IDLE_RETAINED);
}
