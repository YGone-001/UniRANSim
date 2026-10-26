// This file is a part of UERANSIM project.
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
#include <algorithm>
#include <ext/doctest/doctest.h>
#include <lte/enb/codec.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/security.hpp>
#include <string>

namespace
{
using namespace lte;
using namespace lte::enb;
namespace nas = lte::ue::nas;

std::vector<uint8_t> Hex(const std::string &value)
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i < value.size(); i += 2)
        result.push_back(static_cast<uint8_t>(std::stoul(value.substr(i, 2), nullptr, 16)));
    return result;
}
// Independently encoded by pycrate 0.8.1, not the C++ encoder under test.
// Reproduce with tools/lte-modify-fixtures.py. Synthetic identifiers/NAS.
const auto QosFixture = Hex("00060023000003000000020065000800020001001e0010000024000b0c000720066200c95b0107");
const auto AmbrFixture =
    Hex("0006002f00000400000002006500080002000100420008100f42404007a120001e0010000024000b0c000720066200c95b0107");
const auto GbrFixture =
    Hex("00060031000003000000020065000800020001001e001e00002400190c8007201003e8004001f40020fa00207d00066200c95b0107");
const auto TransportFixture = Hex(
    "00060033000003000000020065000800020001001e0020000024001b4c000720066200c95b0107000000b9000a07c0c000020a12345678");
const auto ResponseFixture = Hex("20060025000004000040020065000840020001001f400600002540010c0020400800002340030e0780");

s1ap::ErabModifyRequest Request()
{
    return s1ap::DecodeErabModifyRequest(QosFixture.data(), QosFixture.size());
}

tft::PacketFilter Filter(uint8_t id, uint16_t port)
{
    tft::PacketFilter f;
    f.identifier = id;
    f.precedence = id;
    f.direction = tft::FilterDirection::UPLINK_ONLY;
    f.hasProtocol = true;
    f.protocol = 17;
    f.hasLocalPort = true;
    f.localPortLow = f.localPortHigh = port;
    return f;
}

std::vector<uint8_t> Packet(uint16_t port, bool downlink = false)
{
    auto p = Hex("4500001c00000000401100000a2d0002c00002010000000100080000");
    p[downlink ? 22 : 20] = static_cast<uint8_t>(port >> 8U);
    p[downlink ? 23 : 21] = static_cast<uint8_t>(port);
    return p;
}

tft::TftState InitialTft()
{
    tft::TftState state;
    state.apply({tft::OperationCode::CREATE_NEW, false, {Filter(0, 7000), Filter(1, 8000)}});
    return state;
}

std::vector<uint8_t> Snapshot(const tft::TftState &state)
{
    return tft::Encode({tft::OperationCode::CREATE_NEW, false, state.filters()});
}

class Sender : public IS1apSender
{
  public:
    std::vector<std::vector<uint8_t>> sent;
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(pdu);
    }
};

EnbConfig Config()
{
    EnbConfig c;
    c.plmn = {"460", "02"};
    c.enbId = 1;
    c.tac = 1;
    c.ueLinkAddress = c.s1uAddress = "127.0.0.1";
    c.ueLinkPort = c.s1uPort = 0;
    c.allowLoopbackS1u = true;
    c.maxUes = 4;
    return c;
}

EnbUeEntry &AddUe(EnbMultiplexer &mux, uint32_t id)
{
    auto &r = mux.registry();
    auto &ue = r.registerPeer(id, InetAddress("127.0.0.1", static_cast<uint16_t>(50000 + id)));
    r.bindEnbUeS1apId(ue, id);
    r.setMmeUeS1apId(ue, 100 + id);
    ue.s1 = UeS1State::BEARER_ACTIVE;
    ue.bearer.establish({5, 9, id, {127, 0, 0, 2}, 10 + id, 100 + id});
    ue.bearer.activateUe(id, 5, {10, 45, 0, static_cast<uint8_t>(id)});
    r.bindLocalTeid(ue, 100 + id);
    auto &dedicated = r.addDedicatedBearer(ue, {6, 7, id, {127, 0, 0, 2}, 20 + id, 200 + id, 5});
    dedicated.activateUe(id, 6, ue.bearer.ueIpv4());
    r.bindLocalTeid(ue, dedicated, 200 + id);
    return ue;
}

void Dispatch(EnbMultiplexer &mux, const s1ap::ErabModifyRequest &request)
{
    auto pdu = s1ap::EncodeErabModifyRequest(request);
    mux.handleS1ap(pdu.data(), pdu.size(), 1);
}
} // namespace

TEST_CASE("lte/modify: independent APER fixture decodes mandatory NAS exactly once")
{
    auto r = Request();
    CHECK(r.mmeUeS1apId == 101);
    CHECK(r.enbUeS1apId == 1);
    REQUIRE(r.erabs.size() == 1);
    CHECK(r.erabs[0].erabId == 6);
    CHECK(r.erabs[0].qos.qci == 7);
    CHECK(r.erabs[0].qos.priorityLevel == 8);
    CHECK(r.erabs[0].nasPdu == Hex("6200c95b0107"));
    CHECK_FALSE(r.erabs[0].transport);
    CHECK(s1ap::EncodeErabModifyRequest(r) == QosFixture);
}

TEST_CASE("lte/modify: independent UE AMBR and GBR fixtures preserve all rates")
{
    const auto ambr = s1ap::DecodeErabModifyRequest(AmbrFixture.data(), AmbrFixture.size());
    REQUIRE(ambr.ueAmbr);
    CHECK(ambr.ueAmbr->downlink == 1000000);
    CHECK(ambr.ueAmbr->uplink == 500000);
    const auto gbr = s1ap::DecodeErabModifyRequest(GbrFixture.data(), GbrFixture.size());
    REQUIRE(gbr.erabs[0].qos.gbr);
    const auto &q = *gbr.erabs[0].qos.gbr;
    CHECK(q.maximumDl == 256000);
    CHECK(q.maximumUl == 128000);
    CHECK(q.guaranteedDl == 64000);
    CHECK(q.guaranteedUl == 32000);
    CHECK(s1ap::EncodeErabModifyRequest(gbr) == GbrFixture);
}

TEST_CASE("lte/modify: independent transport extension has no setup root transport fields")
{
    const auto r = s1ap::DecodeErabModifyRequest(TransportFixture.data(), TransportFixture.size());
    REQUIRE(r.erabs[0].transport);
    CHECK(r.erabs[0].transport->address == std::array<uint8_t, 4>{192, 0, 2, 10});
    CHECK(r.erabs[0].transport->teid == 0x12345678);
    CHECK(s1ap::EncodeErabModifyRequest(r) == TransportFixture);
}

TEST_CASE("lte/modify: every truncated independent APER prefix fails")
{
    for (const auto *fixture : {&QosFixture, &AmbrFixture, &GbrFixture, &TransportFixture})
        for (size_t n = 0; n < fixture->size(); ++n)
            CHECK_THROWS_AS(s1ap::DecodeErabModifyRequest(fixture->data(), n), s1ap::CodecError);
}

TEST_CASE("lte/modify: wrong PDU procedure and criticalities fail closed")
{
    for (auto change : {std::pair<size_t, uint8_t>{0, 0x20}, {1, 5}, {2, 0x40}, {9, 0x40}, {24, 0x40}})
    {
        auto p = QosFixture;
        p[change.first] = change.second;
        CHECK_THROWS_AS(s1ap::DecodeErabModifyRequest(p.data(), p.size()), s1ap::CodecError);
    }
}

TEST_CASE("lte/modify: missing mandatory and unknown reject IEs fail")
{
    for (size_t index : {size_t(8), size_t(14), size_t(20)})
    {
        auto p = QosFixture;
        p[index] = 99;
        CHECK_THROWS_AS(s1ap::DecodeErabModifyRequest(p.data(), p.size()), s1ap::CodecError);
    }
}

TEST_CASE("lte/modify: duplicate EBI request fails before state changes")
{
    auto r = Request();
    r.erabs.push_back(r.erabs[0]);
    const auto p = s1ap::EncodeErabModifyRequest(r);
    CHECK_THROWS_AS(s1ap::DecodeErabModifyRequest(p.data(), p.size()), s1ap::CodecError);
}

TEST_CASE("lte/modify: partial response bytes match independent ASN1 fixture")
{
    CHECK(s1ap::EncodeErabModifyResponse(101, 1, {6}, {{7, "radioNetwork", 30}}) == ResponseFixture);
    CHECK_NOTHROW(s1ap::EncodeErabModifyResponse(101, 1, {}, {{7, "radioNetwork", 30}}));
    CHECK_THROWS_AS(s1ap::EncodeErabModifyResponse(101, 1, {6}, {{6, "radioNetwork", 30}}), s1ap::CodecError);
}

TEST_CASE("lte/modify: malformed transport extension criticality length and IPv6 fail")
{
    for (const auto &change : {std::pair<size_t, uint8_t>{43, 0x40}, {44, 0}, {45, 0x80}, {46, 0xF8}})
    {
        auto p = TransportFixture;
        REQUIRE(change.first < p.size());
        p[change.first] = change.second;
        CHECK_THROWS_AS(s1ap::DecodeErabModifyRequest(p.data(), p.size()), s1ap::CodecError);
    }
}

TEST_CASE("lte/modify: NAS QoS only TFT only combined and empty requests")
{
    for (const auto &value : {"6200c95b0109", "6200c9360180", "6200c95b0109360180", "6200c9"})
    {
        const auto p = Hex(value);
        const auto m = nas::DecodeDownlink(p.data(), p.size());
        CHECK(m.type == nas::DownlinkEmm::MODIFY_EPS_BEARER_CONTEXT);
        CHECK(m.messageType == 0xC9);
        CHECK(m.modifyBearer.epsBearerIdentity == 6);
        CHECK(m.modifyBearer.procedureTransactionId == 0);
    }
}

TEST_CASE("lte/modify: NAS accept and reject have independent wire values")
{
    CHECK(nas::EncodeModifyEpsBearerContextAccept(6, 0) == Hex("6200ca"));
    CHECK(nas::EncodeModifyEpsBearerContextReject(6, 7, 41) == Hex("6207cb29"));
    CHECK_THROWS_AS(nas::EncodeModifyEpsBearerContextAccept(0, 0), nas::DecodeError);
}

TEST_CASE("lte/modify: NAS malformed unknown optional duplicate and QoS failures")
{
    for (const auto &value : {"6200c95b", "6200c95b0209", "6200c95b0100", "6200c95b020901", "6200c9300101",
                              "6200c95b01095b0107", "6200c93600", "6200c93602ff"})
    {
        const auto p = Hex(value);
        CHECK_THROWS_AS(nas::DecodeModifyEpsBearerContextRequest(p.data(), p.size()), nas::EsmError);
    }
}

TEST_CASE("lte/modify: EPS QoS extensions are retained without throughput enforcement")
{
    for (size_t length : {size_t(1), size_t(5), size_t(9), size_t(13)})
    {
        std::vector<uint8_t> p{0x52, 0, 0xC9, 0x5B, static_cast<uint8_t>(length)};
        p.resize(5 + length, 1);
        p[5] = 9;
        auto r = nas::DecodeModifyEpsBearerContextRequest(p.data(), p.size());
        nas::EpsBearerConfiguration b;
        b.ebi = 5;
        b.qci = 7;
        nas::ApplyBearerModification(b, r);
        CHECK(b.qci == 9);
        REQUIRE(b.epsQos.size() == length);
        CHECK(b.epsQos.back() == (length == 1 ? 9 : 1));
    }
}

TEST_CASE("lte/modify: unknown bearer reserved and unmatched PTI keep old state")
{
    nas::EpsBearerConfiguration b;
    b.ebi = 6;
    b.qci = 7;
    b.linkedEbi = 5;
    b.tft = InitialTft();
    const auto old = Snapshot(b.tft);
    for (auto identity : {std::pair<uint8_t, uint8_t>{7, 0}, {6, 255}, {6, 1}})
    {
        nas::ModifyEpsBearerContextRequest r;
        r.epsBearerIdentity = identity.first;
        r.procedureTransactionId = identity.second;
        r.epsQos = Hex("09");
        try
        {
            nas::ApplyBearerModification(b, r);
            FAIL("must reject");
        }
        catch (const nas::EsmError &e)
        {
            CHECK(e.cause == (identity.first == 7 ? 43 : identity.second == 255 ? 81 : 47));
        }
        CHECK(b.qci == 7);
        CHECK(b.linkedEbi == 5);
        CHECK(Snapshot(b.tft) == old);
    }
}

TEST_CASE("lte/modify: combined QoS and invalid TFT never partially commits")
{
    nas::EpsBearerConfiguration b;
    b.ebi = 6;
    b.qci = 7;
    b.linkedEbi = 5;
    b.epsQos = {7};
    b.tft = InitialTft();
    const auto old = Snapshot(b.tft);
    nas::ModifyEpsBearerContextRequest r;
    r.epsBearerIdentity = 6;
    r.epsQos = Hex("09");
    r.tft = Hex("82200005401b592f10200105401b5a");
    CHECK_THROWS_AS(nas::ApplyBearerModification(b, r), nas::EsmError);
    CHECK(b.qci == 7);
    CHECK(b.epsQos == std::vector<uint8_t>{7});
    CHECK(Snapshot(b.tft) == old);
}

TEST_CASE("lte/modify: TFT failed add replace delete preserve complete bytes and classification")
{
    for (auto op :
         {tft::OperationCode::ADD_FILTERS, tft::OperationCode::REPLACE_FILTERS, tft::OperationCode::DELETE_FILTERS})
    {
        auto state = InitialTft();
        const auto old = Snapshot(state);
        const auto first = op == tft::OperationCode::ADD_FILTERS ? Filter(2, 9000) : Filter(0, 9000);
        const auto last = op == tft::OperationCode::ADD_FILTERS ? Filter(1, 9001) : Filter(15, 9001);
        CHECK_THROWS_AS(state.apply({op, false, {first, last}}), tft::TftError);
        CHECK(Snapshot(state) == old);
        const auto packet = Packet(7000);
        REQUIRE(state.classify(packet.data(), packet.size(), true));
        CHECK(state.classify(packet.data(), packet.size(), true)->identifier == 0);
    }
}

TEST_CASE("lte/modify: TFT replacement changes real packet classification and direction")
{
    auto state = InitialTft();
    const auto old = Packet(7000), updated = Packet(7001);
    REQUIRE(state.classify(old.data(), old.size(), true));
    CHECK_FALSE(state.classify(updated.data(), updated.size(), true));
    auto filter = Filter(0, 7001);
    filter.precedence = 250;
    state.apply({tft::OperationCode::REPLACE_FILTERS, false, {filter}});
    CHECK_FALSE(state.classify(old.data(), old.size(), true));
    REQUIRE(state.classify(updated.data(), updated.size(), true));
    CHECK(state.classify(updated.data(), updated.size(), true)->precedence == 250);
    CHECK_FALSE(state.classify(updated.data(), updated.size(), false));
}

TEST_CASE("lte/modify: TFT delete wire uses identifier octets and whole delete has no list")
{
    auto state = InitialTft();
    const auto bytes = Hex("a100");
    auto op = tft::Decode(bytes.data(), bytes.size());
    CHECK(tft::Encode(op) == bytes);
    state.apply(op);
    REQUIRE(state.size() == 1);
    CHECK(state.filters()[0].identifier == 1);
    const auto clear = Hex("40");
    state.apply(tft::Decode(clear.data(), clear.size()));
    CHECK(state.empty());
    const auto noOp = Hex("c0");
    CHECK_NOTHROW(state.apply(tft::Decode(noOp.data(), noOp.size())));
}

TEST_CASE("lte/modify: TFT duplicate IDs precedence capacity extensions and invalid operation rollback")
{
    auto state = InitialTft();
    const auto old = Snapshot(state);
    CHECK_THROWS_AS(state.apply({tft::OperationCode::ADD_FILTERS, false, {Filter(2, 2), Filter(2, 3)}}), tft::TftError);
    auto f = Filter(2, 2);
    f.precedence = 1;
    CHECK_THROWS_AS(state.apply({tft::OperationCode::ADD_FILTERS, false, {f}}), tft::TftError);
    CHECK_THROWS_AS(state.apply({static_cast<tft::OperationCode>(7), false, {}}), tft::TftError);
    CHECK_THROWS_AS(state.apply({tft::OperationCode::NO_TFT_OPERATION, true, {}}), tft::TftError);
    std::vector<tft::PacketFilter> many;
    for (uint8_t i = 2; i < 16; ++i)
        many.push_back(Filter(i, i));
    CHECK_THROWS_AS(state.apply({tft::OperationCode::ADD_FILTERS, false, many}), tft::TftError);
    CHECK(Snapshot(state) == old);
}

TEST_CASE("lte/modify: TFT ranges use 41 and 51 component types and full octet precedence")
{
    const auto p = Hex("2130fa0a411b581b5a5113881389");
    auto value = tft::Decode(p.data(), p.size());
    REQUIRE(value.filters.size() == 1);
    CHECK(value.filters[0].precedence == 250);
    CHECK(value.filters[0].localPortHigh == 7002);
    CHECK(value.filters[0].remotePortHigh == 5001);
    CHECK(tft::Encode(value) == p);
}

TEST_CASE("lte/modify: QoS metadata keeps bearer identity address transport readiness and kind")
{
    BearerContext b(BearerKind::DEDICATED);
    b.establish({6, 7, 1, {192, 0, 2, 1}, 11, 22, 5});
    b.activateUe(1, 6, {10, 45, 0, 1});
    b.modifyQos({9, 8, true, false, GbrQos{1000, 2000, 500, 1000}});
    CHECK(b.active());
    CHECK(b.kind() == BearerKind::DEDICATED);
    CHECK(b.parameters().erabId == 6);
    CHECK(b.parameters().linkedDefaultEbi == 5);
    CHECK(b.parameters().sgwTeid == 11);
    CHECK(b.parameters().localTeid == 22);
    CHECK(b.ueIpv4() == std::array<uint8_t, 4>{10, 45, 0, 1});
    CHECK(b.parameters().qos.gbr->maximumUl == 2000);
    CHECK_THROWS_AS(b.modifyQos({0, 8, false, false, {}}), BearerError);
    CHECK(b.parameters().qci == 9);
    CHECK_THROWS_AS(b.modifyQos({1, 8, false, false, GbrQos{100, 100, 200, 100}}), BearerError);
    CHECK(b.parameters().qci == 9);
}

TEST_CASE("lte/modify: transport validation preserves complete old endpoint on failure")
{
    BearerContext b;
    b.establish({5, 9, 1, {192, 0, 2, 1}, 11, 22});
    for (auto addr : {std::array<uint8_t, 4>{0, 0, 0, 0}, {224, 0, 0, 1}, {255, 255, 255, 255}})
        CHECK_THROWS_AS(b.modifyTransport(addr, 33), BearerError);
    CHECK_THROWS_AS(b.modifyTransport({192, 0, 2, 2}, 0), BearerError);
    CHECK(b.parameters().sgwAddress == std::array<uint8_t, 4>{192, 0, 2, 1});
    CHECK(b.parameters().sgwTeid == 11);
    b.modifyTransport({192, 0, 2, 2}, 33);
    CHECK(b.parameters().sgwTeid == 33);
    CHECK(b.parameters().localTeid == 22);
    b.release();
    CHECK_THROWS_AS(b.modifyTransport({192, 0, 2, 2}, 44), BearerError);
}

TEST_CASE("lte/modify: multiplexer applies independent items and preserves other UE indexes counters")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    auto &b = AddUe(mux, 2);
    a.counters.s1uUplinkPackets = 42;
    b.counters.s1uDownlinkPackets = 17;
    auto request = Request();
    request.erabs[0].qos.qci = 9;
    auto missing = request.erabs[0];
    missing.erabId = 7;
    request.erabs.push_back(missing);
    Dispatch(mux, request);
    REQUIRE(sender.sent.size() == 1);
    CHECK(sender.sent[0] == ResponseFixture);
    CHECK(mux.registry().findBearer(a, 6)->parameters().qci == 9);
    CHECK(a.bearer.parameters().qci == 9);
    CHECK(mux.registry().findBearer(b, 6)->parameters().qci == 7);
    CHECK(a.counters.s1uUplinkPackets == 42);
    CHECK(b.counters.s1uDownlinkPackets == 17);
    CHECK(mux.registry().findBearerByLocalTeid(201).entry == &a);
    CHECK(mux.registry().findBearerByLocalTeid(202).entry == &b);
    CHECK(b.mmeUeS1apId == 102);
}

TEST_CASE("lte/modify: stale mismatched and released identities cause no NAS or state mutation")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    AddUe(mux, 2);
    auto request = Request();
    request.mmeUeS1apId = 102;
    Dispatch(mux, request);
    CHECK(sender.sent.empty());
    CHECK(mux.registry().findBearer(a, 6)->parameters().qci == 7);
    mux.registry().releaseS1(a);
    request.mmeUeS1apId = 101;
    Dispatch(mux, request);
    CHECK(sender.sent.empty());
}

TEST_CASE("lte/modify: transport ignores accompanying QoS NAS and preserves other bearer")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    auto r = Request();
    r.erabs[0].qos.qci = 0;
    r.erabs[0].nasPdu.clear();
    r.erabs[0].transport = s1ap::ErabTransport{{127, 0, 0, 3}, 0x1234};
    Dispatch(mux, r);
    auto *b = mux.registry().findBearer(a, 6);
    REQUIRE(b);
    CHECK(b->parameters().qci == 7);
    CHECK(b->parameters().sgwTeid == 0x1234);
    CHECK(b->parameters().localTeid == 201);
    CHECK(a.bearer.parameters().sgwTeid == 11);
    CHECK(a.bearer.active());
    r.erabs[0].transport->teid = 0;
    Dispatch(mux, r);
    CHECK(b->parameters().sgwTeid == 0x1234);
    REQUIRE(sender.sent.size() == 2);
    CHECK(sender.sent.back() == s1ap::EncodeErabModifyResponse(101, 1, {}, {{6, "transport", 0}}));
}

TEST_CASE("lte/modify: unsupported QoS and unknown EBI never create a bearer")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    auto r = Request();
    r.erabs[0].qos.qci = 0;
    Dispatch(mux, r);
    CHECK(mux.registry().findBearer(a, 6)->parameters().qci == 7);
    CHECK(a.dedicatedBearers.size() == 1);
    CHECK(a.bearer.active());
    REQUIRE(sender.sent.size() == 1);
    CHECK(sender.sent[0] == s1ap::EncodeErabModifyResponse(101, 1, {}, {{6, "radioNetwork", 27}}));
}

TEST_CASE("lte/modify: protected modification rejects replay tamper wrong COUNT and preserves other UE")
{
    for (auto cipher : {lte::ue::CipheringAlgorithm::EEA0, lte::ue::CipheringAlgorithm::EEA2})
    {
        lte::ue::SecurityContext a{};
        a.valid = a.keysDerived = a.securityActive = true;
        a.integrity = lte::ue::IntegrityAlgorithm::EIA2;
        a.ciphering = cipher;
        a.ksi = 3;
        auto b = a;
        auto network = a;
        network.dlNasCount = 1;
        const auto wire = nas::Protect(network, false, false, Hex("6200c95b0109"));
        CHECK(nas::ReceiveProtectedDownlink(a, wire) == Hex("6200c95b0109"));
        CHECK(a.dlNasCount == 1);
        CHECK_THROWS_AS(nas::ReceiveProtectedDownlink(a, wire), nas::SecurityError);
        auto corrupt = wire;
        corrupt[2] ^= 1;
        CHECK_THROWS_AS(nas::ReceiveProtectedDownlink(b, corrupt), nas::SecurityError);
        CHECK(b.dlNasCount == 0);
        CHECK(a.ulNasCount == 0);
        CHECK(a.ksi == 3);
        network.dlNasCount = 258;
        auto wrong = nas::Protect(network, false, false, Hex("6200c9"));
        CHECK_THROWS_AS(nas::ReceiveProtectedDownlink(a, wrong), nas::SecurityError);
        CHECK(a.dlNasCount == 1);
        network.dlNasCount = 2;
        CHECK(nas::ReceiveProtectedDownlink(a, nas::Protect(network, false, false, Hex("6200c9"))) == Hex("6200c9"));
        auto accept = nas::Protect(a, true, false, nas::EncodeModifyEpsBearerContextAccept(6, 0));
        CHECK_FALSE(accept.empty());
        CHECK(b.ulNasCount == 0);
        CHECK(b.dlNasCount == 0);
    }
}

TEST_CASE("lte/modify: transport replacement routes actual UDP only to the selected SGW")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    udp::UdpServer radio("127.0.0.1", 50001), oldSgw("127.0.0.2", 2152), newSgw("127.0.0.3", 2152);
    auto r = Request();
    r.erabs[0].transport = s1ap::ErabTransport{{127, 0, 0, 3}, 1234};
    const auto socketBefore = mux.s1uAddress();
    Dispatch(mux, r);
    auto packet = Packet(7100);
    packet[15] = 1; // assigned address of UE A
    auto uplink = [&](bool dedicated) {
        auto payload = packet;
        if (dedicated)
            payload.insert(payload.begin(), 6);
        auto wire = lte::ue::link::Encode(
            {dedicated ? lte::ue::link::MessageType::DATA_UPLINK_BEARER : lte::ue::link::MessageType::DATA_UPLINK, 1,
             payload});
        mux.handleRadioFrame(wire.data(), wire.size(), radio.LocalAddress());
    };
    uint8_t buffer[4096];
    InetAddress peer;
    uplink(true);
    auto n = newSgw.Receive(buffer, sizeof(buffer), 1000, peer);
    REQUIRE(n > 0);
    CHECK(gtpu::Decode(buffer, static_cast<size_t>(n)).teid == 1234);
    CHECK(oldSgw.Receive(buffer, sizeof(buffer), 0, peer) <= 0);
    uplink(false);
    n = oldSgw.Receive(buffer, sizeof(buffer), 1000, peer);
    REQUIRE(n > 0);
    CHECK(gtpu::Decode(buffer, static_cast<size_t>(n)).teid == 11);
    CHECK(mux.s1uAddress() == socketBefore);

    // Invalid subsequent replacement preserves the working new destination.
    r.erabs[0].transport->teid = 0;
    Dispatch(mux, r);
    uplink(true);
    n = newSgw.Receive(buffer, sizeof(buffer), 1000, peer);
    REQUIRE(n > 0);
    CHECK(gtpu::Decode(buffer, static_cast<size_t>(n)).teid == 1234);

    // Old peer must no longer be accepted on the unchanged receiving TEID.
    auto downlink = packet;
    std::swap_ranges(downlink.begin() + 12, downlink.begin() + 16, downlink.begin() + 16);
    auto datagram = gtpu::EncodeTPdu(201, downlink.data(), downlink.size());
    oldSgw.Send(mux.s1uAddress(), datagram.data(), datagram.size());
    mux.poll(0, 16);
    CHECK(radio.Receive(buffer, sizeof(buffer), 0, peer) <= 0);
    newSgw.Send(mux.s1uAddress(), datagram.data(), datagram.size());
    mux.poll(0, 16);
    n = radio.Receive(buffer, sizeof(buffer), 1000, peer);
    REQUIRE(n > 0);
    const auto frame = lte::ue::link::Decode(buffer, static_cast<size_t>(n));
    CHECK(frame.type == lte::ue::link::MessageType::DATA_DOWNLINK_BEARER);
    REQUIRE(frame.payload.size() == 29);
    CHECK(frame.payload[0] == 6);
    CHECK(a.counters.unexpectedPeerDrops == 1);
}

TEST_CASE("lte/modify: combined valid NAS update preserves linked EBI and other UE TFT")
{
    nas::EpsBearerConfiguration a;
    a.ebi = 6;
    a.qci = 7;
    a.linkedEbi = 5;
    a.tft = InitialTft();
    const auto b = a;
    const auto old = Snapshot(b.tft);
    // Independent TLVs: new QCI 9, replace id 0 with UDP local port 7001.
    const auto p = Hex("6200c95b010936098120fa053011401b59");
    const auto r = nas::DecodeModifyEpsBearerContextRequest(p.data(), p.size());
    nas::ApplyBearerModification(a, r);
    CHECK(a.qci == 9);
    CHECK(a.ebi == 6);
    CHECK(a.linkedEbi == 5);
    CHECK(a.tft.size() == 2);
    const auto was = Packet(7000), now = Packet(7001);
    CHECK_FALSE(a.tft.classify(was.data(), was.size(), true));
    REQUIRE(a.tft.classify(now.data(), now.size(), true));
    CHECK(Snapshot(b.tft) == old);
    CHECK(b.qci == 7);
    REQUIRE(b.tft.classify(was.data(), was.size(), true));
}

TEST_CASE("lte/modify: default bearer QoS modification and default TFT rejection are independent")
{
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    auto r = Request();
    r.erabs[0].erabId = 5;
    r.erabs[0].qos.qci = 8;
    Dispatch(mux, r);
    CHECK(a.bearer.parameters().qci == 8);
    CHECK(a.bearer.parameters().localTeid == 101);
    CHECK(a.bearer.active());
    CHECK(mux.registry().findBearer(a, 6)->parameters().qci == 7);
    nas::EpsBearerConfiguration b;
    b.ebi = 5;
    b.qci = 9;
    nas::ModifyEpsBearerContextRequest q;
    q.epsBearerIdentity = 5;
    q.epsQos = Hex("08");
    q.tft = Hex("40");
    CHECK_THROWS_AS(nas::ApplyBearerModification(b, q), nas::EsmError);
    CHECK(b.qci == 9);
}

TEST_CASE("lte/modify: malformed duplicate components and inverted ports cannot change live TFT")
{
    for (const auto &v : {"21200100", "2120010430113011", "21200105411b5a1b58", "21200106aabbccddeeff"})
    {
        auto b = InitialTft();
        const auto old = Snapshot(b);
        const auto p = Hex(v);
        CHECK_THROWS_AS(b.apply(tft::Decode(p.data(), p.size())), tft::TftError);
        CHECK(Snapshot(b) == old);
    }
}

TEST_CASE("lte/modify: independent IPv6 transport fixture returns per E-RAB failure without mutation")
{
    const auto p = Hex("0006003f000003000000020065000800020001001e002c00002400274c000720066200c95b0107000000b900161fc02"
                       "0010db800000000000000000000000112345678");
    const auto r = s1ap::DecodeErabModifyRequest(p.data(), p.size());
    REQUIRE(r.erabs[0].transport);
    CHECK_FALSE(r.erabs[0].transport->ipv4);
    Sender sender;
    EnbMultiplexer mux(Config(), sender);
    auto &a = AddUe(mux, 1);
    mux.handleS1ap(p.data(), p.size(), 1);
    REQUIRE(sender.sent.size() == 1);
    CHECK(sender.sent[0] == s1ap::EncodeErabModifyResponse(101, 1, {}, {{6, "transport", 0}}));
    CHECK(mux.registry().findBearer(a, 6)->parameters().sgwTeid == 21);
    CHECK(mux.registry().findBearer(a, 6)->parameters().qci == 7);
    CHECK(a.bearer.active());
}
