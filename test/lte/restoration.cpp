// This file is a part of UERANSIM project.
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
#include "restoration_fixtures.hpp"
#include <algorithm>
#include <ext/doctest/doctest.h>
#include <lte/enb/codec.hpp>
#include <lte/enb/gtpu.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/ue/bearer_runtime.hpp>
#include <lte/ue/paging.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>
#include <set>

namespace
{
using namespace lte;
using namespace lte::enb;
namespace link = lte::ue::link;
namespace f = restoration_fixtures;

std::vector<uint8_t> Hex(const std::string &s)
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i < s.size(); i += 2)
        result.push_back(static_cast<uint8_t>(std::stoul(s.substr(i, 2), nullptr, 16)));
    return result;
}

class Sender : public IS1apSender
{
  public:
    bool fail{};
    std::vector<std::vector<uint8_t>> sent;
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override
    {
        if (fail)
            throw std::runtime_error("Injected SCTP send failure");
        sent.push_back(pdu);
    }
};

EnbConfig Config()
{
    EnbConfig c;
    c.plmn = {"460", "02"};
    c.enbId = c.tac = 1;
    c.s1uAddress = c.ueLinkAddress = "127.0.0.1";
    c.s1uPort = c.ueLinkPort = 0;
    c.maxUes = 4;
    c.allowLoopbackS1u = true;
    return c;
}

struct Lab
{
    Sender sender;
    EnbMultiplexer mux{Config(), sender};
    udp::UdpServer radio{"127.0.0.1", 0};
    EnbUeEntry &entry;
    std::vector<uint32_t> oldTeids;

    explicit Lab(size_t dedicated = 2, bool pending = true)
        : entry(mux.registry().registerPeer(1, radio.LocalAddress()))
    {
        auto &r = mux.registry();
        r.bindEnbUeS1apId(entry, 8);
        r.setMmeUeS1apId(entry, 88);
        entry.s1 = UeS1State::BEARER_ACTIVE;
        auto parameters = [&](uint8_t ebi) {
            return BearerParameters{ebi, 9, 1, {127, 0, 0, 9}, static_cast<uint32_t>(0x1000 + ebi),
                r.allocateLocalTeid(), static_cast<uint8_t>(ebi == 5 ? 0 : 5), {9, 15, false, false, {}}};
        };
        entry.bearer.establish(parameters(5));
        entry.bearer.activateUe(1, 5, {10, 45, 0, 2});
        r.bindLocalTeid(entry, entry.bearer.parameters().localTeid);
        oldTeids.push_back(entry.bearer.parameters().localTeid);
        for (size_t i = 0; i < dedicated; ++i)
        {
            auto &bearer = r.addDedicatedBearer(entry, parameters(static_cast<uint8_t>(6 + i)));
            bearer.activateUe(1, static_cast<uint8_t>(6 + i), {10, 45, 0, 2});
            r.bindLocalTeid(entry, bearer, bearer.parameters().localTeid);
            oldTeids.push_back(bearer.parameters().localTeid);
        }
        r.releaseS1(entry);
        if (pending)
        {
            r.bindEnbUeS1apId(entry, 1);
            entry.s1 = UeS1State::CONTEXT_PENDING;
        }
    }

    void request(const char *fixture)
    {
        auto bytes = Hex(fixture);
        mux.handleS1ap(bytes.data(), bytes.size(), 1);
    }
    void request(const s1ap::InitialContextSetupRequest &value)
    {
        auto bytes = s1ap::EncodeInitialContextSetupRequest(value);
        mux.handleS1ap(bytes.data(), bytes.size(), 1);
    }
    void uplink(link::MessageType type, std::vector<uint8_t> payload, uint32_t id = 1)
    {
        const auto wire = link::Encode({type, id, std::move(payload)});
        mux.handleRadioFrame(wire.data(), wire.size(), radio.LocalAddress());
    }
    void ready(uint8_t ebi, uint32_t generation = 1)
    {
        uplink(link::MessageType::BEARER_TRANSPORT_READY, link::EncodeBearerRestoration(ebi, generation));
    }
    std::vector<link::Message> notifications()
    {
        std::vector<link::Message> messages;
        uint8_t buffer[4096];
        InetAddress peer;
        for (int i = 0; i < 16; ++i)
        {
            int n = radio.Receive(buffer, sizeof(buffer), 0, peer);
            if (n <= 0) break;
            messages.push_back(link::Decode(buffer, static_cast<size_t>(n)));
        }
        return messages;
    }
    s1ap::S1apPdu outcome()
    {
        REQUIRE(!sender.sent.empty());
        return s1ap::ProbeS1apPdu(sender.sent.back().data(), sender.sent.back().size());
    }
};

s1ap::InitialContextSetupRequest Request()
{
    auto bytes = Hex(f::request3);
    return s1ap::DecodeInitialContextSetupRequest(bytes.data(), bytes.size());
}

ue::MobilityContext Mobility()
{
    ue::MobilityContext m;
    m.emm = ue::EmmState::REGISTERED;
    m.ecm = ue::EcmState::CONNECTED;
    m.bearer = ue::EpsBearerState::USER_PLANE_READY;
    m.securityContextValid = true;
    m.defaultEbi = 5;
    m.assignedIpv4 = {10, 45, 0, 2};
    m.guti = std::array<uint8_t, 11>{0xF6, 0x64, 0xF0, 0x20, 0, 1, 1, 0x12, 0x34, 0x56, 0x78};
    m.taiList = {0x40, 0x64, 0xF0, 0x20, 0, 1};
    return m;
}

std::vector<uint8_t> Ip(bool downlink = false)
{
    return Hex(downlink ? "450000140000000040010000c00002010a2d0002"
                        : "4500001400000000400100000a2d0002c0000201");
}
} // namespace

TEST_CASE("restoration/retention: logical identity QoS address survive all access endpoints")
{
    Lab lab;
    for (uint8_t ebi : {5, 6, 7})
    {
        auto *b = lab.mux.registry().findBearer(lab.entry, ebi);
        REQUIRE(b != nullptr);
        CHECK(b->logicalExists());
        CHECK_FALSE(b->signalingEstablished());
        CHECK_FALSE(b->active());
        CHECK(b->parameters().erabId == ebi);
        CHECK(b->parameters().linkedDefaultEbi == (ebi == 5 ? 0 : 5));
        CHECK(b->parameters().qos.qci == 9);
        CHECK(b->parameters().qos.priorityLevel == 15);
        CHECK(b->ueIpv4() == std::array<uint8_t, 4>{10, 45, 0, 2});
        CHECK(b->parameters().localTeid == 0);
        CHECK(b->parameters().sgwTeid == 0);
        CHECK(b->parameters().sgwAddress == std::array<uint8_t, 4>{});
        auto ip = Ip();
        CHECK_THROWS(b->validateUplink(1, ip.data(), ip.size()));
    }
    for (auto teid : lab.oldTeids)
        CHECK(lab.mux.registry().findByLocalTeid(teid) == nullptr);
    CHECK(lab.mux.registry().findByEnbUeS1apId(8) == nullptr);
    CHECK(lab.mux.registry().findByMmeUeS1apId(88) == nullptr);
}

TEST_CASE("restoration/codec: independent two and three item requests")
{
    for (auto fixture : {f::request2, f::request3, f::reordered})
    {
        auto wire = Hex(fixture);
        auto request = s1ap::DecodeInitialContextSetupRequest(wire.data(), wire.size());
        REQUIRE(request.erabs.size() >= 2);
        CHECK(request.erabs.back().qci == 9);
        CHECK(s1ap::EncodeInitialContextSetupRequest(request) == wire);
    }
}

TEST_CASE("restoration/codec: independent success mixed and failure outcome bytes")
{
    const s1ap::ErabSetupItem a{5, {192, 0, 2, 1}, TeidToBytes(0x2005)};
    const s1ap::ErabSetupItem b{6, {192, 0, 2, 1}, TeidToBytes(0x2006)};
    const s1ap::ErabSetupItem c{7, {192, 0, 2, 1}, TeidToBytes(0x2007)};
    CHECK(s1ap::EncodeInitialContextSetupResponse(101, 1, {a, b}) == Hex(f::response2));
    CHECK(s1ap::EncodeInitialContextSetupResponse(101, 1, {a, b, c}) == Hex(f::response3));
    CHECK(s1ap::EncodeInitialContextSetupResponse(101, 1, {a, b}, {{7, "radioNetwork", 30}}) == Hex(f::mixed));
    CHECK(s1ap::EncodeInitialContextSetupFailure(101, 1, "radioNetwork", 25) == Hex(f::failure));
    CHECK_THROWS(s1ap::EncodeInitialContextSetupResponse(101, 1, {a}, {{5, "radioNetwork", 30}}));
    CHECK_THROWS(s1ap::EncodeInitialContextSetupResponse(101, 1, {a, a}));
    CHECK_THROWS(s1ap::EncodeInitialContextSetupResponse(101, 1, {}));
    CHECK(s1ap::EncodeErabSetupResponse(101, 1, {b}, {}) == Hex(f::standalone_success));
    CHECK(s1ap::EncodeErabSetupResponse(101, 1, {}, {{6, "radioNetwork", 25}}) == Hex(f::standalone_failure));
    auto invalid = a;
    invalid.gtpTeid = {};
    CHECK_THROWS(s1ap::EncodeInitialContextSetupResponse(101, 1, {invalid}));
}

TEST_CASE("restoration/setup: three E-RABs get fresh correct independent transports")
{
    Lab lab;
    lab.request(f::request3);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    std::set<uint32_t> teids;
    for (uint8_t ebi : {5, 6, 7})
    {
        auto *b = lab.mux.registry().findBearer(lab.entry, ebi);
        REQUIRE(b != nullptr);
        CHECK(b->signalingEstablished());
        CHECK_FALSE(b->active());
        CHECK(b->parameters().sgwTeid == 0x1000U + ebi);
        CHECK(b->parameters().sgwAddress == std::array<uint8_t, 4>{127, 0, 0, 9});
        CHECK(teids.insert(b->parameters().localTeid).second);
        CHECK(std::find(lab.oldTeids.begin(), lab.oldTeids.end(), b->parameters().localTeid) == lab.oldTeids.end());
        CHECK(lab.mux.registry().findBearerByLocalTeid(b->parameters().localTeid).bearer == b);
    }
    CHECK(lab.entry.dedicatedBearers.size() == 2);
}

TEST_CASE("restoration/setup: MME order cannot redefine the default role or radio order")
{
    Lab lab;
    lab.request(f::reordered);
    CHECK(lab.entry.bearer.parameters().erabId == 5);
    auto frames = lab.notifications();
    REQUIRE(frames.size() == 3);
    CHECK(frames[0].type == link::MessageType::S1_CONTEXT_RESTORED);
    CHECK(frames[0].payload == link::EncodeBearerRestoration(5, 1));
    CHECK(frames[1].type == link::MessageType::DEDICATED_BEARER_RESTORED);
    CHECK(frames[1].payload == link::EncodeBearerRestoration(7, 1));
    CHECK(frames[2].payload == link::EncodeBearerRestoration(6, 1));
}

TEST_CASE("restoration/setup: default-only request leaves retained dedicated transports inactive")
{
    Lab lab;
    auto r = Request();
    r.erabs.resize(1);
    lab.request(r);
    REQUIRE(lab.entry.bearer.signalingEstablished());
    lab.ready(5);
    CHECK(lab.entry.bearer.active());
    for (auto &b : lab.entry.dedicatedBearers)
    {
        CHECK(b.logicalExists());
        CHECK_FALSE(b.active());
        CHECK(b.parameters().localTeid == 0);
    }
    CHECK(lab.notifications().size() == 1);
}

TEST_CASE("restoration/setup: duplicate EBI fails without transport or notifications")
{
    Lab lab;
    lab.request(f::duplicate);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
    CHECK(lab.entry.mmeUeS1apId == 0);
    CHECK(lab.notifications().empty());
}

TEST_CASE("restoration/setup: missing default rolls back otherwise valid dedicated E-RABs")
{
    Lab lab;
    auto r = Request();
    r.erabs.erase(r.erabs.begin());
    lab.request(r);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    for (auto &b : lab.entry.dedicatedBearers)
    {
        CHECK_FALSE(b.signalingEstablished());
        CHECK(b.parameters().localTeid == 0);
    }
}

TEST_CASE("restoration/setup: invalid QoS fails one item while independent bearers succeed")
{
    Lab lab;
    auto r = Request();
    r.erabs[1].qci = 1; // missing mandatory GBR information
    lab.request(r);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    CHECK(lab.entry.bearer.signalingEstablished());
    CHECK_FALSE(lab.entry.dedicatedBearers[0].signalingEstablished());
    CHECK(lab.entry.dedicatedBearers[1].signalingEstablished());
    CHECK(lab.notifications().size() == 2);
}

TEST_CASE("restoration/setup: independent IPv6 transport item fails without discarding other results")
{
    Lab lab;
    lab.request(f::ipv6);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    CHECK_FALSE(lab.entry.dedicatedBearers[0].signalingEstablished());
    CHECK(lab.entry.dedicatedBearers[1].signalingEstablished());
}

TEST_CASE("restoration/setup: zero TEID multicast and zero address cannot become active")
{
    for (int bad = 0; bad < 3; ++bad)
    {
        Lab lab;
        auto r = Request();
        if (bad == 0) r.erabs[1].gtpTeid = {};
        if (bad == 1) r.erabs[1].transportLayerAddress = {224, 0, 0, 1};
        if (bad == 2) r.erabs[1].transportLayerAddress = {};
        lab.request(r);
        CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
        CHECK_FALSE(lab.entry.dedicatedBearers[0].signalingEstablished());
    }
}

TEST_CASE("restoration/setup: full failure preserves old logical state without indexing a tunnel")
{
    Lab lab;
    auto r = Request();
    for (auto &item : r.erabs) item.gtpTeid = {};
    lab.request(r);
    CHECK(lab.sender.sent.back() == Hex(f::failure));
    CHECK(lab.entry.s1 == UeS1State::CONTEXT_PENDING);
    CHECK(lab.entry.dedicatedBearers.size() == 2);
    CHECK(lab.entry.bearer.logicalExists());
    CHECK(lab.notifications().empty());
}

TEST_CASE("restoration/setup: unknown EBI does not create a logical bearer")
{
    Lab lab(1);
    lab.request(f::request3);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    CHECK(lab.entry.dedicatedBearers.size() == 1);
    CHECK(lab.mux.registry().findBearer(lab.entry, 7) == nullptr);
    CHECK(lab.notifications().size() == 2);
}

TEST_CASE("restoration/setup: bounded eight bearer capacity reports excess identities")
{
    Lab lab(7);
    auto r = Request();
    for (uint8_t ebi = 8; ebi <= 15; ++ebi)
    {
        auto item = r.erabs[1]; item.erabId = ebi; r.erabs.push_back(item);
    }
    lab.request(r);
    CHECK(lab.entry.dedicatedBearers.size() == 7);
    CHECK(lab.notifications().size() == 8);
    CHECK(lab.mux.registry().findBearer(lab.entry, 13) == nullptr);
}

TEST_CASE("restoration/setup: malformed independent APER cannot mutate retained state")
{
    Lab lab;
    auto wire = Hex(f::request3);
    for (size_t n = 0; n < wire.size(); ++n)
        lab.mux.handleS1ap(wire.data(), n, 1);
    CHECK(lab.sender.sent.empty());
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
    CHECK(lab.entry.mmeUeS1apId == 0);
}

TEST_CASE("restoration/setup: foreign MME identity does not mutate either UE")
{
    Lab lab;
    auto &other = lab.mux.registry().registerPeer(2, InetAddress("127.0.0.1", 39002));
    lab.mux.registry().bindEnbUeS1apId(other, 2);
    lab.mux.registry().setMmeUeS1apId(other, 101);
    other.s1 = UeS1State::CONTEXT_PENDING;
    lab.request(f::request3);
    CHECK(lab.sender.sent.empty());
    CHECK(other.mmeUeS1apId == 101);
    CHECK(lab.entry.mmeUeS1apId == 0);
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
}

TEST_CASE("restoration/setup: duplicate request allocates no additional TEID or radio indication")
{
    Lab lab;
    lab.request(f::request3);
    const auto teid = lab.entry.bearer.parameters().localTeid;
    REQUIRE(lab.notifications().size() == 3);
    lab.request(f::request3);
    CHECK(lab.sender.sent.size() == 1);
    CHECK(lab.entry.bearer.parameters().localTeid == teid);
    CHECK(lab.notifications().empty());
}

TEST_CASE("restoration/setup: injected SCTP failure rolls back all provisional TEID indexes")
{
    Lab lab;
    lab.sender.fail = true;
    lab.request(f::request3);
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
    CHECK(lab.entry.mmeUeS1apId == 0);
    CHECK(lab.notifications().empty());
    lab.sender.fail = false;
    lab.request(f::request3);
    CHECK(lab.entry.bearer.signalingEstablished());
}

TEST_CASE("restoration/radio: generation direction length and identity are strict")
{
    for (auto type : {link::MessageType::DEDICATED_BEARER_RESTORED, link::MessageType::BEARER_TRANSPORT_READY})
    {
        const auto payload = link::EncodeBearerRestoration(6, 0x12345678);
        auto wire = link::Encode({type, 42, payload});
        auto frame = link::Decode(wire.data(), wire.size());
        CHECK(frame.ueId == 42);
        CHECK(link::DecodeBearerRestoration(frame.payload).second == 0x12345678);
        CHECK(link::IsDownlink(type) == (type == link::MessageType::DEDICATED_BEARER_RESTORED));
        CHECK(link::IsUplink(type) == (type == link::MessageType::BEARER_TRANSPORT_READY));
        CHECK_THROWS(link::Encode({type, 42, {6}}));
        wire.pop_back();
        CHECK_THROWS(link::Decode(wire.data(), wire.size()));
    }
    CHECK_THROWS(link::EncodeBearerRestoration(0, 1));
}

TEST_CASE("restoration/radio: only requested EBI and current generation can activate")
{
    Lab lab;
    lab.request(f::request2);
    lab.ready(5, 0);
    lab.ready(5, 2);
    CHECK_FALSE(lab.entry.bearer.active());
    lab.ready(6);
    CHECK_FALSE(lab.entry.dedicatedBearers[0].active());
    lab.ready(5);
    lab.ready(7);
    CHECK_FALSE(lab.entry.dedicatedBearers[1].active());
    lab.ready(6);
    CHECK(lab.entry.dedicatedBearers[0].active());
    lab.ready(6); // no second activation
    CHECK(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/radio: old NAS activation and default-ready frames cannot bypass restoration")
{
    Lab lab;
    lab.request(f::request2);
    lab.uplink(link::MessageType::BEARER_READY, {5, 10, 45, 0, 2});
    lab.uplink(link::MessageType::BEARER_ACTIVATED, {6});
    CHECK_FALSE(lab.entry.bearer.active());
    CHECK_FALSE(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/UE: release retains PDN security and complete modified TFT")
{
    auto m = Mobility();
    ue::SecurityContext security;
    security.ulNasCount = 12; security.dlNasCount = 19;
    ue::DedicatedBearerRuntime b;
    b.ebi = 6; b.linkedEbi = 5; b.qci = 7; b.epsQos = {7};
    tft::PacketFilter filter;
    filter.identifier = 0; filter.precedence = 1; filter.hasProtocol = true; filter.protocol = 1;
    b.tft.apply({tft::OperationCode::CREATE_NEW, false, {filter}});
    filter.identifier = 1; filter.precedence = 2; filter.protocol = 17;
    b.tft.apply({tft::OperationCode::ADD_FILTERS, false, {filter}});
    const auto snapshot = tft::Encode({tft::OperationCode::CREATE_NEW, false, b.tft.filters()});
    m.acceptAccessRelease(5, 1); b.releaseAccessTransport();
    CHECK_FALSE(b.accessReady);
    m.startServiceRequest();
    CHECK_THROWS(b.restoreAccess(m, 6, 1)); // default has not restored
    m.validateAccessRestoration(5, 1, false);
    m.onServiceRestored();
    b.restoreAccess(m, 6, 1);
    CHECK(b.accessReady);
    CHECK(b.qci == 7);
    CHECK(b.epsQos == std::vector<uint8_t>{7});
    CHECK(tft::Encode({tft::OperationCode::CREATE_NEW, false, b.tft.filters()}) == snapshot);
    auto packet = Ip();
    CHECK(b.tft.classify(packet.data(), packet.size(), true) != nullptr);
    CHECK(security.ulNasCount == 12);
    CHECK(security.dlNasCount == 19);
    CHECK(m.assignedIpv4 == std::array<uint8_t, 4>{10, 45, 0, 2});
    CHECK(m.securityContextValid);
    CHECK_THROWS(b.restoreAccess(m, 6, 1));
}

TEST_CASE("restoration/UE: stale no-Service-Request wrong EBI and unregistered restores fail")
{
    auto m = Mobility();
    CHECK_THROWS(m.validateAccessRestoration(5, 1, false));
    m.acceptAccessRelease(5, 1);
    CHECK_THROWS(m.validateAccessRestoration(5, 1, false));
    m.startServiceRequest();
    CHECK_THROWS(m.validateAccessRestoration(6, 1, false));
    CHECK_THROWS(m.validateAccessRestoration(5, 0, false));
    CHECK_THROWS(m.validateAccessRestoration(5, 2, false));
    m.emm = ue::EmmState::DEREGISTERED;
    CHECK_THROWS(m.validateAccessRestoration(5, 1, false));
}

TEST_CASE("restoration/UE: delayed release cannot invalidate the new connection")
{
    auto m = Mobility();
    m.acceptAccessRelease(5, 1);
    m.startServiceRequest(); m.onServiceRestored();
    CHECK_THROWS(m.acceptAccessRelease(5, 1));
    CHECK_THROWS(m.acceptAccessRelease(5, 3));
    CHECK(m.ecm == ue::EcmState::CONNECTED);
    m.acceptAccessRelease(5, 2);
    CHECK(m.ecm == ue::EcmState::IDLE);
}

TEST_CASE("restoration/UE: dedicated EBI and linked default must name the existing logical bearer")
{
    auto m = Mobility();
    m.acceptAccessRelease(5, 1); m.startServiceRequest(); m.onServiceRestored();
    ue::DedicatedBearerRuntime b;
    b.ebi = 6; b.linkedEbi = 7; b.releaseAccessTransport();
    CHECK_THROWS(b.restoreAccess(m, 6, 1));
    b.linkedEbi = 5;
    CHECK_THROWS(b.restoreAccess(m, 7, 1));
    CHECK_FALSE(b.accessReady);
}

TEST_CASE("restoration/lifecycle: standalone retained E-RAB setup reuses the same logical identity")
{
    Lab lab(1);
    auto r = Request(); r.erabs.resize(1); lab.request(r); lab.ready(5);
    s1ap::ErabSetupRequest setup{101, 1, {Request().erabs[1]}};
    setup.erabs[0].nasPduPresent = true;
    setup.erabs[0].nasPdu = {0x27, 0, 0, 0, 0, 1, 0}; // opaque synthetic protected NAS
    auto bytes = s1ap::EncodeErabSetupRequest(setup);
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
    CHECK(lab.entry.dedicatedBearers.size() == 1);
    CHECK(lab.entry.dedicatedBearers[0].restorationPending());
    lab.ready(6);
    CHECK(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/lifecycle: full deletion removes retained contexts and prevents Service Request")
{
    Lab lab(2, false);
    lab.uplink(link::MessageType::EPS_SESSION_DELETED, link::EncodeBearerRestoration(5, 1));
    CHECK_FALSE(lab.entry.bearer.logicalExists());
    CHECK(lab.entry.dedicatedBearers.empty());
    lab.uplink(link::MessageType::SERVICE_REQUEST, {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0, 1, 2});
    CHECK(lab.entry.s1 == UeS1State::IDLE_RETAINED);
    CHECK(lab.sender.sent.empty());
}

TEST_CASE("restoration/lifecycle: dedicated deactivation removes only its own logical state")
{
    Lab lab;
    lab.request(f::request3); lab.ready(5); lab.ready(6); lab.ready(7);
    const auto teid = lab.entry.dedicatedBearers[0].parameters().localTeid;
    lab.mux.registry().releaseBearer(lab.entry, 6);
    CHECK(lab.mux.registry().findByLocalTeid(teid) == nullptr);
    CHECK(lab.entry.bearer.active());
    REQUIRE(lab.entry.dedicatedBearers.size() == 1);
    CHECK(lab.entry.dedicatedBearers[0].parameters().erabId == 7);
    CHECK(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/lifecycle: pending setup release rejects delayed MME and radio results")
{
    Lab lab;
    auto release = s1ap::EncodeUeContextReleaseCommand(101, 1, "radioNetwork", 20);
    lab.mux.handleS1ap(release.data(), release.size(), 1);
    lab.request(f::request3);
    lab.ready(5);
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
    CHECK(lab.entry.s1 == UeS1State::IDLE_RETAINED);
}

TEST_CASE("restoration/lifecycle: genuine radio Service Request creates fresh S1 identity")
{
    Lab lab(2, false);
    lab.uplink(link::MessageType::SERVICE_REQUEST, {1, 0x12, 0x34, 0x56, 0x78, 0xC7, 0, 1, 2});
    CHECK(lab.entry.enbUeS1apId != 8);
    CHECK(lab.entry.s1 == UeS1State::CONTEXT_PENDING);
    CHECK(lab.outcome().procedureCode == 12);
    lab.request(f::request3); lab.ready(5); lab.ready(6); lab.ready(7);
    CHECK(lab.entry.bearer.active());
    CHECK(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/paging: only matching idle S-TMSI starts a protected Service Request")
{
    auto a = Mobility(); auto b = Mobility();
    (*b.guti)[10] ^= 1;
    a.acceptAccessRelease(5, 1); b.acceptAccessRelease(5, 1);
    ue::SecurityContext sa{}, sb{};
    sa.valid = sa.keysDerived = sa.securityActive = true;
    sa.ksi = 1; sa.integrity = ue::IntegrityAlgorithm::EIA2;
    sb = sa;
    const link::PagingNotification page{1, 0x12345678, 1};
    auto request = ue::RespondToPaging(a, {"460", "02"}, page, sa);
    REQUIRE(request.has_value());
    CHECK(request->size() == 4);
    CHECK_FALSE(ue::RespondToPaging(b, {"460", "02"}, page, sb).has_value());
    CHECK(b.pending == ue::PendingProcedure::NONE);
    a.validateAccessRestoration(5, 1, false); a.onServiceRestored();
    CHECK(a.ecm == ue::EcmState::CONNECTED);
    CHECK(b.ecm == ue::EcmState::IDLE);
}

TEST_CASE("restoration/user-plane: fresh bearer TEIDs forward and stale peer or TEID cannot deliver")
{
    Lab lab;
    udp::UdpServer sgw("127.0.0.9", 2152);
    lab.request(f::request3); lab.ready(5); lab.ready(6); lab.ready(7);
    lab.notifications();
    auto packet = Ip();
    for (uint8_t ebi : {5, 6, 7})
    {
        auto payload = packet;
        auto type = link::MessageType::DATA_UPLINK;
        if (ebi != 5) { payload.insert(payload.begin(), ebi); type = link::MessageType::DATA_UPLINK_BEARER; }
        lab.uplink(type, payload);
        uint8_t buffer[4096]; InetAddress peer;
        int n = sgw.Receive(buffer, sizeof(buffer), 1000, peer);
        REQUIRE(n > 0);
        CHECK(gtpu::Decode(buffer, static_cast<size_t>(n)).teid == 0x1000U + ebi);
        auto *bearer = lab.mux.registry().findBearer(lab.entry, ebi);
        auto downlink = Ip(true);
        auto datagram = gtpu::EncodeTPdu(bearer->parameters().localTeid, downlink.data(), downlink.size());
        sgw.Send(lab.mux.s1uAddress(), datagram.data(), datagram.size());
        lab.mux.poll(0, 16);
        auto frames = lab.notifications();
        REQUIRE(frames.size() == 1);
        CHECK(frames.front().type == (ebi == 5 ? link::MessageType::DATA_DOWNLINK : link::MessageType::DATA_DOWNLINK_BEARER));
        if (ebi != 5) CHECK(frames.front().payload[0] == ebi);
        CHECK(bearer->counters().uplinkPackets == 1);
        CHECK(bearer->counters().downlinkPackets == 1);
    }
    auto downlink = Ip(true);
    for (auto old : lab.oldTeids)
    {
        auto stale = gtpu::EncodeTPdu(old, downlink.data(), downlink.size());
        sgw.Send(lab.mux.s1uAddress(), stale.data(), stale.size());
    }
    udp::UdpServer wrong("127.0.0.10", 2152);
    auto foreign = gtpu::EncodeTPdu(lab.entry.bearer.parameters().localTeid, downlink.data(), downlink.size());
    wrong.Send(lab.mux.s1uAddress(), foreign.data(), foreign.size());
    lab.mux.poll(0, 16);
    CHECK(lab.notifications().empty());
    CHECK(lab.entry.counters.unexpectedPeerDrops == 1);
}

TEST_CASE("restoration/classification: retained modified TFT selects an inactive bearer without fallback")
{
    ue::DedicatedBearerRuntime b;
    b.ebi = 6; b.linkedEbi = 5;
    tft::PacketFilter filter;
    filter.identifier = 0; filter.precedence = 3; filter.hasProtocol = true; filter.protocol = 17;
    b.tft.apply({tft::OperationCode::CREATE_NEW, false, {filter}});
    filter.identifier = 1; filter.precedence = 2; filter.protocol = 1;
    b.tft.apply({tft::OperationCode::ADD_FILTERS, false, {filter}});
    b.releaseAccessTransport();
    auto packet = Ip();
    auto selected = ue::SelectUplinkBearer(5, {b}, packet.data(), packet.size());
    CHECK(selected.ebi == 6);
    CHECK_FALSE(selected.accessReady);
    b.accessReady = true;
    selected = ue::SelectUplinkBearer(5, {b}, packet.data(), packet.size());
    CHECK(selected.ebi == 6);
    CHECK(selected.accessReady);
    packet[9] = 6;
    CHECK(ue::SelectUplinkBearer(5, {b}, packet.data(), packet.size()).ebi == 5);
    CHECK(b.tft.size() == 2);
}

TEST_CASE("restoration/setup: authoritative network QoS replaces retained access QoS only")
{
    Lab lab;
    auto request = Request();
    request.erabs[1].qci = 7;
    request.erabs[1].priorityLevel = 8;
    lab.request(request);
    CHECK(lab.entry.dedicatedBearers[0].parameters().qos.qci == 7);
    CHECK(lab.entry.dedicatedBearers[0].parameters().qos.priorityLevel == 8);
    CHECK(lab.entry.dedicatedBearers[1].parameters().qos.qci == 9);
    CHECK(lab.entry.dedicatedBearers[0].parameters().linkedDefaultEbi == 5);
}

TEST_CASE("restoration/setup: ambiguous initial Attach roles fail explicitly")
{
    Lab lab;
    lab.mux.registry().deleteBearerContexts(lab.entry);
    lab.request(f::request2);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    CHECK_FALSE(lab.entry.bearer.logicalExists());
    CHECK(lab.entry.dedicatedBearers.empty());
}

TEST_CASE("restoration/radio: another peer cannot acknowledge a restored bearer")
{
    Lab lab;
    lab.request(f::request3);
    const auto frame = link::Encode({link::MessageType::BEARER_TRANSPORT_READY, 1,
                                    link::EncodeBearerRestoration(5, 1)});
    lab.mux.handleRadioFrame(frame.data(), frame.size(), InetAddress("127.0.0.1", 39003));
    CHECK_FALSE(lab.entry.bearer.active());
    CHECK_FALSE(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/registry: duplicate local TEID cannot replace another bearer mapping")
{
    Lab lab;
    lab.request(f::request3);
    const auto defaultTeid = lab.entry.bearer.parameters().localTeid;
    CHECK_THROWS(lab.mux.registry().bindLocalTeid(lab.entry, lab.entry.dedicatedBearers[0], defaultTeid));
    CHECK(lab.mux.registry().findBearerByLocalTeid(defaultTeid).bearer == &lab.entry.bearer);
}

TEST_CASE("restoration/registry: invalid linked-default identity cannot be restored")
{
    Lab lab;
    auto &bearer = lab.entry.dedicatedBearers[0];
    bearer.release();
    bearer.establish({6, 9, 1, {127, 0, 0, 9}, 0x1006, 123, 8, {9, 15, false, false, {}}});
    bearer.releaseAccessTransport();
    lab.request(f::request3);
    CHECK(lab.entry.bearer.signalingEstablished());
    CHECK_FALSE(lab.entry.dedicatedBearers[0].signalingEstablished());
    CHECK(lab.entry.dedicatedBearers[0].parameters().linkedDefaultEbi == 8);
}

TEST_CASE("restoration/UE: S1 release aborts a pending restoration without erasing EPS registration")
{
    auto m = Mobility();
    m.acceptAccessRelease(5, 1); m.startServiceRequest();
    m.acceptAccessRelease(5, 2);
    CHECK(m.pending == ue::PendingProcedure::NONE);
    CHECK(m.emm == ue::EmmState::REGISTERED);
    CHECK(m.defaultEbi == 5);
    CHECK(m.securityContextValid);
    CHECK_THROWS(m.validateAccessRestoration(5, 1, false));
}

TEST_CASE("restoration/lifecycle: Detach notification racing S1 release still deletes logical bearers")
{
    Lab lab(2, false);
    lab.uplink(link::MessageType::EPS_SESSION_DELETED, link::EncodeBearerRestoration(5, 0));
    CHECK_FALSE(lab.entry.bearer.logicalExists());
    CHECK(lab.entry.dedicatedBearers.empty());
    CHECK(lab.entry.enbUeS1apId == 0);
}

TEST_CASE("restoration/lifecycle: stale session deletion cannot delete a later generation")
{
    Lab lab;
    lab.request(f::request3); lab.ready(5);
    lab.uplink(link::MessageType::EPS_SESSION_DELETED, link::EncodeBearerRestoration(5, 0));
    CHECK(lab.entry.bearer.active());
    CHECK(lab.entry.dedicatedBearers.size() == 2);
}

TEST_CASE("restoration/user-plane: unrequested dedicated bearer cannot emit a GTP-U packet")
{
    Lab lab;
    udp::UdpServer sgw("127.0.0.9", 2152);
    auto request = Request(); request.erabs.resize(1);
    lab.request(request); lab.ready(5);
    auto packet = Ip(); packet.insert(packet.begin(), 6);
    lab.uplink(link::MessageType::DATA_UPLINK_BEARER, packet);
    uint8_t buffer[4096]; InetAddress peer;
    CHECK(sgw.Receive(buffer, sizeof(buffer), 0, peer) <= 0);
    CHECK(lab.entry.counters.bearerInactiveDrops == 1);
    CHECK(lab.entry.dedicatedBearers[0].counters().uplinkPackets == 0);
}

TEST_CASE("restoration/multi-UE: UE B traffic and identifiers survive UE A restore and release")
{
    Lab lab;
    auto &r = lab.mux.registry();
    udp::UdpServer radioB("127.0.0.1", 0), sgwB("127.0.0.11", 2152);
    auto &b = r.registerPeer(2, radioB.LocalAddress());
    r.bindEnbUeS1apId(b, 9); r.setMmeUeS1apId(b, 202);
    b.s1 = UeS1State::BEARER_ACTIVE;
    b.bearer.establish({5, 9, 2, {127, 0, 0, 11}, 0x9005, r.allocateLocalTeid(), 0, {9, 15, false, false, {}}});
    b.bearer.activateUe(2, 5, {10, 45, 0, 3});
    r.bindLocalTeid(b, b.bearer.parameters().localTeid);
    const auto teidB = b.bearer.parameters().localTeid;
    for (int stage = 0; stage < 3; ++stage)
    {
        if (stage == 1) { lab.request(f::request3); lab.ready(5); lab.ready(6); }
        if (stage == 2) r.releaseS1(lab.entry);
        auto packet = Ip(); packet[15] = 3;
        auto frame = link::Encode({link::MessageType::DATA_UPLINK, 2, packet});
        lab.mux.handleRadioFrame(frame.data(), frame.size(), radioB.LocalAddress());
        uint8_t buffer[4096]; InetAddress peer;
        int n = sgwB.Receive(buffer, sizeof(buffer), 1000, peer);
        REQUIRE(n > 0);
        CHECK(gtpu::Decode(buffer, static_cast<size_t>(n)).teid == 0x9005);
        CHECK(b.enbUeS1apId == 9);
        CHECK(b.mmeUeS1apId == 202);
        CHECK(b.bearer.parameters().localTeid == teidB);
        CHECK(b.bearer.active());
    }
    CHECK(b.bearer.counters().uplinkPackets == 3);
    CHECK(lab.entry.dedicatedBearers[0].counters().uplinkPackets == 0);
}

TEST_CASE("restoration/setup: a provisional bearer without NAS confirmation cannot be restored")
{
    Lab lab;
    lab.entry.bearer.release();
    lab.entry.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0x1005, 1234, 0, {9, 15, false, false, {}}});
    lab.entry.bearer.releaseAccessTransport();
    lab.request(f::request3);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    CHECK_FALSE(lab.entry.bearer.signalingEstablished());
    CHECK_FALSE(lab.entry.bearer.logicalConfirmed());
    CHECK(lab.notifications().empty());
}

TEST_CASE("restoration/setup: failed standalone response preserves retained logical bearer for retry")
{
    Lab lab(1);
    auto r = Request(); r.erabs.resize(1); lab.request(r); lab.ready(5);
    lab.notifications();
    s1ap::ErabSetupRequest setup{101, 1, {Request().erabs[1]}};
    setup.erabs[0].nasPduPresent = true;
    setup.erabs[0].nasPdu = {0x27, 0, 0, 0, 0, 1, 0};
    auto bytes = s1ap::EncodeErabSetupRequest(setup);
    lab.sender.fail = true;
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
    CHECK(lab.entry.bearer.active());
    CHECK(lab.entry.dedicatedBearers.size() == 1);
    CHECK(lab.entry.dedicatedBearers[0].parameters().erabId == 6);
    CHECK(lab.entry.dedicatedBearers[0].parameters().localTeid == 0);
    CHECK(lab.notifications().empty());
    lab.sender.fail = false;
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
    CHECK(lab.entry.dedicatedBearers[0].signalingEstablished());
    lab.ready(6);
    CHECK(lab.entry.dedicatedBearers[0].active());
}

TEST_CASE("restoration/lifecycle: radio delivery failure cannot prevent S1 Release Complete")
{
    Lab lab;
    lab.entry.peer = InetAddress("127.0.0.1", 0); // inject an invalid UDP destination
    auto release = s1ap::EncodeUeContextReleaseCommand(101, 1, "radioNetwork", 20);
    lab.mux.handleS1ap(release.data(), release.size(), 1);
    REQUIRE(lab.sender.sent.size() == 1);
    CHECK(lab.outcome().procedureCode == 23);
    CHECK(lab.outcome().kind == s1ap::S1apPdu::Kind::SUCCESSFUL_OUTCOME);
    CHECK(lab.entry.s1 == UeS1State::IDLE_RETAINED);
    CHECK(lab.entry.bearer.logicalConfirmed());
    CHECK(lab.mux.registry().findByEnbUeS1apId(1) == nullptr);
}
