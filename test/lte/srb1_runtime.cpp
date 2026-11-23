//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B2: SRB1 configuration mapping, the pre-security SRB PDCP
// runtime, the RRCConnectionSetupComplete codec and the actual RRC connection
// runtime over the simulated Uu.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/lte_am.hpp>
#include <lte/rrc-runtime/rrc_connection_setup_complete.hpp>
#include <lte/rrc-runtime/rrc_srb1_runtime.hpp>
#include <lte/rrc-runtime/srb1_pdcp.hpp>
#include <lte/rrc-runtime/srb1_rlc_config.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "uu_relay.hpp"

using namespace lte;
using namespace lte::rrc;
using namespace uu_test;

namespace
{

constexpr uint32_t Assoc = 0x6201;
constexpr uint32_t AssocB = 0x6202;

// The SRB1 configuration the tests offer, in TS 36.331 enumerator values:
// t-PollRetransmit ms15, pollPDU p8, pollByte kB50, maxRetxThreshold t8,
// t-Reordering ms5, t-StatusProhibit ms5.
RrcConnectionSetupMessage Srb1Setup(uint8_t transactionId = 0)
{
    RrcConnectionSetupMessage setup;
    setup.transactionId = transactionId;
    setup.srbIdentity = 1;
    setup.tPollRetransmit = 2;
    setup.pollPdu = 1;
    setup.pollByte = 1;
    setup.maxRetxThreshold = 5;
    setup.tReordering = 1;
    setup.tStatusProhibit = 1;
    return setup;
}

std::vector<uint8_t> TestNas()
{
    return {0x07, 0x41, 0x71, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
}

UeSrb1Runtime::Config UeConfig(uint32_t association)
{
    UeSrb1Runtime::Config config;
    config.association = association;
    config.mmec = 0x01;
    config.mTmsi = 0xC000038D;
    config.selectedPlmnIdentity = 1;
    return config;
}

} // namespace

TEST_CASE("lte/srb1/config/the ts 36.331 enumerations become runtime timer and poll parameters")
{
    const Srb1ResolvedConfig resolved = MapSrb1Configuration(Srb1Setup());
    CHECK(resolved.pollRetransmitMs == 15);
    CHECK(resolved.am.pollTicks == 15);
    CHECK(resolved.reorderingMs == 5);
    CHECK(resolved.am.reorderingTicks == 5);
    CHECK(resolved.statusProhibitMs == 5);
    CHECK(resolved.am.prohibitTicks == 5);
    CHECK(resolved.pollPduCount == 8);
    CHECK(resolved.am.pollPdu == 8);
    CHECK(resolved.pollByteCount == 50);
    CHECK(resolved.am.pollByte == 50);
    // maxRetxThreshold t8 counts retransmissions; the entity counts
    // transmissions, so it fails after the ninth one.
    CHECK(resolved.maxRetransmissions == 8);
    CHECK(resolved.am.maxRetx == 9);

    // The first and last defined enumerators of each table.
    RrcConnectionSetupMessage first;
    first.srbIdentity = 1;
    first.tPollRetransmit = 0;
    first.pollPdu = 0;
    first.pollByte = 0;
    first.maxRetxThreshold = 0;
    first.tReordering = 0;
    first.tStatusProhibit = 0;
    const auto low = MapSrb1Configuration(first);
    CHECK(low.pollRetransmitMs == 5);
    CHECK(low.reorderingMs == 0);
    CHECK(low.statusProhibitMs == 0);
    CHECK(low.pollPduCount == 4);
    CHECK(low.pollByteCount == 25);
    CHECK(low.maxRetransmissions == 1);
    CHECK(low.am.maxRetx == 2);

    RrcConnectionSetupMessage high;
    high.srbIdentity = 1;
    high.tPollRetransmit = 58;   // ms4000
    high.pollPdu = 7;            // pInfinity
    high.pollByte = 14;          // kBinfinity
    high.maxRetxThreshold = 7;   // t32
    high.tReordering = 31;       // ms1600
    high.tStatusProhibit = 61;   // ms2400
    const auto top = MapSrb1Configuration(high);
    CHECK(top.pollRetransmitMs == 4000);
    CHECK(top.pollPduCount == 0);
    CHECK(top.pollByteCount == 0);
    CHECK(top.maxRetransmissions == 32);
    CHECK(top.am.maxRetx == 33);
    CHECK(top.reorderingMs == 1600);
    CHECK(top.statusProhibitMs == 2400);
}

TEST_CASE("lte/srb1/config/the timer conversion is not a cast")
{
    Srb1RuntimeTiming timing;
    timing.tickMilliseconds = 5;
    const auto resolved = MapSrb1Configuration(Srb1Setup(), timing);
    CHECK(resolved.pollRetransmitMs == 15);
    CHECK(resolved.am.pollTicks == 3);
    CHECK(resolved.reorderingMs == 5);
    CHECK(resolved.am.reorderingTicks == 1);
    CHECK(resolved.statusProhibitMs == 5);
    CHECK(resolved.am.prohibitTicks == 1);

    RrcConnectionSetupMessage setup = Srb1Setup();
    setup.tPollRetransmit = 58;  // ms4000
    const auto longTimer = MapSrb1Configuration(setup, timing);
    CHECK(longTimer.am.pollTicks == 800);
}

TEST_CASE("lte/srb1/config/unsupported enumerators and identities are refused by name")
{
    auto expectRefusal = [](RrcConnectionSetupMessage setup, Srb1ConfigError reason) {
        try
        {
            (void)MapSrb1Configuration(setup);
            FAIL("the configuration was accepted");
        }
        catch (const Srb1ConfigException &error)
        {
            CHECK(error.Reason() == reason);
        }
    };

    auto setup = Srb1Setup();
    setup.srbIdentity = 2;
    expectRefusal(setup, Srb1ConfigError::INVALID_SRB_IDENTITY);

    setup = Srb1Setup();
    setup.tPollRetransmit = 59;  // spare5
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_T_POLL_RETRANSMIT);

    setup = Srb1Setup();
    setup.pollPdu = 8;
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_POLL_PDU);

    setup = Srb1Setup();
    setup.pollByte = 15;  // spare1
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_POLL_BYTE);

    setup = Srb1Setup();
    setup.maxRetxThreshold = 8;
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_MAX_RETX_THRESHOLD);

    setup = Srb1Setup();
    setup.tReordering = 32;
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_T_REORDERING);

    setup = Srb1Setup();
    setup.tStatusProhibit = 62;  // spare2
    expectRefusal(setup, Srb1ConfigError::UNSUPPORTED_T_STATUS_PROHIBIT);

    Srb1RuntimeTiming zeroTick;
    zeroTick.tickMilliseconds = 0;
    try
    {
        (void)MapSrb1Configuration(Srb1Setup(), zeroTick);
        FAIL("a zero tick was accepted");
    }
    catch (const Srb1ConfigException &error)
    {
        CHECK(error.Reason() == Srb1ConfigError::ZERO_TICK);
    }
}

TEST_CASE("lte/srb1/pdcp/the pre-security srb header carries only a five bit sn")
{
    auto tx = pdcp::SrbPdcpEntity::Create(true);
    const std::vector<uint8_t> sdu = {0x00, 0xFF, 0x7E, 0x00};
    const auto pdu = tx.Protect(sdu);

    REQUIRE(pdu.size() == 1 + sdu.size());
    CHECK(pdu[0] == 0x00);  // three reserved bits zero, SN 0
    CHECK(std::vector<uint8_t>(pdu.begin() + 1, pdu.end()) == sdu);
    CHECK(tx.NextSn() == 1);
    CHECK(tx.NextCount() == 1);
    CHECK(tx.TxHfn() == 0);

    auto rx = pdcp::SrbPdcpEntity::Create(false);
    CHECK(rx.Unprotect(pdu) == sdu);
    CHECK(rx.ExpectedSn() == 1);
    CHECK(rx.ReceivedCount() == 1);
    CHECK(rx.Delivered() == 1);
}

TEST_CASE("lte/srb1/pdcp/the sn wraps at 32 and the hfn follows the count")
{
    auto tx = pdcp::SrbPdcpEntity::Create(true);
    std::vector<uint8_t> sns;
    for (int i = 0; i < 40; i++)
    {
        const auto pdu = tx.Protect({static_cast<uint8_t>(i)});
        sns.push_back(static_cast<uint8_t>(pdu[0] & 0x1FU));
    }
    for (int i = 0; i < 40; i++)
        CHECK(sns[static_cast<size_t>(i)] == static_cast<uint8_t>(i % 32));

    CHECK(tx.NextCount() == 40);
    CHECK(tx.NextSn() == 8);
    CHECK(tx.TxHfn() == 1);

    auto rx = pdcp::SrbPdcpEntity::Create(false);
    auto tx2 = pdcp::SrbPdcpEntity::Create(true);
    for (int i = 0; i < 40; i++)
    {
        const auto pdu = tx2.Protect({static_cast<uint8_t>(i)});
        REQUIRE(rx.Unprotect(pdu) == std::vector<uint8_t>({static_cast<uint8_t>(i)}));
    }
    CHECK(rx.ReceivedCount() == 40);
    CHECK(rx.ExpectedSn() == 8);
    CHECK(rx.RxHfn() == 1);
}

TEST_CASE("lte/srb1/pdcp/duplicates, gaps, reserved bits and short pdus are refused")
{
    auto tx = pdcp::SrbPdcpEntity::Create(true);
    auto rx = pdcp::SrbPdcpEntity::Create(false);

    const auto first = tx.Protect({0x10});
    REQUIRE(rx.Unprotect(first) == std::vector<uint8_t>({0x10}));

    try
    {
        (void)rx.Unprotect(first);
        FAIL("a duplicate was accepted");
    }
    catch (const pdcp::SrbPdcpException &error)
    {
        CHECK(error.Reason() == pdcp::SrbPdcpError::DUPLICATE);
    }

    const auto second = tx.Protect({0x11});
    const auto third = tx.Protect({0x12});
    try
    {
        (void)rx.Unprotect(third);
        FAIL("a gap was accepted");
    }
    catch (const pdcp::SrbPdcpException &error)
    {
        CHECK(error.Reason() == pdcp::SrbPdcpError::OUT_OF_SEQUENCE);
    }
    REQUIRE(rx.Unprotect(second) == std::vector<uint8_t>({0x11}));
    REQUIRE(rx.Unprotect(third) == std::vector<uint8_t>({0x12}));

    auto reserved = third;
    reserved[0] |= 0xE0;
    try
    {
        (void)rx.Unprotect(reserved);
        FAIL("a reserved bit was accepted");
    }
    catch (const pdcp::SrbPdcpException &error)
    {
        CHECK(error.Reason() == pdcp::SrbPdcpError::RESERVED_BITS_SET);
    }

    try
    {
        (void)rx.Unprotect({});
        FAIL("an empty PDU was accepted");
    }
    catch (const pdcp::SrbPdcpException &error)
    {
        CHECK(error.Reason() == pdcp::SrbPdcpError::MALFORMED_PDU);
    }

    rx.Release();
    try
    {
        (void)rx.Unprotect(first);
        FAIL("a released entity accepted a PDU");
    }
    catch (const pdcp::SrbPdcpException &error)
    {
        CHECK(error.Reason() == pdcp::SrbPdcpError::RELEASED);
    }
}

TEST_CASE("lte/srb1/setup-complete/uper round trips the nas payload and the transaction identifier")
{
    RrcConnectionSetupCompleteMessage message;
    message.transactionId = 2;
    message.selectedPlmnIdentity = 4;
    message.dedicatedInfoNas = TestNas();

    const auto encoded = EncodeRrcConnectionSetupComplete(message);
    REQUIRE_FALSE(encoded.empty());

    RrcConnectionSetupCompleteMessage decoded;
    REQUIRE(DecodeRrcConnectionSetupComplete(encoded.data(), encoded.size(), decoded));
    CHECK(decoded.transactionId == 2);
    CHECK(decoded.selectedPlmnIdentity == 4);
    CHECK(decoded.dedicatedInfoNas == TestNas());

    // A setup is not a setup complete.
    const auto setup = [&] {
        RrcConnectionSetupMessage value;
        value.srbIdentity = 1;
        value.tPollRetransmit = 2;
        return EncodeRrcConnectionSetup(value);
    }();
    REQUIRE_FALSE(setup.empty());
    CHECK_FALSE(DecodeRrcConnectionSetupComplete(setup.data(), setup.size(), decoded));

    auto invalid = message;
    invalid.transactionId = 4;
    CHECK(EncodeRrcConnectionSetupComplete(invalid).empty());
    invalid = message;
    invalid.selectedPlmnIdentity = 0;
    CHECK(EncodeRrcConnectionSetupComplete(invalid).empty());
    invalid = message;
    invalid.dedicatedInfoNas.clear();
    CHECK(EncodeRrcConnectionSetupComplete(invalid).empty());
    CHECK_FALSE(DecodeRrcConnectionSetupComplete(encoded.data(), encoded.size() - 1, decoded));
}

namespace
{

// One UE endpoint and one eNB endpoint, optionally with the deterministic link
// node between them. The runtimes borrow the sockets; this object owns them.
struct Session
{
    std::unique_ptr<uu::Socket> ueSocket{};
    std::unique_ptr<uu::Socket> enbSocket{};
    std::unique_ptr<UuRelay> relay{};
    std::unique_ptr<UeSrb1Runtime> ue{};
    std::unique_ptr<EnbSrb1Runtime> enb{};
    std::vector<RrcConnectionSetupCompleteMessage> delivered{};
    uint32_t association{Assoc};

    bool Build(uint32_t assoc, bool relayed, const RrcConnectionSetupMessage &setup = Srb1Setup())
    {
        association = assoc;
        auto ueSock = uu::Socket::BindLoopback(0, nullptr);
        auto enbSock = uu::Socket::BindLoopback(0, nullptr);
        if (!ueSock || !enbSock)
            return false;

        const uint16_t uePort = ueSock->Port();
        const uint16_t enbPort = enbSock->Port();
        uint16_t peerPort = enbPort;

        if (relayed)
        {
            relay = std::make_unique<UuRelay>();
            if (!relay->Bind(nullptr))
                return false;
            relay->SetPeers(uePort, enbPort);
            peerPort = relay->UeFacingPort();
        }

        ueSocket = std::make_unique<uu::Socket>(std::move(*ueSock));
        enbSocket = std::make_unique<uu::Socket>(std::move(*enbSock));
        ue = std::make_unique<UeSrb1Runtime>(*ueSocket, peerPort, UeConfig(assoc));

        EnbSrb1Runtime::Config config;
        config.expectedPlmnIdentity = 1;
        config.setupTransactionId = setup.transactionId;
        config.setup = setup;
        enb = std::make_unique<EnbSrb1Runtime>(
            *enbSocket, config,
            [this](uint32_t, const RrcConnectionSetupCompleteMessage &message) { delivered.push_back(message); });
        return true;
    }

    void Round()
    {
        if (relay)
            relay->Pump();
        ue->Pump(0);
        enb->Pump(0);
        ue->Tick();
        enb->Tick();
    }

    bool RunUntil(const std::function<bool()> &done, int maxRounds)
    {
        for (int i = 0; i < maxRounds; i++)
        {
            Round();
            if (done())
                return true;
        }
        return done();
    }

    [[nodiscard]] bool Connected() const
    {
        return ue->State() == RrcState::RRC_CONNECTED && enb->StateOf(association) == RrcState::RRC_CONNECTED;
    }
};

bool Establish(Session &session, const std::vector<uint8_t> &nas, int maxRounds)
{
    session.ue->StartAccess();
    if (!session.RunUntil([&] { return session.ue->State() == RrcState::RRC_SRB1_CONFIGURING; }, 60))
        return false;
    session.ue->SubmitSetupComplete(nas);
    return session.RunUntil([&] { return session.Connected(); }, maxRounds);
}

std::vector<uint8_t> PdcpPdu(uint8_t sn, const std::vector<uint8_t> &rrc)
{
    std::vector<uint8_t> pdu{static_cast<uint8_t>(sn & 0x1FU)};
    pdu.insert(pdu.end(), rrc.begin(), rrc.end());
    return pdu;
}

std::vector<uint8_t> SetupCompleteFor(uint8_t transactionId, const std::vector<uint8_t> &nas, uint8_t plmn = 1)
{
    RrcConnectionSetupCompleteMessage message;
    message.transactionId = transactionId;
    message.selectedPlmnIdentity = plmn;
    message.dedicatedInfoNas = nas;
    return EncodeRrcConnectionSetupComplete(message);
}

bool InjectAmd(uint16_t port, uint32_t association, uu::Direction direction, uu::LogicalChannel channel, uint16_t sn,
               const std::vector<uint8_t> &data)
{
    auto probe = uu::Socket::BindLoopback(0, nullptr);
    if (!probe)
        return false;
    AmdPdu pdu;
    pdu.sn = sn;
    pdu.data = data;
    uu::Frame frame;
    frame.association = association;
    frame.direction = direction;
    frame.channel = channel;
    frame.payload = EncodeAmd(pdu);
    return probe->Send(port, frame, nullptr);
}

// Drives the SRB0 exchange only, so a test can inject its own SRB1 PDU.
bool ReachSetupPending(Session &session)
{
    session.ue->StartAccess();
    return session.RunUntil([&] { return session.ue->State() == RrcState::RRC_SRB1_CONFIGURING; }, 60);
}

} // namespace

TEST_CASE("lte/srb1/e2e/setupcomplete crosses the uu on srb1 and the enb decodes it")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));

    const auto nas = TestNas();
    REQUIRE(Establish(session, nas, 300));

    CHECK(session.ue->State() == RrcState::RRC_CONNECTED);
    CHECK(session.enb->StateOf(Assoc) == RrcState::RRC_CONNECTED);
    REQUIRE(session.delivered.size() == 1);
    CHECK(session.delivered[0].dedicatedInfoNas == nas);
    CHECK(session.delivered[0].transactionId == 0);
    CHECK(session.delivered[0].selectedPlmnIdentity == 1);
    CHECK(session.enb->Deliveries(Assoc) == 1);
    CHECK(session.enb->DeliveredNas(Assoc) == nas);

    // The UE's own evidence: one RRC message, one PDCP PDU, SN 0, and the same
    // bytes the eNB's RLC delivered.
    const auto &evidence = session.ue->Evidence();
    CHECK(evidence.rrcMessages == 1);
    CHECK(evidence.pdcpPdus == 1);
    CHECK(evidence.lastPdcpSn == 0);
    CHECK(evidence.lastPdcpPdu.size() == 1 + evidence.lastRrcPdu.size());
    REQUIRE(session.enb->PdcpPdusOf(Assoc).size() == 1);
    CHECK(session.enb->PdcpPdusOf(Assoc)[0] == evidence.lastPdcpPdu);

    RrcConnectionSetupCompleteMessage sent;
    REQUIRE(DecodeRrcConnectionSetupComplete(evidence.lastRrcPdu.data(), evidence.lastRrcPdu.size(), sent));
    CHECK(sent.dedicatedInfoNas == nas);
    CHECK(sent.transactionId == 0);

    // Both endpoints instantiated the same SRB1 AM configuration.
    const auto &ueConfig = session.ue->Configuration();
    const auto &enbConfig = session.enb->ConfigurationOf(Assoc);
    CHECK(ueConfig.am.pollTicks == enbConfig.am.pollTicks);
    CHECK(ueConfig.am.reorderingTicks == enbConfig.am.reorderingTicks);
    CHECK(ueConfig.am.prohibitTicks == enbConfig.am.prohibitTicks);
    CHECK(ueConfig.am.pollPdu == enbConfig.am.pollPdu);
    CHECK(ueConfig.am.pollByte == enbConfig.am.pollByte);
    CHECK(ueConfig.am.maxRetx == enbConfig.am.maxRetx);

    // The exact sequence: request on CCCH, setup on CCCH, AMD on DCCH, STATUS.
    const auto &trace = session.relay->Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
    REQUIRE(trace.size() >= 4);
    CHECK(trace[0].channel == uu::LogicalChannel::CCCH);
    CHECK(trace[0].label == uu::Direction::UPLINK);
    CHECK(trace[1].channel == uu::LogicalChannel::CCCH);
    CHECK(trace[1].label == uu::Direction::DOWNLINK);
    CHECK(trace[2].channel == uu::LogicalChannel::DCCH);
    CHECK(trace[2].amd);
    CHECK(trace[2].label == uu::Direction::UPLINK);
    CHECK(trace[2].sn == 0);
    CHECK(trace[2].bytes == 1 + evidence.lastRrcPdu.size() + 2);
    CHECK(trace[3].amd == false);
    CHECK(trace[3].label == uu::Direction::DOWNLINK);
}

TEST_CASE("lte/srb1/e2e/a lost setupcomplete is recovered by rlc am, not by an application retry")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));

    Impairment uplink;
    uplink.dropAmdAt = 1;  // the first SetupComplete PDU is lost
    session.relay->SetImpairments(uplink, Impairment{});

    const auto nas = TestNas();
    REQUIRE(Establish(session, nas, 400));

    // The UE submitted exactly one RRC message through exactly one PDCP PDU.
    CHECK(session.ue->Evidence().pdcpPdus == 1);
    REQUIRE(session.ue->Srb1() != nullptr);
    CHECK(session.ue->Srb1()->Retransmissions() == 1);
    CHECK(session.enb->Deliveries(Assoc) == 1);
    CHECK(session.enb->DeliveredNas(Assoc) == nas);

    const auto &trace = session.relay->Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
    size_t lostAmd = 0;
    size_t deliveredAmd = 0;
    for (const auto &entry : trace)
    {
        if (!entry.amd)
            continue;
        if (entry.delivered)
            deliveredAmd++;
        else
            lostAmd++;
    }
    CHECK(lostAmd == 1);
    REQUIRE(deliveredAmd == 1);  // only the retransmission reached the eNB
    for (const auto &entry : trace)
    {
        if (entry.amd && entry.delivered)
            CHECK(entry.poll);
    }
}

TEST_CASE("lte/srb1/e2e/a duplicated or delayed setupcomplete still delivers the nas once")
{
    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        Impairment uplink;
        uplink.duplicateAmdAt = 1;
        session.relay->SetImpairments(uplink, Impairment{});

        const auto nas = TestNas();
        REQUIRE(Establish(session, nas, 300));
        CHECK(session.enb->Deliveries(Assoc) == 1);
        CHECK(session.enb->DeliveredNas(Assoc) == nas);
        CHECK(session.ue->Evidence().pdcpPdus == 1);
    }
    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        Impairment uplink;
        uplink.delayAmdAt = 1;
        uplink.delayRounds = 8;
        session.relay->SetImpairments(uplink, Impairment{});

        const auto nas = TestNas();
        REQUIRE(Establish(session, nas, 300));
        CHECK(session.enb->Deliveries(Assoc) == 1);
        CHECK(session.enb->DeliveredNas(Assoc) == nas);
    }
}

TEST_CASE("lte/srb1/e2e/a wrong transaction identifier is refused and the context survives")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));
    REQUIRE(ReachSetupPending(session));

    const auto nas = TestNas();
    // The setup carried transaction 0; this one claims transaction 1.
    const auto wrong = SetupCompleteFor(1, nas);
    REQUIRE_FALSE(wrong.empty());
    REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 0,
                      PdcpPdu(0, wrong)));
    session.enb->Pump(20);
    CHECK(session.enb->StateOf(Assoc) == RrcState::RRC_SETUP_PENDING);
    CHECK(session.enb->Deliveries(Assoc) == 0);
    CHECK(session.enb->RefusedSetupComplete() == 1);

    // The correct message, next PDCP SN, is still accepted.
    const auto good = SetupCompleteFor(0, nas);
    REQUIRE_FALSE(good.empty());
    REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 1,
                      PdcpPdu(1, good)));
    session.enb->Pump(20);
    CHECK(session.enb->StateOf(Assoc) == RrcState::RRC_CONNECTED);
    CHECK(session.enb->Deliveries(Assoc) == 1);
    CHECK(session.enb->DeliveredNas(Assoc) == nas);
}

TEST_CASE("lte/srb1/e2e/malformed pdcp and malformed rrc are refused before delivery")
{
    const auto nas = TestNas();
    const auto good = SetupCompleteFor(0, nas);
    REQUIRE_FALSE(good.empty());

    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        REQUIRE(ReachSetupPending(session));

        // Reserved PDCP bits set: the PDCP entity refuses and the SN is not
        // consumed.
        const auto bad = PdcpPdu(0, good);
        auto reserved = bad;
        reserved[0] |= 0xE0;
        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 0,
                          reserved));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 0);
        CHECK(session.enb->RefusedSetupComplete() == 1);

        // RLC consumed SN 0 for the refused PDU, so the retry arrives with the
        // next RLC SN; the PDCP sequence was not consumed and still expects 0.
        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 1,
                          PdcpPdu(0, good)));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 1);
    }
    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        REQUIRE(ReachSetupPending(session));

        // A valid PDCP header around bytes that are not an RRC message.
        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 0,
                          PdcpPdu(0, {0xDE, 0xAD, 0xBE, 0xEF})));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 0);
        CHECK(session.enb->RefusedSetupComplete() == 1);

        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 1,
                          PdcpPdu(1, good)));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 1);
    }
}

TEST_CASE("lte/srb1/e2e/wrong direction, channel and association never reach the pdcp")
{
    const auto nas = TestNas();
    const auto good = SetupCompleteFor(0, nas);
    REQUIRE_FALSE(good.empty());

    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        REQUIRE(ReachSetupPending(session));

        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::DOWNLINK, uu::LogicalChannel::DCCH, 0,
                          PdcpPdu(0, good)));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 0);
        CHECK(session.enb->PdcpPdusOf(Assoc).empty());
        CHECK(session.enb->RefusedFrames() == 1);
    }
    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        REQUIRE(ReachSetupPending(session));

        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::CCCH, 0,
                          PdcpPdu(0, good)));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 0);
        CHECK(session.enb->PdcpPdusOf(Assoc).empty());
    }
    {
        Session session;
        REQUIRE(session.Build(Assoc, true));
        REQUIRE(ReachSetupPending(session));

        REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc + 1, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 0,
                          PdcpPdu(0, good)));
        session.enb->Pump(20);
        CHECK(session.enb->Deliveries(Assoc) == 0);
        CHECK(session.enb->RefusedFrames() == 1);
    }
}

TEST_CASE("lte/srb1/e2e/two ue contexts keep independent srb1 state on one enb")
{
    auto enbSocket = uu::Socket::BindLoopback(0, nullptr);
    auto ueSocketA = uu::Socket::BindLoopback(0, nullptr);
    auto ueSocketB = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(enbSocket.has_value());
    REQUIRE(ueSocketA.has_value());
    REQUIRE(ueSocketB.has_value());

    // UE A reaches the eNB through the link node, so its SRB1 PDU can be lost
    // without touching UE B.
    UuRelay relayA;
    REQUIRE(relayA.Bind(nullptr));
    relayA.SetPeers(ueSocketA->Port(), enbSocket->Port());

    std::vector<std::pair<uint32_t, RrcConnectionSetupCompleteMessage>> delivered;
    EnbSrb1Runtime::Config config;
    config.setup = Srb1Setup();
    EnbSrb1Runtime enb(*enbSocket, config,
                       [&delivered](uint32_t association, const RrcConnectionSetupCompleteMessage &message) {
                           delivered.emplace_back(association, message);
                       });

    UeSrb1Runtime ueA(*ueSocketA, relayA.UeFacingPort(), UeConfig(Assoc));
    UeSrb1Runtime ueB(*ueSocketB, enbSocket->Port(), UeConfig(AssocB));

    ueA.StartAccess();
    ueB.StartAccess();

    auto pump = [&](int rounds) {
        for (int i = 0; i < rounds; i++)
        {
            relayA.Pump();
            ueA.Pump(0);
            ueB.Pump(0);
            enb.Pump(0);
            ueA.Tick();
            ueB.Tick();
            enb.Tick();
        }
    };

    for (int i = 0; i < 60 && (ueA.State() != RrcState::RRC_SRB1_CONFIGURING ||
                              ueB.State() != RrcState::RRC_SRB1_CONFIGURING);
         i++)
        pump(1);
    REQUIRE(ueA.State() == RrcState::RRC_SRB1_CONFIGURING);
    REQUIRE(ueB.State() == RrcState::RRC_SRB1_CONFIGURING);
    CHECK(enb.ContextCount() == 2);

    const auto nasA = std::vector<uint8_t>{0xA1, 0xA2, 0xA3};
    const auto nasB = std::vector<uint8_t>{0xB1, 0xB2};

    // Lose UE A's first SRB1 PDU. B must complete while A is still recovering.
    Impairment uplink;
    uplink.dropAmdAt = 1;
    relayA.SetImpairments(uplink, Impairment{});

    ueA.SubmitSetupComplete(nasA);
    ueB.SubmitSetupComplete(nasB);
    for (int i = 0; i < 40 && ueB.State() != RrcState::RRC_CONNECTED; i++)
        pump(1);
    CHECK(ueB.State() == RrcState::RRC_CONNECTED);
    CHECK(ueA.State() != RrcState::RRC_CONNECTED);
    CHECK(enb.StateOf(AssocB) == RrcState::RRC_CONNECTED);
    CHECK(enb.StateOf(Assoc) == RrcState::RRC_SETUP_PENDING);

    for (int i = 0; i < 200 && (ueA.State() != RrcState::RRC_CONNECTED || ueB.State() != RrcState::RRC_CONNECTED); i++)
        pump(1);

    CHECK(ueA.State() == RrcState::RRC_CONNECTED);
    CHECK(ueB.State() == RrcState::RRC_CONNECTED);
    CHECK(enb.StateOf(Assoc) == RrcState::RRC_CONNECTED);
    CHECK(enb.StateOf(AssocB) == RrcState::RRC_CONNECTED);
    CHECK(enb.DeliveredNas(Assoc) == nasA);
    CHECK(enb.DeliveredNas(AssocB) == nasB);
    REQUIRE(delivered.size() == 2);
    CHECK(delivered[0].first == AssocB);  // the undisturbed context arrived first
    CHECK(delivered[1].first == Assoc);
    CHECK(delivered[0].second.dedicatedInfoNas == nasB);
    CHECK(delivered[1].second.dedicatedInfoNas == nasA);

    // Both UEs started their own PDCP sequence at zero, and each eNB context
    // keeps its own RX count and an untouched TX count.
    CHECK(ueA.Evidence().lastPdcpSn == 0);
    CHECK(ueB.Evidence().lastPdcpSn == 0);
    CHECK(ueA.Pdcp().NextSn() == 1);
    CHECK(ueB.Pdcp().NextSn() == 1);
    REQUIRE(enb.PdcpOf(Assoc) != nullptr);
    REQUIRE(enb.PdcpOf(AssocB) != nullptr);
    CHECK(enb.PdcpOf(Assoc)->ReceivedCount() == 1);
    CHECK(enb.PdcpOf(AssocB)->ReceivedCount() == 1);
    CHECK(enb.PdcpOf(Assoc)->NextCount() == 0);
    CHECK(enb.PdcpOf(AssocB)->NextCount() == 0);
}

TEST_CASE("lte/srb1/e2e/release drops the srb1 context and a new one starts from sn zero")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));
    REQUIRE(Establish(session, TestNas(), 300));
    REQUIRE(session.enb->Deliveries(Assoc) == 1);

    session.enb->Release(Assoc);
    CHECK_FALSE(session.enb->HasContext(Assoc));
    CHECK(session.enb->StateOf(Assoc) == RrcState::RRC_IDLE);

    // A frame for the released context is refused before any entity sees it.
    const auto nas = TestNas();
    const auto message = SetupCompleteFor(0, nas);
    REQUIRE_FALSE(message.empty());
    REQUIRE(InjectAmd(session.enbSocket->Port(), Assoc, uu::Direction::UPLINK, uu::LogicalChannel::DCCH, 0,
                      PdcpPdu(0, message)));
    session.enb->Pump(20);
    CHECK(session.enb->Deliveries(Assoc) == 0);
    CHECK(session.enb->RefusedFrames() == 1);

    // A replacement UE on a new radio endpoint establishes a fresh context.
    Session replacement;
    REQUIRE(replacement.Build(Assoc, true));
    REQUIRE(Establish(replacement, nas, 300));
    CHECK(replacement.enb->Deliveries(Assoc) == 1);
    CHECK(replacement.ue->Evidence().lastPdcpSn == 0);
    CHECK(replacement.enb->PdcpPdusOf(Assoc).size() == 1);
}

namespace
{

struct ChildReport
{
    uint8_t state{0};
    uint8_t pdcpSn{0};
    uint32_t pdcpPdus{0};
    uint16_t vtA{0};
    uint16_t vtS{0};
    uint16_t nasSize{0};
};

bool ReadAll(int fd, void *buffer, size_t size)
{
    auto *out = static_cast<uint8_t *>(buffer);
    size_t done = 0;
    while (done < size)
    {
        const ssize_t got = ::read(fd, out + done, size - done);
        if (got <= 0)
            return false;
        done += static_cast<size_t>(got);
    }
    return true;
}

bool WriteAll(int fd, const void *buffer, size_t size)
{
    const auto *in = static_cast<const uint8_t *>(buffer);
    size_t done = 0;
    while (done < size)
    {
        const ssize_t put = ::write(fd, in + done, size - done);
        if (put <= 0)
            return false;
        done += static_cast<size_t>(put);
    }
    return true;
}

} // namespace

TEST_CASE("lte/srb1/e2e/a separate ue process completes the whole rrc connection")
{
    auto enbSocket = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(enbSocket.has_value());

    int toChild[2] = {-1, -1};
    int toParent[2] = {-1, -1};
    REQUIRE(::pipe(toChild) == 0);
    REQUIRE(::pipe(toParent) == 0);

    const auto nas = TestNas();
    const pid_t child = ::fork();
    REQUIRE(child >= 0);

    if (child == 0)
    {
        ::close(toChild[1]);
        ::close(toParent[0]);
        enbSocket->Close();

        uint16_t enbPort = 0;
        if (!ReadAll(toChild[0], &enbPort, sizeof(enbPort)))
            ::_exit(11);
        auto ueSocket = uu::Socket::BindLoopback(0, nullptr);
        if (!ueSocket)
            ::_exit(12);

        UeSrb1Runtime ue(*ueSocket, enbPort, UeConfig(Assoc));
        ChildReport report;
        bool submitted = false;
        try
        {
            ue.StartAccess();
            for (int i = 0; i < 4000; i++)
            {
                ue.Pump(1);
                ue.Tick();
                if (!submitted && ue.State() == RrcState::RRC_SRB1_CONFIGURING)
                {
                    ue.SubmitSetupComplete(nas);
                    submitted = true;
                }
                if (ue.State() == RrcState::RRC_CONNECTED)
                    break;
            }
        }
        catch (...)
        {
            ::_exit(13);
        }

        report.state = static_cast<uint8_t>(ue.State());
        report.pdcpSn = ue.Evidence().lastPdcpSn;
        report.pdcpPdus = static_cast<uint32_t>(ue.Evidence().pdcpPdus);
        report.vtA = ue.Srb1() != nullptr ? ue.Srb1()->VtA() : 0;
        report.vtS = ue.Srb1() != nullptr ? ue.Srb1()->VtS() : 0;
        report.nasSize = static_cast<uint16_t>(nas.size());
        if (!WriteAll(toParent[1], &report, sizeof(report)))
            ::_exit(14);
        ::_exit(ue.State() == RrcState::RRC_CONNECTED ? 0 : 7);
    }

    ::close(toChild[0]);
    ::close(toParent[1]);

    std::vector<RrcConnectionSetupCompleteMessage> delivered;
    EnbSrb1Runtime::Config config;
    config.setup = Srb1Setup();
    EnbSrb1Runtime enb(*enbSocket, config,
                       [&delivered](uint32_t, const RrcConnectionSetupCompleteMessage &message) {
                           delivered.push_back(message);
                       });

    const uint16_t enbPort = enbSocket->Port();
    REQUIRE(WriteAll(toChild[1], &enbPort, sizeof(enbPort)));

    int status = 0;
    bool reaped = false;
    for (int i = 0; i < 6000; i++)
    {
        enb.Pump(1);
        enb.Tick();
        const pid_t done = ::waitpid(child, &status, WNOHANG);
        if (done == child)
        {
            reaped = true;
            break;
        }
    }
    if (!reaped)
        ::waitpid(child, &status, 0);

    ChildReport report;
    REQUIRE(ReadAll(toParent[0], &report, sizeof(report)));
    ::close(toParent[0]);

    REQUIRE(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    CHECK(report.state == static_cast<uint8_t>(RrcState::RRC_CONNECTED));
    CHECK(report.pdcpPdus == 1);
    CHECK(report.pdcpSn == 0);
    CHECK(report.vtA == 1);
    CHECK(report.vtS == 1);
    CHECK(report.nasSize == nas.size());

    REQUIRE(delivered.size() == 1);
    CHECK(delivered[0].dedicatedInfoNas == nas);
    CHECK(delivered[0].transactionId == 0);
    CHECK(enb.StateOf(Assoc) == RrcState::RRC_CONNECTED);
}


TEST_CASE("lte/srb1/e2e/a lost rlc status is recovered by the poll timer without a second delivery")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));

    Impairment downlink;
    downlink.dropStatusAt = 1;  // the first acknowledgement is lost
    session.relay->SetImpairments(Impairment{}, downlink);

    const auto nas = TestNas();
    REQUIRE(Establish(session, nas, 400));

    CHECK(session.enb->Deliveries(Assoc) == 1);
    CHECK(session.enb->DeliveredNas(Assoc) == nas);
    CHECK(session.ue->Evidence().pdcpPdus == 1);
    REQUIRE(session.ue->Srb1() != nullptr);
    CHECK(session.ue->Srb1()->Retransmissions() == 1);

    const auto &trace = session.relay->Trace();
    for (const auto &entry : trace)
        MESSAGE(Describe(entry));
    size_t lostStatus = 0;
    size_t deliveredStatus = 0;
    for (const auto &entry : trace)
    {
        if (entry.amd)
            continue;
        if (entry.delivered)
            deliveredStatus++;
        else
            lostStatus++;
    }
    CHECK(lostStatus == 1);
    CHECK(deliveredStatus >= 1);
}

TEST_CASE("lte/srb1/e2e/a delayed original is overtaken by the rlc retransmission")
{
    Session session;
    REQUIRE(session.Build(Assoc, true));

    // Hold the first SetupComplete longer than t-PollRetransmit, so the
    // retransmission reaches the eNB first and the original arrives after it as
    // a duplicate. The NAS is still delivered exactly once.
    Impairment uplink;
    uplink.delayAmdAt = 1;
    uplink.delayRounds = 30;
    session.relay->SetImpairments(uplink, Impairment{});

    const auto nas = TestNas();
    REQUIRE(Establish(session, nas, 400));

    CHECK(session.enb->Deliveries(Assoc) == 1);
    CHECK(session.enb->DeliveredNas(Assoc) == nas);
    CHECK(session.ue->Evidence().pdcpPdus == 1);
    REQUIRE(session.enb->PdcpOf(Assoc) != nullptr);
    CHECK(session.enb->PdcpOf(Assoc)->ReceivedCount() == 1);
    CHECK(session.enb->RefusedSetupComplete() == 0);
}

