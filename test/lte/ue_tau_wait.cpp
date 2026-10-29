//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Production-path tests for the Tracking Area Update retransmission, timeout
// and shutdown behaviour.
//
// These drive the real lte::ue::Run() over a real UDP radio link against a
// minimal fake MME. The retransmission, deadline and shutdown decisions live
// inside Run() and are only observable through its return code and its log, so
// a helper-only unit test cannot make the claim this file makes: that a running
// UE repeats the very same protected PDU on the very same route, and that a
// stop request is reported as an abandonment rather than as a timeout. Both are
// asserted here, through the production path and no other.
//
// The fake MME speaks the same NAS and radio-link codecs as production and
// reuses the public 3GPP TS 35.208 test subscriber already present in
// test/lte/ue.cpp. It creates no subscriber, touches no HSS and never reaches a
// real EPC. The UE config asks for control-plane-only mode: TUN creation is not
// required, and the single requested route carries host bits so the kernel
// rejects it and nothing is installed. No network namespace is created.

#include <ext/doctest/doctest.h>

#include "log_capture.hpp"

#include <lte/enb/codec.hpp>
#include <lte/ue/app.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>

#include <lib/udp/server.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace lte::ue;
namespace link = lte::ue::link;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The 3GPP TS 35.208 test subscriber, identical to test/lte/ue.cpp. It is
// fixture data only; no subscription is created and no HSS is consulted.
std::string UeConfig(uint16_t uePort, uint16_t mmePort, const std::string &scenario, int triggerAfterMs = 100,
                     int procedureTimeoutMs = 5000, int maxRetries = 3)
{
    std::ostringstream out;
    out << R"(imsi: '460020123456789'
mcc: '460'
mnc: '02'
k: '465B5CE8B199B49FAA5F0A2EE238A6BC'
opc: 'CD63CB71954A9F4E48A5994E37A02BAF'
amf: 'B9B9'
initialSqn: 'FF9BB4D0B607'
pdnType: IPv4
networkCapability: 'A020'
enbLink:
  localAddress: 127.0.0.1
  localPort: )"
       << uePort << R"(
  address: 127.0.0.1
  port: )"
       << mmePort << R"(
  timeoutMs: 10000
tun:
  required: false
  routes: ['192.168.5.7/24']
lifecycle:
  scenario: )"
       << scenario << R"(
  triggerAfterMs: )"
       << triggerAfterMs << R"(
  procedureTimeoutMs: )"
       << procedureTimeoutMs << R"(
  maxRetries: )"
       << maxRetries << R"(
  pagingWaitMs: 30000
  recoveryDelayMs: 0
  recoveryRetryMs: 5000
  recoveryMaxAttempts: 0
)";
    return out.str();
}

// The assigned S-TMSI of the synthetic GUTI in the Attach Accept below.
constexpr uint8_t kMmeCode = 1;
constexpr uint32_t kMTmsi = 0xC000018Eu;
constexpr uint8_t kDefaultEbi = 5;

// ---------------------------------------------------------------------------
// Fake MME
// ---------------------------------------------------------------------------

// What the fake network does once the Tracking Area Update Request arrives.
enum class TauAction
{
    // Never answer. The UE must repeat its own request and then report a
    // bounded failure.
    NoAnswer,
    // Accept the update and assign a new GUTI, so the UE owes the network a
    // protected TAU Complete before the procedure is terminated.
    AcceptWithNewGuti
};

// Minimal peer for the simulated radio link. It completes a real EPS Attach and
// then scripts the Tracking Area Update half of the lifecycle. It never logs:
// all std::cout output during a test belongs to the production UE.
class FakeMme
{
  public:
    FakeMme(const std::string &address, uint16_t port) : m_socket(address, port)
    {
    }
    ~FakeMme()
    {
        stop();
    }

    void start(const Config &config, TauAction action)
    {
        m_config = config;
        m_action = action;
        m_thread = std::thread([this] { run(); });
    }

    void stop()
    {
        m_stop = true;
        if (m_thread.joinable())
            m_thread.join();
    }

    // Observations the tests assert on. They are written on the MME thread and
    // read only after stop() has joined it.
    std::vector<std::string> frames;
    std::vector<std::string> failures;
    // Every Tracking Area Update Request the network saw, paired with the radio
    // message type it arrived on, so a test can prove a retransmission repeats
    // the same protected PDU on the same route instead of consuming a new NAS
    // COUNT or a different uplink route.
    std::vector<std::pair<link::MessageType, std::vector<uint8_t>>> tauRequests;
    int tauCompletes{};
    int protectedUplinks{};
    uint32_t lastUplinkCount{};
    bool attachComplete{};

  private:
    void fail(const std::string &reason)
    {
        failures.push_back(reason);
        m_stop = true;
    }

    void run()
    {
        try
        {
            while (!m_stop)
            {
                uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
                InetAddress peer;
                const int received = m_socket.Receive(buffer, sizeof(buffer), 20, peer);
                if (received <= 0)
                    continue;
                const auto frame = link::Decode(buffer, static_cast<size_t>(received));
                if (frame.ueId != m_config.ueId)
                {
                    fail("radio frame carried an unexpected UE identity");
                    return;
                }
                if (!handle(frame, peer))
                    return;
            }
        }
        catch (const std::exception &e)
        {
            fail(e.what());
        }
    }

    bool handle(const link::Message &frame, const InetAddress &peer)
    {
        switch (frame.type)
        {
        case link::MessageType::NAS_UPLINK:
            frames.push_back("NAS_UPLINK");
            return onNas(frame.type, frame.payload, peer);
        default:
            frames.push_back("OTHER");
            fail("radio frame type is not part of the scripted Attach/TAU exchange");
            return false;
        }
    }

    static bool IsTauRequest(const std::vector<uint8_t> &plain)
    {
        return plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x48;
    }

    bool onNas(link::MessageType route, const std::vector<uint8_t> &payload, const InetAddress &peer)
    {
        if (payload.size() < 2)
        {
            fail("truncated NAS uplink");
            return false;
        }
        if (payload[0] == 0x07 && payload[1] == 0x41)
        {
            // Derive the same EPS AKA context the UE will, so the two sides
            // agree on RES, CK, IK and KASME without any new credential.
            const auto challenge = AuthRequestBytes();
            m_security = nas::Authenticate(m_config, nas::DecodeAuthenticationRequest(challenge.data(),
                                                                                     challenge.size()))
                             .context;
            m_security.advertisedSecurityCapabilities.assign(m_config.networkCapability.begin(),
                                                             m_config.networkCapability.end());
            sendNas(peer, challenge);
            return true;
        }
        if (payload[0] == 0x07 && payload[1] == 0x53)
        {
            // Authentication Response is plain EMM; the matching context was
            // derived when the challenge was built.
            sendNas(peer, SecurityModeCommand());
            return true;
        }

        const auto parsed = nas::ParseProtectedHeader(payload.data(), payload.size());
        const bool fresh = nas::StartsNewContext(parsed.headerType);
        const uint32_t count =
            fresh ? parsed.sequenceNumber : nas::EstimateNasCount(m_security.ulNasCount, parsed.sequenceNumber);
        if (!fresh && count <= m_security.ulNasCount)
        {
            // A retransmission repeats the protected PDU it already sent and
            // therefore repeats its NAS COUNT. That is not a replay: a replay
            // reuses the COUNT with a different body. Only the byte-identical
            // repeat is admitted, and it is not a new uplink.
            if (count == m_security.ulNasCount && payload == m_lastProtectedUplink)
            {
                if (IsTauRequest(m_lastUplinkPlain))
                    tauRequests.emplace_back(route, payload);
                return true;
            }
            fail("replayed uplink NAS COUNT");
            return false;
        }
        auto plain = nas::UnprotectBody(m_security, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                        parsed.plain);
        m_security.ulNasCount = count;
        lastUplinkCount = count;
        ++protectedUplinks;
        m_lastProtectedUplink = payload;
        m_lastUplinkPlain = plain;
        if (IsTauRequest(plain))
            tauRequests.emplace_back(route, payload);

        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x5E)
        {
            sendNas(peer, ProtectDownlink(AttachAccept(), /*newContext=*/false));
            return true;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x43)
        {
            attachComplete = true;
            return true;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x48)
        {
            if (m_action == TauAction::AcceptWithNewGuti)
                sendNas(peer, ProtectDownlink(TauAccept(FreshGuti()), /*newContext=*/false));
            return true;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x4A)
        {
            ++tauCompletes;
            return true;
        }
        return true;
    }

    void sendNas(const InetAddress &peer, std::vector<uint8_t> nas)
    {
        send(link::MessageType::NAS_DOWNLINK, std::move(nas), peer);
    }

    void send(link::MessageType type, std::vector<uint8_t> payload, const InetAddress &peer)
    {
        const auto frame = link::Encode({type, m_config.ueId, std::move(payload)});
        m_socket.Send(peer, frame.data(), frame.size());
    }

    // The Security Mode Command must reach the UE on the integrity-only
    // "new EPS security context" header so its information elements stay
    // readable in the clear. nas::Protect with a fresh context always selects
    // the ciphered new-context header, and this fixture negotiates EEA0, so the
    // protected body is already the plain message and only the header nibble
    // has to be corrected. The MAC covers sequenceNumber||body and is
    // unchanged.
    std::vector<uint8_t> SecurityModeCommand()
    {
        const std::vector<uint8_t> plain{0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
        const auto command = nas::DecodeSecurityModeCommand(plain.data(), plain.size());
        nas::ValidateSecurityModeCommand(m_config, command, m_security);
        m_security.kNasInt = nas::DeriveKnasInt(m_security.kasme, m_security.integrity);
        m_security.kNasEnc = nas::DeriveKnasEnc(m_security.kasme, m_security.ciphering);
        m_security.keysDerived = true;
        auto envelope = ProtectDownlink(plain, /*newContext=*/true);
        envelope[0] = static_cast<uint8_t>(
            (static_cast<uint8_t>(SecurityHeaderType::INTEGRITY_PROTECTED_WITH_NEW_CONTEXT) << 4U) | 0x07U);
        return envelope;
    }

    std::vector<uint8_t> ProtectDownlink(const std::vector<uint8_t> &plain, bool newContext)
    {
        auto message = nas::Protect(m_security, /*uplink=*/false, newContext, plain);
        m_security.dlNasCount = (m_security.dlNasCount + 1U) & 0xFFFFFFU;
        return message;
    }

    static std::vector<uint8_t> AuthRequestBytes()
    {
        return {0x07, 0x52, 0x07,
                0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
                0x10, 0x55, 0xF3, 0x28, 0xB4, 0x35, 0x77, 0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF,
                0xB3};
    }

    // Attach Accept with a full TAI list for the served PLMN/TAC and the GUTI
    // the TAU Request is later identified by. Both are built from the same PLMN
    // encoding the UE uses, so the fixture cannot drift from the codec.
    std::vector<uint8_t> AttachAccept() const
    {
        const auto plmn = lte::enb::s1ap::EncodePlmn(m_config.plmn);

        // Activate Default EPS Bearer Context Request: EBI 5, PTI 1, QCI 5,
        // APN "internet", PDN address 10.0.0.1.
        const std::vector<uint8_t> esm{0x52, 0x01, 0xC1,
                                       0x01, 0x05,
                                       0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74,
                                       0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};

        std::vector<uint8_t> out{0x07, 0x42,
                                 0x01, // EPS attach result
                                 0x30, // GPRS timer T3412
                                 0x06, // TAI list length
                                 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x01};
        out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
        out.push_back(static_cast<uint8_t>(esm.size()));
        out.insert(out.end(), esm.begin(), esm.end());

        // GUTI optional IE: MMEC 1, M-TMSI 0xC000018E.
        out.push_back(0x50);
        out.push_back(0x0B);
        out.push_back(0xF6);
        out.insert(out.end(), plmn.begin(), plmn.end());
        out.insert(out.end(), {0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
        return out;
    }

    // A fresh but otherwise identical EPS GUTI: same PLMN and MME group, a new
    // M-TMSI. Accepting it is what obliges the UE to send a TAU Complete.
    std::array<uint8_t, 11> FreshGuti() const
    {
        const auto plmn = lte::enb::s1ap::EncodePlmn(m_config.plmn);
        std::array<uint8_t, 11> guti{};
        guti[0] = 0xF6;
        guti[1] = plmn[0];
        guti[2] = plmn[1];
        guti[3] = plmn[2];
        guti[4] = 0x00;
        guti[5] = 0x01;
        guti[6] = kMmeCode;
        guti[7] = 0xC0;
        guti[8] = 0x00;
        guti[9] = 0x01;
        guti[10] = 0x8F;
        return guti;
    }

    // A Tracking Area Update Accept the network itself would author: the plain
    // EPS-only "TA updated" result this procedure performs, a periodic timer, a
    // tracking area list for the served PLMN/TAC and optionally a new GUTI. It
    // is built from the same PLMN encoding the UE uses and carries no bearer
    // context status, so it cannot drop a bearer the UE still holds.
    std::vector<uint8_t> TauAccept(const std::optional<std::array<uint8_t, 11>> &newGuti) const
    {
        const auto plmn = lte::enb::s1ap::EncodePlmn(m_config.plmn);
        std::vector<uint8_t> out{0x07, 0x49, 0x00};
        out.push_back(0x5A); // GPRS timer T3412, type-1 optional IE
        out.push_back(0x30);
        out.insert(out.end(), {0x54, 0x06, 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x01});
        if (newGuti.has_value())
        {
            out.push_back(0x50);
            out.push_back(0x0B);
            out.insert(out.end(), newGuti->begin(), newGuti->end());
        }
        return out;
    }

    Config m_config;
    TauAction m_action{TauAction::NoAnswer};
    udp::UdpServer m_socket;
    SecurityContext m_security{};
    std::vector<uint8_t> m_lastProtectedUplink;
    std::vector<uint8_t> m_lastUplinkPlain;
    std::thread m_thread;
    std::atomic_bool m_stop{false};
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Session
{
    std::unique_ptr<lte::test::LogCapture> capture;
    std::unique_ptr<FakeMme> mme;
    std::atomic_bool shutdown{false};
    int exitCode{-1};
    std::string log;
    Clock::duration elapsed{};

    void run(const std::string &yaml, TauAction action, uint16_t mmePort)
    {
        const auto config = ParseConfig(yaml);
        capture = std::make_unique<lte::test::LogCapture>();
        mme = std::make_unique<FakeMme>("127.0.0.1", mmePort);
        mme->start(config, action);

        const auto started = Clock::now();
        std::thread ue([&] { exitCode = lte::ue::Run(config, shutdown); });
        ue.join();
        elapsed = Clock::now() - started;
        mme->stop();
        log = capture->text();
        // Restore std::cout before any assertion so a failure is visible.
        capture.reset();
    }

    // Runs the UE on a worker thread so the test can observe production state
    // before asking for a stop. Used only where the shutdown has to land
    // against a known outstanding Tracking Area Update.
    void startAsync(const std::string &yaml, TauAction action, uint16_t mmePort)
    {
        const auto config = ParseConfig(yaml);
        capture = std::make_unique<lte::test::LogCapture>();
        mme = std::make_unique<FakeMme>("127.0.0.1", mmePort);
        mme->start(config, action);
        m_config = config;
        m_started = Clock::now();
        m_ue = std::thread([this] { exitCode = lte::ue::Run(m_config, shutdown); });
    }

    bool waitFor(const std::string &needle, int timeoutMs = 8000)
    {
        return capture->waitFor(needle, timeoutMs);
    }

    void finish()
    {
        if (m_ue.joinable())
            m_ue.join();
        elapsed = Clock::now() - m_started;
        mme->stop();
        log = capture->text();
        capture.reset();
    }

    ~Session()
    {
        shutdown = true;
        if (m_ue.joinable())
            m_ue.join();
    }

  private:
    Config m_config;
    Clock::time_point m_started{};
    std::thread m_ue;
};

bool Contains(const std::string &log, const std::string &needle)
{
    return log.find(needle) != std::string::npos;
}

} // namespace

// ---------------------------------------------------------------------------
// Bounded retransmission of a Tracking Area Update
// ---------------------------------------------------------------------------

TEST_CASE("lte/tau/wait: an unanswered Tracking Area Update is retransmitted unchanged and then fails")
{
    // The network answers the Update with silence, so the protected TAU Request
    // is retransmitted up to the configured bound and then reported as an
    // unresolved procedure. The deadline is far shorter than anything else in
    // the lifecycle, so this outcome cannot be an Attach or link timeout.
    Session session;
    session.run(UeConfig(47201, 47202, /*scenario=*/"tau-normal", /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/100, /*maxRetries=*/1),
                TauAction::NoAnswer, 47202);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Protected normal Tracking Area Update Request sent"));
    CHECK(Contains(session.log, "Retransmitted TAU_NORMAL_PENDING, retry=1"));
    // The failure is named as a bounded retransmission outcome of the Tracking
    // Area Update procedure itself, never as an Attach failure and never as a
    // completed update.
    CHECK(Contains(session.log, "TAU_NORMAL_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Tracking Area Update accepted"));
    CHECK_FALSE(Contains(session.log, "TAU_NORMAL_PENDING abandoned at shutdown"));
    CHECK_FALSE(Contains(session.log, "LTE UE shutdown complete"));

    // Exactly one initial request and one retransmission, and the retry repeats
    // the same protected PDU on the same route rather than consuming another
    // uplink NAS COUNT or leaving by a different message type.
    REQUIRE(session.mme->tauRequests.size() == 2);
    CHECK(session.mme->tauRequests[0].first == link::MessageType::NAS_UPLINK);
    CHECK(session.mme->tauRequests[1].first == link::MessageType::NAS_UPLINK);
    CHECK(session.mme->tauRequests[0].second == session.mme->tauRequests[1].second);
    // Security Mode Complete, Attach Complete and the one fresh TAU Request.
    // The retransmission is a repeat, not a fourth uplink.
    CHECK(session.mme->protectedUplinks == 3);
    CHECK(session.mme->lastUplinkCount == 2);
    CHECK(session.mme->tauCompletes == 0);
    CHECK(session.mme->attachComplete);
    CHECK(session.mme->failures.empty());
    // The failure returns through the unresolved-procedure path, so the clean
    // shutdown statistics are deliberately absent: no outcome was invented and
    // no completed run is being reported.
    CHECK_FALSE(Contains(session.log, "NAS security counts:"));
    CHECK(session.elapsed < std::chrono::seconds(5));
    // Cleanup: the run left through an explicit return, and no namespace, TUN
    // or route was created.
    CHECK(Contains(session.log, "Control-plane-only mode: LTE TUN unavailable"));
}

TEST_CASE("lte/tau/wait: an unanswered periodic Tracking Area Update fails the same way")
{
    // The periodic Update is a different NAS procedure with its own request
    // type, but the bounded retransmission and the failure attribution must not
    // depend on which of the two started.
    Session session;
    session.run(UeConfig(47203, 47204, /*scenario=*/"tau-periodic", /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/100, /*maxRetries=*/1),
                TauAction::NoAnswer, 47204);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Protected periodic Tracking Area Update Request sent"));
    CHECK(Contains(session.log, "Retransmitted TAU_PERIODIC_PENDING, retry=1"));
    CHECK(Contains(session.log, "TAU_PERIODIC_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Protected normal Tracking Area Update Request sent"));
    CHECK_FALSE(Contains(session.log, "Tracking Area Update accepted"));
    CHECK_FALSE(Contains(session.log, "TAU_PERIODIC_PENDING abandoned at shutdown"));

    REQUIRE(session.mme->tauRequests.size() == 2);
    CHECK(session.mme->tauRequests[0].second == session.mme->tauRequests[1].second);
    CHECK(session.mme->protectedUplinks == 3);
    CHECK(session.mme->lastUplinkCount == 2);
    CHECK(session.mme->failures.empty());
    CHECK(session.elapsed < std::chrono::seconds(5));
}

// ---------------------------------------------------------------------------
// Shutdown while a Tracking Area Update is outstanding
// ---------------------------------------------------------------------------

TEST_CASE("lte/tau/wait: a stop request during a Tracking Area Update is an abandonment, not a timeout")
{
    // The stop lands only once production has actually sent the request, so
    // this covers the outstanding-procedure shutdown rather than an earlier
    // lifecycle stage. The procedure deadline is far away, so no retransmission
    // can race the stop.
    Session session;
    session.startAsync(UeConfig(47205, 47206, /*scenario=*/"tau-normal", /*triggerAfterMs=*/100,
                                /*procedureTimeoutMs=*/30000, /*maxRetries=*/3),
                       TauAction::NoAnswer, 47206);
    REQUIRE(session.waitFor("Protected normal Tracking Area Update Request sent"));
    const auto requested = Clock::now();
    session.shutdown = true;
    session.finish();
    const auto prompt = Clock::now() - requested;

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "TAU_NORMAL_PENDING abandoned at shutdown; no outcome was invented"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    // Neither outcome may be invented: no timeout, and no acceptance that the
    // network never sent.
    CHECK_FALSE(Contains(session.log, "timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Tracking Area Update accepted"));
    CHECK_FALSE(Contains(session.log, "Retransmitted TAU_NORMAL_PENDING"));
    // The stop was honoured promptly instead of being reported as a failed
    // procedure at the deadline.
    CHECK(prompt < std::chrono::seconds(2));
    CHECK(session.elapsed < std::chrono::seconds(5));
    // One request left the UE and the network never answered it.
    REQUIRE(session.mme->tauRequests.size() == 1);
    CHECK(session.mme->tauCompletes == 0);
    CHECK(session.mme->failures.empty());
    CHECK(Contains(session.log, "NAS security counts: UL-next=3 DL-last=1"));
}

TEST_CASE("lte/tau/wait: a stop request and a Tracking Area Update deadline are never reported together")
{
    // The deadline is the configured minimum and the stop request is raised
    // after it, so both conditions can hold on the same evaluation. Which one
    // the loop observes first is not ordered from outside; what must hold is
    // that the two outcomes are never conflated. The runtime guard makes the
    // evaluation itself total: when both hold, the stop wins.
    Session session;
    session.startAsync(UeConfig(47207, 47208, /*scenario=*/"tau-normal", /*triggerAfterMs=*/100,
                                /*procedureTimeoutMs=*/100, /*maxRetries=*/0),
                       TauAction::NoAnswer, 47208);
    REQUIRE(session.waitFor("Protected normal Tracking Area Update Request sent"));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    session.shutdown = true;
    session.finish();

    const bool timedOut = Contains(session.log, "TAU_NORMAL_PENDING timed out after bounded retransmissions");
    const bool abandoned = Contains(session.log, "TAU_NORMAL_PENDING abandoned at shutdown");
    CHECK(timedOut != abandoned);
    CHECK(session.exitCode == (timedOut ? 1 : 0));
    if (abandoned)
        CHECK(session.exitCode == 0);
    CHECK_FALSE(Contains(session.log, "Tracking Area Update accepted"));
    CHECK(session.mme->tauRequests.size() == 1);
    CHECK(session.mme->failures.empty());
}

// ---------------------------------------------------------------------------
// A completed update leaves nothing for the shutdown tail
// ---------------------------------------------------------------------------

TEST_CASE("lte/tau/wait: an accepted Tracking Area Update leaves nothing to abandon at shutdown")
{
    // The network accepts the update and assigns a new GUTI, so the UE owes it
    // a protected TAU Complete. Once that is sent the procedure is terminated,
    // and a later stop request must not be reported as an abandonment of a
    // procedure that no longer exists.
    Session session;
    session.startAsync(UeConfig(47209, 47210, /*scenario=*/"tau-normal", /*triggerAfterMs=*/100,
                                /*procedureTimeoutMs=*/30000, /*maxRetries=*/3),
                       TauAction::AcceptWithNewGuti, 47210);
    REQUIRE(session.waitFor("Tracking Area Update accepted"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "Tracking Area Update accepted; context preserved; TAU Complete sent for new GUTI"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    CHECK_FALSE(Contains(session.log, "abandoned at shutdown"));
    CHECK_FALSE(Contains(session.log, "timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Retransmitted TAU_NORMAL_PENDING"));
    // One request in, one protected TAU Complete back, and the complete is a
    // fresh uplink rather than a repeat of the request.
    REQUIRE(session.mme->tauRequests.size() == 1);
    CHECK(session.mme->tauCompletes == 1);
    CHECK(session.mme->protectedUplinks == 4);
    CHECK(session.mme->lastUplinkCount == 3);
    CHECK(session.mme->failures.empty());
    CHECK(Contains(session.log, "NAS security counts: UL-next=4 DL-last=2"));
}
