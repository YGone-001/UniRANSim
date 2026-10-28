//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Production-path tests for the UE paging-wait window.
//
// These drive the real lte::ue::Run() over a real UDP radio link against a
// minimal fake MME. A helper-only unit test cannot prove what the running
// process does at exit: the timeout and shutdown decisions live inside Run()
// and are only observable through its return code and its log, so that is what
// these tests assert. The new file exists because no other test owns the
// end-to-end Attach/release/paging exchange, and mixing this harness into an
// existing suite would make every test in it depend on a live socket pair.
//
// The fake MME speaks the same NAS and radio-link codecs as production and
// reuses the public 3GPP TS 35.208 test subscriber already present in
// test/lte/ue.cpp. It creates no subscriber, touches no HSS and never reaches
// a real EPC. The UE config asks for control-plane-only mode: TUN creation is
// not required, and the single requested route carries host bits so the
// kernel rejects it and nothing is installed. No network namespace is created.

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
std::string UeConfig(uint16_t uePort, uint16_t mmePort, int pagingWaitMs, int triggerAfterMs = 100,
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
  scenario: paging
  triggerAfterMs: )"
       << triggerAfterMs << R"(
  procedureTimeoutMs: )"
       << procedureTimeoutMs << R"(
  maxRetries: )"
       << maxRetries << R"(
  pagingWaitMs: )"
       << pagingWaitMs << R"(
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
constexpr uint16_t kServedTac = 1;

// ---------------------------------------------------------------------------
// Fake MME
// ---------------------------------------------------------------------------

// What the fake network does once the UE has entered ECM-IDLE under the
// controlled idle trigger.
enum class IdleAction
{
    // Never page. The paging wait must expire on its own.
    StaySilent,
    // One page carrying an S-TMSI that is not the UE's, then silence. The
    // window must remain armed and still expire.
    PageForeign,
    // One matching page and then nothing. The UE is left with a Service
    // Request in flight so a stop request can be tested against it.
    PageMatchingNoRestore,
    // One matching page, then complete the restoration.
    PageMatchingRestore
};

// Minimal peer for the simulated radio link. It completes a real EPS Attach
// and then scripts the idle/paging half of the lifecycle. It never logs: all
// std::cout output during a test belongs to the production UE.
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

    void start(const Config &config, IdleAction action)
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
    int serviceRequests{};
    // Every SERVICE_REQUEST frame body, so a test can prove a retransmission
    // repeats the same protected PDU instead of consuming a new NAS COUNT.
    std::vector<std::vector<uint8_t>> serviceRequestPayloads;
    int protectedUplinks{};
    uint32_t lastUplinkCount{};
    bool attachComplete{};
    bool releaseSeen{};
    bool pagingSent{};
    bool restoreSent{};

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
            return onNas(frame.payload, peer);
        case link::MessageType::BEARER_READY:
            frames.push_back("BEARER_READY");
            return true;
        case link::MessageType::BEARER_TRANSPORT_READY:
            frames.push_back("BEARER_TRANSPORT_READY");
            return true;
        case link::MessageType::S1_CONTEXT_RELEASE_REQUEST:
            frames.push_back("S1_CONTEXT_RELEASE_REQUEST");
            return onReleaseRequest(peer);
        case link::MessageType::SERVICE_REQUEST:
            frames.push_back("SERVICE_REQUEST");
            serviceRequestPayloads.push_back(frame.payload);
            return onServiceRequest(peer);
        default:
            frames.push_back("OTHER");
            fail("radio frame type is not part of the scripted Attach/paging exchange");
            return false;
        }
    }

    bool onNas(const std::vector<uint8_t> &payload, const InetAddress &peer)
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
            fail("replayed uplink NAS COUNT");
            return false;
        }
        auto plain = nas::UnprotectBody(m_security, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                        parsed.plain);
        m_security.ulNasCount = count;
        lastUplinkCount = count;
        ++protectedUplinks;

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
        return true;
    }

    bool onReleaseRequest(const InetAddress &peer)
    {
        releaseSeen = true;
        send(link::MessageType::S1_CONTEXT_RELEASED,
             link::EncodeBearerRestoration(kDefaultEbi, 1), peer);
        if (m_action == IdleAction::StaySilent || m_action == IdleAction::PageForeign)
        {
            if (m_action == IdleAction::PageForeign)
                sendPage(peer, kMmeCode + 9, 0xDEADBEEFu);
            return true;
        }
        // Give the UE a turn to record ECM-IDLE and arm its wait before the
        // page arrives, so the match is evaluated against a real idle context.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        sendPage(peer, kMmeCode, kMTmsi);
        return true;
    }

    bool onServiceRequest(const InetAddress &peer)
    {
        ++serviceRequests;
        if (m_action == IdleAction::PageMatchingRestore)
        {
            send(link::MessageType::S1_CONTEXT_RESTORED, link::EncodeBearerRestoration(kDefaultEbi, 1), peer);
            restoreSent = true;
        }
        return true;
    }

    void sendPage(const InetAddress &peer, uint8_t mmeCode, uint32_t mTmsi)
    {
        pagingSent = true;
        link::PagingNotification page;
        page.mmeCode = mmeCode;
        page.mTmsi = mTmsi;
        page.tac = kServedTac;
        send(link::MessageType::PAGING_INDICATION, link::EncodePagingNotification(page), peer);
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
    // the paging tests match against. Both are built from the same PLMN
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

    Config m_config;
    IdleAction m_action{IdleAction::StaySilent};
    udp::UdpServer m_socket;
    SecurityContext m_security{};
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

    void run(const std::string &yaml, IdleAction action, uint16_t mmePort)
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
    // against a known paging-wait state.
    void startAsync(const std::string &yaml, IdleAction action, uint16_t mmePort)
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
// Paging-wait expiry
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: an unanswered paging window expires without inventing a Service Request")
{
    Session session;
    session.run(UeConfig(47101, 47102, /*pagingWaitMs=*/400), IdleAction::StaySilent, 47102);

    // The failure outcome is explicit and nonzero, as the production runtime
    // requires of an unresolved procedure.
    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Timed out waiting for a network paging indication; no Service Request was sent"));
    // The diagnostic must not claim network Paging success, and no bearer may
    // be reported active or restored.
    CHECK_FALSE(Contains(session.log, "Paging identity matched"));
    CHECK_FALSE(Contains(session.log, "Access restoration completed"));
    CHECK_FALSE(Contains(session.log, "State=ECM_CONNECTED"));
    // A stop request did not run, so the shutdown paths must stay silent.
    CHECK_FALSE(Contains(session.log, "Paging wait abandoned at shutdown"));
    CHECK_FALSE(Contains(session.log, "LTE UE shutdown complete"));
    // No compact Service Request left the UE: the network saw neither the
    // SERVICE_REQUEST radio frame nor a further protected uplink, so the
    // phantom page consumed no uplink NAS COUNT either.
    CHECK(session.mme->serviceRequests == 0);
    CHECK(session.mme->protectedUplinks == 2); // Security Mode Complete + Attach Complete
    CHECK(session.mme->lastUplinkCount == 1);  // next uplink COUNT is still 2
    CHECK(session.mme->failures.empty());
    CHECK_FALSE(Contains(session.log, "Compact EPS Service Request sent"));
    // The wait is bounded; it must not approach the configured link timeout.
    CHECK(session.elapsed < std::chrono::seconds(5));
    // Cleanup: the run left through an explicit return, and no namespace, TUN
    // or route was created.
    CHECK(Contains(session.log, "Control-plane-only mode: LTE TUN unavailable"));
}

TEST_CASE("lte/paging/wait: a foreign S-TMSI page is ignored and the window still expires")
{
    Session session;
    session.run(UeConfig(47107, 47108, /*pagingWaitMs=*/400), IdleAction::PageForeign, 47108);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Paging indication ignored: IDENTITY_MISMATCH"));
    CHECK(Contains(session.log, "Timed out waiting for a network paging indication; no Service Request was sent"));
    CHECK_FALSE(Contains(session.log, "Paging identity matched"));
    CHECK_FALSE(Contains(session.log, "Access restoration completed"));
    CHECK(session.mme->pagingSent);
    CHECK(session.mme->serviceRequests == 0);
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(session.mme->failures.empty());
}

// ---------------------------------------------------------------------------
// Graceful shutdown during the paging wait
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: a stop request during the paging window is a shutdown, not a paging timeout")
{
    Session session;
    session.startAsync(UeConfig(47103, 47104, /*pagingWaitMs=*/30000), IdleAction::StaySilent, 47104);
    // Land the stop only once production has actually armed the wait, so this
    // covers the armed-window shutdown rather than an earlier lifecycle stage.
    REQUIRE(session.waitFor("Waiting for a network paging indication"));
    const auto requested = Clock::now();
    session.shutdown = true;
    session.finish();
    const auto prompt = Clock::now() - requested;

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "Paging wait abandoned at shutdown; no Service Request was sent"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    CHECK_FALSE(Contains(session.log, "Timed out waiting for a network paging indication"));
    CHECK_FALSE(Contains(session.log, "Paging identity matched"));
    CHECK_FALSE(Contains(session.log, "Access restoration completed"));
    // The wait expired nowhere near its deadline: the stop was honoured
    // promptly instead of being reported as a failed procedure.
    CHECK(prompt < std::chrono::seconds(2));
    CHECK(session.elapsed < std::chrono::seconds(5));
    // The clean-exit statistics are the honest ones: nothing paged, nothing
    // restored, and no uplink NAS COUNT was consumed by a page that never
    // arrived.
    CHECK(Contains(session.log, "Paging statistics: indications=0 matched=0 ignored=0 duplicate-trigger-suppressed=0 "
                                "service-requests=0 restorations=0 restoration-failures=0"));
    CHECK(Contains(session.log, "NAS security counts: UL-next=2 DL-last=1"));
    CHECK(Contains(session.log, "Access-recovery statistics: losses=0 restorations=0 failures=0 attempts=0"));
    CHECK(session.mme->serviceRequests == 0);
    CHECK(session.mme->failures.empty());
}

TEST_CASE("lte/paging/wait: a valid page disarms the window and a later stop is not a timeout")
{
    Session session;
    session.startAsync(UeConfig(47105, 47106, /*pagingWaitMs=*/30000), IdleAction::PageMatchingRestore, 47106);
    REQUIRE(session.waitFor("Access restoration completed after a network paging indication"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "Paging identity matched (MMEC=1); compact EPS Service Request sent for the "
                                "network-triggered restoration"));
    CHECK(Contains(session.log, "Access restoration completed after a network paging indication"));
    CHECK_FALSE(Contains(session.log, "Timed out waiting for a network paging indication"));
    // The wait was disarmed by the accepted page, so the shutdown tail must
    // not claim it was abandoned.
    CHECK_FALSE(Contains(session.log, "Paging wait abandoned at shutdown"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    CHECK(Contains(session.log, "Paging statistics: indications=1 matched=1 ignored=0 duplicate-trigger-suppressed=0 "
                                "service-requests=1 restorations=1 restoration-failures=0"));
    // One page produced exactly one Service Request and one uplink NAS COUNT.
    // The compact Service Request is its own radio frame, not a protected NAS
    // uplink, so only the two Attach messages were unprotected by the MME.
    CHECK(session.mme->serviceRequests == 1);
    CHECK(session.mme->restoreSent);
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(Contains(session.log, "NAS security counts: UL-next=3 DL-last=1"));
    CHECK(session.mme->failures.empty());
}

TEST_CASE("lte/paging/wait: shutdown while a paging Service Request is pending is still a shutdown")
{
    Session session;
    session.startAsync(UeConfig(47109, 47110, /*pagingWaitMs=*/30000), IdleAction::PageMatchingNoRestore, 47110);
    REQUIRE(session.waitFor("Paging identity matched"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "Paging identity matched"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    CHECK_FALSE(Contains(session.log, "Timed out waiting for a network paging indication"));
    CHECK_FALSE(Contains(session.log, "Access restoration completed"));
    CHECK(session.mme->serviceRequests == 1);
    CHECK_FALSE(session.mme->restoreSent);
    CHECK(session.mme->failures.empty());
}

// ---------------------------------------------------------------------------
// Trigger ownership and deadline precedence
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: a finished run leaves no paging-wait state for the next run")
{
    // The first run lets the window expire. If pagingWaitArmed or its deadline
    // survived Run(), the second run would time out immediately instead of
    // reaching a fresh Attach and a fresh wait.
    Session expired;
    expired.run(UeConfig(47111, 47112, /*pagingWaitMs=*/400), IdleAction::StaySilent, 47112);
    CHECK(expired.exitCode == 1);
    CHECK(Contains(expired.log, "Timed out waiting for a network paging indication"));

    Session fresh;
    fresh.startAsync(UeConfig(47113, 47114, /*pagingWaitMs=*/30000), IdleAction::StaySilent, 47114);
    REQUIRE(fresh.waitFor("Waiting for a network paging indication"));
    fresh.shutdown = true;
    fresh.finish();

    CHECK(fresh.exitCode == 0);
    CHECK(Contains(fresh.log, "Paging wait abandoned at shutdown; no Service Request was sent"));
    CHECK_FALSE(Contains(fresh.log, "Timed out waiting for a network paging indication"));
    CHECK(Contains(fresh.log, "EPS Attach complete"));
    CHECK(fresh.mme->attachComplete);
    CHECK(fresh.mme->failures.empty());
}

TEST_CASE("lte/paging/wait: a stop request and a paging-wait expiry are never reported together")
{
    // The deadline is the configured minimum, and the stop request is raised
    // after it, so both conditions can hold on the same evaluation. Which one
    // the loop observes first is not ordered from outside; what must hold is
    // that the two outcomes are never conflated. The runtime guard makes the
    // evaluation itself total: when both hold, the stop wins.
    Session session;
    session.startAsync(UeConfig(47115, 47116, /*pagingWaitMs=*/100), IdleAction::StaySilent, 47116);
    REQUIRE(session.waitFor("Waiting for a network paging indication"));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    session.shutdown = true;
    session.finish();

    const bool timedOut = Contains(session.log, "Timed out waiting for a network paging indication");
    const bool abandoned = Contains(session.log, "Paging wait abandoned at shutdown");
    CHECK(timedOut != abandoned);
    CHECK(session.exitCode == (timedOut ? 1 : 0));
    if (abandoned)
        CHECK(session.exitCode == 0);
    CHECK(session.mme->serviceRequests == 0);
    CHECK(session.mme->failures.empty());
}

// ---------------------------------------------------------------------------
// Bounded retransmission of a Paging-triggered Service Request
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: an unanswered paging Service Request fails after bounded retransmissions")
{
    // The network answers the page with silence, so the compact Service Request
    // is retransmitted up to the configured bound and then reported as an
    // unresolved restoration. The paging window is far longer than the retry
    // budget, so this outcome cannot be the paging-wait expiry.
    Session session;
    session.run(UeConfig(47117, 47118, /*pagingWaitMs=*/30000, /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/100, /*maxRetries=*/1),
                IdleAction::PageMatchingNoRestore, 47118);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Paging identity matched (MMEC=1)"));
    CHECK(Contains(session.log, "compact EPS Service Request sent for the network-triggered restoration"));
    CHECK(Contains(session.log, "Retransmitted SERVICE_REQUEST_PENDING, retry=1"));
    // The failure is attributed to the paging trigger and named as a bounded
    // retransmission outcome, never as a paging-wait timeout and never as a
    // successful restoration.
    CHECK(Contains(session.log, "Paging-triggered service restoration failed after bounded retransmissions"));
    CHECK(Contains(session.log, "SERVICE_REQUEST_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Timed out waiting for a network paging indication"));
    CHECK_FALSE(Contains(session.log, "Access restoration completed"));
    CHECK_FALSE(Contains(session.log, "Paging wait abandoned at shutdown"));
    CHECK_FALSE(Contains(session.log, "State=ECM_CONNECTED"));

    // Exactly one initial request and one retransmission; the retry repeats the
    // same protected PDU rather than consuming another uplink NAS COUNT.
    REQUIRE(session.mme->serviceRequestPayloads.size() == 2);
    CHECK(session.mme->serviceRequestPayloads[0] == session.mme->serviceRequestPayloads[1]);
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(session.mme->lastUplinkCount == 1);
    CHECK_FALSE(session.mme->restoreSent);
    CHECK(session.mme->failures.empty());
    CHECK(session.elapsed < std::chrono::seconds(5));
}
