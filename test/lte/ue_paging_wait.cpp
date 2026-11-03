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
                     int procedureTimeoutMs = 5000, int maxRetries = 3, int idleRounds = 1)
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
  idleRounds: )"
       << idleRounds << R"(
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
    PageMatchingRestore,
    // One matching page per round, restoring every one and then releasing the
    // access again so the next round starts from ECM-IDLE. `cycles` rounds in
    // total. Each round advances the access generation the way a real eNB
    // does: the release that ends an epoch carries the next number, and the
    // restoration that answers a page restates the epoch it belongs to.
    PageRepeated,
    // The same repeated rounds, except that the access between them ends in an
    // unexpected loss of the eNB's S1-MME association rather than in a UE
    // Context Release. The session, the security context and the paging
    // behaviour must be identical either way.
    PageRepeatedAfterLoss
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
        start(config, action, 1, 1);
    }

    // `cycles` is how many page/restore/release rounds the scripted network
    // drives. One is the single-paging behaviour every older test uses.
    // `restoreCycles` says how many of those rounds the network actually
    // answers with a bearer restoration. The last rounds can be left
    // unanswered instead, which is the only way a later-epoch Service Request
    // retransmission is observable at all.
    void start(const Config &config, IdleAction action, int cycles, int restoreCycles)
    {
        m_config = config;
        m_action = action;
        m_cycles = cycles;
        m_restoreCycles = restoreCycles;
        m_generation = 0;
        m_completedCycles = 0;
        m_round = 0;
        m_answeredRound = 0;
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
    // The access generation each S1 release presented to the UE, and the one
    // each restoration restated. A repeated-access test proves the pairing is
    // exact: release n hands the UE generation n and restoration n answers
    // with generation n, so no cycle reuses a previous epoch's number.
    std::vector<uint32_t> releaseGenerations;
    std::vector<uint32_t> restoreGenerations;
    // How many access rounds the network actually completed. A round the
    // network left unanswered is not a completed one, and the retransmissions
    // of its Service Request are not further rounds.
    int completedCycles{};

    // The access epoch the network currently presents. It advances exactly
    // when an access that carried bearer transport ends, which is the one
    // transition the UE is told about.
    uint32_t generation() const
    {
        return m_generation;
    }

    // Lets a test deliver a further page after the scripted one, through the
    // same radio endpoint the network already used, so a duplicate page is
    // indistinguishable from a real one on the wire.
    void sendPageNow(const link::PagingNotification &notification)
    {
        pagingSent = true;
        send(link::MessageType::PAGING_INDICATION, link::EncodePagingNotification(notification), m_uePeer);
    }

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
                m_uePeer = peer;
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
        case link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT:
            // The same answer to a page, carrying the bearer inventory beside
            // the compact Service Request. A cell reached in the first access
            // epoch holds no bearer context of this session and cannot tell the
            // default bearer from the dedicated ones, so the UE names them and
            // the network is still answered with an ordinary four-octet EPS
            // Service Request. It is one procedure either way, so it is counted
            // and replayed here exactly as the compact form is.
            frames.push_back("SERVICE_REQUEST_DECLARED");
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

    // Ends the current access epoch and returns the number the UE is told
    // about. A real eNB advances the epoch exactly when an access that carried
    // bearer transport ends, and the notification names the new number, so
    // every generation-bound confirmation of the next epoch is compared
    // against one this UE has never seen.
    uint32_t endAccessEpoch()
    {
        if (++m_generation == 0)
            ++m_generation;
        releaseGenerations.push_back(m_generation);
        return m_generation;
    }

    bool onReleaseRequest(const InetAddress &peer)
    {
        releaseSeen = true;
        send(link::MessageType::S1_CONTEXT_RELEASED,
             link::EncodeBearerRestoration(kDefaultEbi, endAccessEpoch()), peer);
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
            send(link::MessageType::S1_CONTEXT_RESTORED, link::EncodeBearerRestoration(kDefaultEbi, m_generation),
                 peer);
            restoreGenerations.push_back(m_generation);
            restoreSent = true;
            ++m_completedCycles;
            completedCycles = m_completedCycles;
        }
        else if (m_action == IdleAction::PageRepeated || m_action == IdleAction::PageRepeatedAfterLoss)
        {
            // A retransmission repeats the frozen Service Request of the round
            // that is still outstanding. It is not a new page and not a new
            // access epoch, so the network neither answers it again nor counts
            // it as a completed round.
            if (m_answeredRound == m_round)
                return true;
            m_answeredRound = m_round;
            // Only the rounds the network chose to answer carry a restoration.
            // The rest are left outstanding so the UE's bounded retransmission
            // runs against a Service Request of a later access epoch.
            const bool restored = m_round <= m_restoreCycles;
            if (restored)
            {
                send(link::MessageType::S1_CONTEXT_RESTORED, link::EncodeBearerRestoration(kDefaultEbi, m_generation),
                     peer);
                restoreGenerations.push_back(m_generation);
                restoreSent = true;
                ++m_completedCycles;
                completedCycles = m_completedCycles;
                // A round is only ever followed by another one once this round
                // actually completed an access, because the next page has to
                // start from ECM-IDLE.
                if (m_completedCycles < m_cycles)
                    return releaseAndPageAgain(peer);
            }
        }
        return true;
    }

    // After a restoration has completed, the network drops the access again,
    // exactly as it would on user inactivity, and pages for the next round.
    // The UE is never asked to re-Attach and never told to reselect.
    bool releaseAndPageAgain(const InetAddress &peer)
    {
        // Let the UE finish recording the restoration before the release lands.
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        const uint32_t generation = endAccessEpoch();
        if (m_action == IdleAction::PageRepeatedAfterLoss)
            // This access does not end in a UE Context Release at all: the
            // eNB's S1-MME association is lost and the access transport dies
            // with it. It carries the same generation-bound identity because
            // the same access epoch is ending either way.
            send(link::MessageType::S1_ACCESS_LOST, link::EncodeBearerRestoration(kDefaultEbi, generation), peer);
        else
            send(link::MessageType::S1_CONTEXT_RELEASED, link::EncodeBearerRestoration(kDefaultEbi, generation), peer);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        sendPage(peer, kMmeCode, kMTmsi);
        return true;
    }

    void sendPage(const InetAddress &peer, uint8_t mmeCode, uint32_t mTmsi)
    {
        pagingSent = true;
        // Every page opens one access round: one page, one Service Request
        // answer and at most one restoration, however often that answer is
        // retransmitted before the network replies.
        ++m_round;
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
    int m_cycles{1};
    int m_restoreCycles{1};
    uint32_t m_generation{0};
    int m_completedCycles{0};
    int m_round{0};
    int m_answeredRound{0};
    InetAddress m_uePeer;
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
        run(yaml, action, mmePort, 1, 1);
    }

    void run(const std::string &yaml, IdleAction action, uint16_t mmePort, int cycles)
    {
        run(yaml, action, mmePort, cycles, cycles);
    }

    void run(const std::string &yaml, IdleAction action, uint16_t mmePort, int cycles, int restoreCycles)
    {
        const auto config = ParseConfig(yaml);
        capture = std::make_unique<lte::test::LogCapture>();
        mme = std::make_unique<FakeMme>("127.0.0.1", mmePort);
        mme->start(config, action, cycles, restoreCycles);

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
        startAsync(yaml, action, mmePort, 1, 1);
    }

    void startAsync(const std::string &yaml, IdleAction action, uint16_t mmePort, int cycles)
    {
        startAsync(yaml, action, mmePort, cycles, cycles);
    }

    void startAsync(const std::string &yaml, IdleAction action, uint16_t mmePort, int cycles, int restoreCycles)
    {
        const auto config = ParseConfig(yaml);
        capture = std::make_unique<lte::test::LogCapture>();
        mme = std::make_unique<FakeMme>("127.0.0.1", mmePort);
        mme->start(config, action, cycles, restoreCycles);
        m_config = config;
        m_started = Clock::now();
        m_ue = std::thread([this] { exitCode = lte::ue::Run(m_config, shutdown); });
    }

    bool waitFor(const std::string &needle, int timeoutMs = 8000)
    {
        return capture->waitFor(needle, timeoutMs);
    }

    // Waits for the `count`-th appearance of `needle`. A repeated-access test
    // has to hold the UE alive until its last access epoch has completed, and
    // waiting for the first of several identical events would stop it early.
    bool waitForOccurrences(const std::string &needle, int count, int timeoutMs = 8000)
    {
        return capture->waitForOccurrences(needle, count, timeoutMs);
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

// How many radio frames the fake network saw under one name. The paging answer
// is the interesting one: it is a single frame per page, and its type says
// whether the UE also declared the bearer inventory it still holds.
int CountFrames(const std::vector<std::string> &frames, const std::string &name)
{
    int count = 0;
    for (const auto &frame : frames)
        if (frame == name)
            ++count;
    return count;
}

// How often a log line appears, so a repeated-access test can prove an event
// happened once per cycle and not once per retransmission or not at all.
int CountOccurrences(const std::string &log, const std::string &needle)
{
    int count = 0;
    for (size_t at = log.find(needle); at != std::string::npos; at = log.find(needle, at + needle.size()))
        ++count;
    return count;
}

// The three pieces a declaring paging answer is made of. The identity prefix
// and the NAS tail are together exactly the body a compact SERVICE_REQUEST
// frame carries; the bearer inventory sits between them and is the only part
// the declaration adds.
struct PagingAnswer
{
    std::vector<uint8_t> identity;
    link::BearerInventory inventory;
    std::vector<uint8_t> nas;
};

// Reads one NAS_UPLINK_MOBILITY_CONTEXT body the way the network side does, so
// a test can tell "the declaration is additive" from "the Service Request was
// replaced by something longer".
PagingAnswer DecodePagingAnswer(const std::vector<uint8_t> &payload)
{
    REQUIRE(payload.size() > 5);
    link::BearerInventory inventory{};
    const size_t consumed = link::DecodeBearerInventory(payload.data() + 5, payload.size() - 5, inventory);
    PagingAnswer answer;
    answer.identity.assign(payload.begin(), payload.begin() + 5);
    answer.inventory = std::move(inventory);
    answer.nas.assign(payload.begin() + 5 + consumed, payload.end());
    return answer;
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
    // This fixture runs without a local user plane, so the UE never sent the
    // BEARER_READY that would confirm this cell's bearer roles. The answer is
    // therefore the declaring form, and the log names the form it actually
    // sent instead of always claiming the compact one.
    CHECK(Contains(session.log, "Paging identity matched (MMEC=1); bearer-inventory Service Request sent for the "
                                "network-triggered restoration (bootstrap=DECLARE_REQUIRED)"));
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

// ---------------------------------------------------------------------------
// The form of the answer to a page
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: an answer at a cell that never confirmed this session's bearer roles declares the "
          "inventory")
{
    // The declaring form is chosen from what the endpoint being answered has
    // been confirmed to hold, not from the access generation. This fixture
    // attaches without a local user plane, so the UE never sent the
    // BEARER_READY that would confirm this cell's bearer roles, and the cell
    // has never told the UE it holds them. The MME's answer to the Service
    // Request is one Initial Context Setup Request naming every bearer the
    // session still holds, and that list marks no roles. The UE must therefore
    // name them itself, beside an ordinary compact EPS Service Request.
    //
    // The generation here is the same one a retained cell would present, so
    // the fact that this answer declares proves the counter does not decide
    // the form on its own.
    Session session;
    session.startAsync(UeConfig(47121, 47122, /*pagingWaitMs=*/30000), IdleAction::PageMatchingRestore, 47122);
    REQUIRE(session.waitFor("Access restoration completed after a network paging indication"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(session.mme->failures.empty());
    // Exactly one answer to one page, and it is the declaring form. The compact
    // form must not also be sent: that would be a second answer to one page and
    // would leave the network with two Service Requests for one procedure.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 0);
    REQUIRE(session.mme->serviceRequestPayloads.size() == 1);
    // The declaration is additive. Read the body the way the network does and
    // the identity prefix plus the NAS tail are exactly the nine octets a
    // compact SERVICE_REQUEST frame carries, so the MME answers the procedure
    // it already knows rather than a new one invented for this phase. Only the
    // inventory between the two halves is new, and the NAS it precedes is the
    // ordinary four-octet EPS Service Request, carried verbatim.
    const auto answer = DecodePagingAnswer(session.mme->serviceRequestPayloads[0]);
    CHECK(answer.identity == std::vector<uint8_t>{kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
    CHECK(answer.nas.size() == 4);
    CHECK(answer.identity.size() + answer.nas.size() == 9);
    // This scenario holds the default bearer and nothing on top of it, so the
    // declaration names that one identity and no dedicated one.
    CHECK(answer.inventory.defaultEbi == kDefaultEbi);
    CHECK(answer.inventory.dedicatedEbis.empty());
    CHECK(session.mme->serviceRequests == 1);
}

// ---------------------------------------------------------------------------
// Repeated ECM-IDLE access epochs of one EPS registration
// ---------------------------------------------------------------------------

TEST_CASE("lte/paging/wait: three consecutive paging restorations of one registration never re-Attach")
{
    // The decisive repeated-access result at the UE level: one real Attach,
    // then three independent network-paged restorations, with the network
    // dropping the access again after each one so the next page starts from
    // ECM-IDLE. No new Attach is permitted between the cycles, and none is
    // sent: the only unprotected uplinks remain the two of the original Attach
    // exchange.
    //
    // The UE is held alive until the third restoration has actually completed,
    // because a finished restoration leaves the UE in ECM-CONNECTED rather than
    // ending the run, and a stop request is the only honest way to end it.
    Session session;
    session.startAsync(UeConfig(47125, 47126, /*pagingWaitMs=*/30000), IdleAction::PageRepeated, 47126, /*cycles=*/3);
    REQUIRE(session.waitForOccurrences("Access restoration completed after a network paging indication", 3));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(session.mme->failures.empty());
    CHECK(session.mme->attachComplete);
    // Three pages, three answers, three restorations.
    CHECK(session.mme->serviceRequests == 3);
    CHECK(session.mme->restoreGenerations == std::vector<uint32_t>{1, 2, 3});
    // Each access epoch is numbered once and the restoration of that epoch
    // restates the same number. The UE never sees a cycle reuse a previous
    // epoch's identifier, and the network never advances the number without an
    // access ending.
    CHECK(session.mme->releaseGenerations == std::vector<uint32_t>{1, 2, 3});
    CHECK(session.mme->completedCycles == 3);
    // No second Attach: the only unprotected uplinks are the Authentication
    // Response and the Attach Complete of the one registration.
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(CountOccurrences(session.log, "State=ATTACH_REQUEST_SENT") == 1);
    CHECK(CountOccurrences(session.log, "State=EPS_REGISTERED") == 1);
    CHECK(CountOccurrences(session.log, "Access restoration completed after a network paging indication") == 3);
    // Exactly one answer per page, never two.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") +
              CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") ==
          3);
    CHECK(CountOccurrences(session.log, "Paging statistics: indications=3 matched=3 ignored=0") == 1);
    // Every answer is an ordinary EPS Service Request under the one security
    // context. The NAS COUNT advances once per answer and never twice for one
    // procedure: three answers on top of the two Attach messages leave the next
    // count at five.
    REQUIRE(session.mme->serviceRequestPayloads.size() == 3);
    for (const auto &payload : session.mme->serviceRequestPayloads)
    {
        REQUIRE(payload.size() >= 9);
        // The five-octet S-TMSI prefix is the same in both answer forms.
        CHECK(std::vector<uint8_t>(payload.begin(), payload.begin() + 5) ==
              std::vector<uint8_t>{kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
    }
    CHECK(Contains(session.log, "NAS security counts: UL-next=5"));

    // The form of those three answers is decided from what the cell being
    // answered has been confirmed to hold, never from the access generation.
    // This fixture never sent the BEARER_READY that would confirm the cell's
    // bearer roles, so the first answer declares them; the restoration that
    // follows is a confirmed bearer access at that same cell and is itself the
    // confirmation, so the second and third answers are compact. Their
    // generations are 2 and 3 while the first is 1, and the form still follows
    // the confirmed roles alone — a cell that has never confirmed them is
    // answered with the declaration at any generation.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 2);
    // The declared answer is still an ordinary Service Request with an
    // additive inventory, so the network answers one procedure either way.
    const auto first = DecodePagingAnswer(session.mme->serviceRequestPayloads[0]);
    CHECK(first.inventory.defaultEbi == kDefaultEbi);
    CHECK(first.identity.size() + first.nas.size() == 9);
    // The compact answers carry no inventory at all: their whole body is the
    // identity prefix and the four-octet NAS.
    CHECK(session.mme->serviceRequestPayloads[1].size() == 9);
    CHECK(session.mme->serviceRequestPayloads[2].size() == 9);
    CHECK(Contains(session.log, "bootstrap=DECLARE_REQUIRED"));
    CHECK(Contains(session.log, "bootstrap=ROLES_RETAINED"));
}

TEST_CASE("lte/paging/wait: a configured run of repeated idle periods drives each restoration itself")
{
    // The scenario driver, not the network, is what opens the second and third
    // access epochs in a live run: it releases S1 again once the previous
    // restoration has genuinely completed. This pins that the driver really
    // repeats — three release requests from one registration, three pages, three
    // restorations — instead of firing its controlled idle trigger once and
    // leaving the later epochs to whoever happens to send a frame.
    Session session;
    session.startAsync(UeConfig(47137, 47138, /*pagingWaitMs=*/30000, /*triggerAfterMs=*/100,
                                /*procedureTimeoutMs=*/5000, /*maxRetries=*/3, /*idleRounds=*/3),
                       IdleAction::PageMatchingRestore, 47138);
    REQUIRE(session.waitForOccurrences("Access restoration completed after a network paging indication", 3));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(session.mme->failures.empty());
    CHECK(session.mme->attachComplete);
    // One registration, three epochs it asked for, three the network restored.
    CHECK(CountOccurrences(session.log, "State=ATTACH_REQUEST_SENT") == 1);
    CHECK(CountOccurrences(session.log, "State=EPS_REGISTERED") == 1);
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(CountFrames(session.mme->frames, "S1_CONTEXT_RELEASE_REQUEST") == 3);
    CHECK(session.mme->releaseGenerations == std::vector<uint32_t>{1, 2, 3});
    CHECK(session.mme->serviceRequests == 3);
    CHECK(session.mme->restoreGenerations == std::vector<uint32_t>{1, 2, 3});
    CHECK(session.mme->completedCycles == 3);
    // The first two rounds announce the next one; the last one is the end of
    // the configured run and schedules nothing further.
    CHECK(CountOccurrences(session.log, "Controlled idle period 1 of 3 completed; the next one is scheduled") == 1);
    CHECK(CountOccurrences(session.log, "Controlled idle period 2 of 3 completed; the next one is scheduled") == 1);
    CHECK_FALSE(Contains(session.log, "Controlled idle period 3 of 3"));
    CHECK(CountOccurrences(session.log, "Access restoration completed after a network paging indication") == 3);
    CHECK(CountOccurrences(session.log, "Paging statistics: indications=3 matched=3 ignored=0") == 1);
    // Every epoch is answered once, and the form still follows the confirmed
    // bearer roles: this fixture confirms them through the first restoration,
    // so only that first answer needs the declaration.
    REQUIRE(session.mme->serviceRequestPayloads.size() == 3);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 2);
    CHECK(session.mme->serviceRequestPayloads[1].size() == 9);
    CHECK(session.mme->serviceRequestPayloads[2].size() == 9);
}

TEST_CASE("lte/paging/wait: a retransmitted answer of a later epoch repeats the compact form and no new COUNT")
{
    // A retry of a compact answer is still the compact form. Dropping to a
    // different frame type on the retry would change the message the network
    // sees mid-procedure, and rebuilding it would consume a second uplink NAS
    // COUNT for one Service Request.
    //
    // The compact form is only ever chosen at an epoch whose cell has already
    // confirmed the bearer roles, so the first round here is answered and
    // restored — that restoration is the confirmation — and the second round is
    // the one left outstanding. Everything the retry is decided from therefore
    // belongs to a later access epoch, and nothing about it may fall back to
    // the declaration.
    Session session;
    session.run(UeConfig(47129, 47130, /*pagingWaitMs=*/30000, /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/250, /*maxRetries=*/2),
                IdleAction::PageRepeated, 47130, /*cycles=*/2, /*restoreCycles=*/1);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Paging-triggered service restoration failed after bounded retransmissions"));
    CHECK(session.mme->failures.empty());
    // Only the first round completed an access; the second was left
    // outstanding and is the one whose answer was retransmitted. Neither the
    // round nor the epoch is reopened by a retry: the network completed one
    // restoration at generation 1 and released once more for generation 2.
    CHECK(session.mme->completedCycles == 1);
    CHECK(session.mme->restoreGenerations == std::vector<uint32_t>{1});
    CHECK(session.mme->releaseGenerations == std::vector<uint32_t>{1, 2});
    REQUIRE(session.mme->serviceRequestPayloads.size() == 4);
    // The first round declares and the second answers compact, with its two
    // retransmissions repeating exactly that frame.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 3);
    CHECK(session.mme->serviceRequestPayloads[1] == session.mme->serviceRequestPayloads[2]);
    CHECK(session.mme->serviceRequestPayloads[1] == session.mme->serviceRequestPayloads[3]);
    CHECK(session.mme->serviceRequestPayloads[1].size() == 9);
    // A Service Request is its own radio frame rather than a protected NAS
    // uplink, so the two Attach messages are the only uplinks the network side
    // ever unprotected. The retransmissions consumed no second uplink NAS COUNT
    // either: the whole Service Request body is frozen at its first
    // transmission and the retry repeats it byte for byte, so the NAS sequence
    // number inside it cannot have advanced.
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(session.mme->lastUplinkCount == 1);
    CHECK(CountOccurrences(session.log, "Retransmitted SERVICE_REQUEST_PENDING") == 2);
}

TEST_CASE("lte/paging/wait: a duplicate page during a pending restoration starts no second procedure")
{
    // The network may page more than once while one Service Request is still
    // outstanding. The second page must not start a second procedure, must not
    // consume a second NAS COUNT and must not replace the frame the first
    // answer already sent.
    //
    // It is refused as a page for a UE that already has an access procedure
    // running, which is the earlier and stricter of the two duplicate guards:
    // a page is only ever evaluated for a UE in ECM-IDLE with no pending
    // procedure, so the second one never reaches the trigger arbitration at
    // all. The alternative reason for refusing a page — another restoration
    // trigger already owning the access — is reserved for a page racing an
    // armed access-recovery timer.
    Session session;
    session.startAsync(UeConfig(47131, 47132, /*pagingWaitMs=*/30000), IdleAction::PageMatchingNoRestore, 47132);
    // Wait until the first answer has left the UE, then page again from the
    // test thread through the same radio endpoint the network uses.
    REQUIRE(session.waitFor("Paging identity matched (MMEC=1)"));
    link::PagingNotification page;
    page.mmeCode = kMmeCode;
    page.mTmsi = kMTmsi;
    page.tac = kServedTac;
    session.mme->sendPageNow(page);
    // Give the duplicate a moment to arrive before shutting down.
    REQUIRE(session.waitFor("Paging indication ignored: PROCEDURE_PENDING"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(session.mme->failures.empty());
    CHECK(Contains(session.log, "Paging indication ignored: PROCEDURE_PENDING"));
    CHECK_FALSE(Contains(session.log, "another trigger already owns the pending restoration"));
    // One answer on the wire for one accepted page; the duplicate produced
    // neither a second frame nor a second NAS COUNT.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 0);
    CHECK(session.mme->serviceRequests == 1);
    CHECK(session.mme->protectedUplinks == 2);
    // Both pages are counted, and only one of them was matched and answered.
    CHECK(Contains(session.log, "Paging statistics: indications=2 matched=1 ignored=1 duplicate-trigger-suppressed=0 "
                                "service-requests=1 restorations=0 restoration-failures=0"));
}

TEST_CASE("lte/paging/wait: a retransmitted answer repeats the frozen declaration instead of falling back to the compact form")
{
    // The network answers the page with silence, so the answer is retransmitted
    // up to the configured bound. A retransmission of a procedure that is still
    // opening an S1 connection must repeat the very frame the first
    // transmission sent. It is decided from how the original left, not from
    // whether an identifier has been assigned yet: the UE has never been told
    // that identifier, and a guess would change the message a reselected cell
    // receives. Falling back to the compact form on the retry would drop the
    // declaration from exactly the transmission that may be the one the cell
    // finally sees.
    Session session;
    session.run(UeConfig(47123, 47124, /*pagingWaitMs=*/30000, /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/100, /*maxRetries=*/1),
                IdleAction::PageMatchingNoRestore, 47124);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Paging-triggered service restoration failed after bounded retransmissions"));
    CHECK(session.mme->failures.empty());
    // The first transmission and the retry are the same declared frame, and the
    // compact form is never substituted for it.
    REQUIRE(session.mme->serviceRequestPayloads.size() == 2);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 2);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 0);
    CHECK(session.mme->serviceRequestPayloads[0] == session.mme->serviceRequestPayloads[1]);
    // Every transmission carries the whole declaration, and the NAS inside it
    // is still the unchanged compact four-octet EPS Service Request.
    for (const auto &payload : session.mme->serviceRequestPayloads)
    {
        const auto answer = DecodePagingAnswer(payload);
        CHECK(answer.identity == std::vector<uint8_t>{kMmeCode, 0xC0, 0x00, 0x01, 0x8E});
        CHECK(answer.nas.size() == 4);
        CHECK(answer.identity.size() + answer.nas.size() == 9);
        CHECK(answer.inventory.defaultEbi == kDefaultEbi);
        CHECK(answer.inventory.dedicatedEbis.empty());
    }
    CHECK(session.mme->protectedUplinks == 2);
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

TEST_CASE("lte/paging/wait: a stop request during a later restoration is a shutdown, not a restoration failure")
{
    // The same rule one access epoch on: the first page was answered and its
    // access really completed, and the second is still outstanding when the UE
    // is asked to stop. A stop request wins over that procedure's deadline too,
    // so the run reports a shutdown rather than a failed second restoration,
    // and it does not pretend the outstanding one ever completed.
    Session session;
    session.startAsync(UeConfig(47133, 47134, /*pagingWaitMs=*/30000), IdleAction::PageRepeated, 47134,
                       /*cycles=*/2, /*restoreCycles=*/1);
    // Round two answers compact because round one's restoration confirmed the
    // cell's bearer roles, and this is the last thing the UE does before the
    // stop lands.
    REQUIRE(session.waitFor("compact EPS Service Request sent for the network-triggered restoration"));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "LTE UE shutdown complete"));
    CHECK(Contains(session.log, "SERVICE_REQUEST_PENDING abandoned at shutdown; no outcome was invented"));
    CHECK_FALSE(Contains(session.log, "Paging-triggered service restoration failed after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Timed out waiting for a network paging indication"));
    // One restoration really happened and the second is not reported as one.
    CHECK(CountOccurrences(session.log, "Access restoration completed after a network paging indication") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 1);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 1);
    CHECK(session.mme->completedCycles == 1);
    CHECK(session.mme->restoreGenerations == std::vector<uint32_t>{1});
    CHECK(session.mme->releaseGenerations == std::vector<uint32_t>{1, 2});
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(session.mme->failures.empty());
    CHECK(Contains(session.log, "Paging statistics: indications=2 matched=2 ignored=0 duplicate-trigger-suppressed=0 "
                                "service-requests=2 restorations=1 restoration-failures=0"));
}

TEST_CASE("lte/paging/wait: an unexpected S1 access loss inside a later cycle is not a new registration")
{
    // The access between two paging restorations does not always end in a UE
    // Context Release. When the serving eNB's S1-MME association is lost the
    // access transport dies with it and no release procedure ran at all. That
    // is an internal simulator indication rather than a NAS or S1AP message,
    // and it must leave exactly what a release leaves: one EPS registration in
    // ECM-IDLE that the next page can still restore, with no re-Attach and no
    // change to the security context or the bearer identities.
    Session session;
    session.startAsync(UeConfig(47135, 47136, /*pagingWaitMs=*/30000), IdleAction::PageRepeatedAfterLoss, 47136,
                       /*cycles=*/3);
    REQUIRE(session.waitForOccurrences("Access restoration completed after a network paging indication", 3));
    session.shutdown = true;
    session.finish();

    CHECK(session.exitCode == 0);
    CHECK(session.mme->failures.empty());
    // Every access epoch but the last ended in an unexpected loss, and every
    // one of them was still followed by a working page and restoration.
    CHECK(CountOccurrences(session.log, "S1 access transport lost unexpectedly") == 2);
    CHECK(session.mme->completedCycles == 3);
    CHECK(session.mme->serviceRequests == 3);
    CHECK(session.mme->restoreGenerations == std::vector<uint32_t>{1, 2, 3});
    CHECK(session.mme->releaseGenerations == std::vector<uint32_t>{1, 2, 3});
    // No second Attach through any of it: the only unprotected uplinks remain
    // the two of the original Attach exchange.
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(CountOccurrences(session.log, "State=ATTACH_REQUEST_SENT") == 1);
    CHECK(CountOccurrences(session.log, "State=EPS_REGISTERED") == 1);
    CHECK(CountOccurrences(session.log, "Access restoration completed after a network paging indication") == 3);
    CHECK(Contains(session.log, "Paging statistics: indications=3 matched=3 ignored=0"));
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
    // The network answers the page with silence, so the paging answer is
    // retransmitted up to the configured bound and then reported as an
    // unresolved restoration. The paging window is far longer than the retry
    // budget, so this outcome cannot be the paging-wait expiry.
    Session session;
    session.run(UeConfig(47117, 47118, /*pagingWaitMs=*/30000, /*triggerAfterMs=*/100,
                         /*procedureTimeoutMs=*/100, /*maxRetries=*/1),
                IdleAction::PageMatchingNoRestore, 47118);

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Paging identity matched (MMEC=1)"));
    CHECK(Contains(session.log, "bearer-inventory Service Request sent for the network-triggered restoration "
                                "(bootstrap=DECLARE_REQUIRED)"));
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

    // Exactly one initial request and one retransmission, both of the declaring
    // form this access epoch answers with; the retry repeats the same protected
    // PDU rather than consuming another uplink NAS COUNT.
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST_DECLARED") == 2);
    CHECK(CountFrames(session.mme->frames, "SERVICE_REQUEST") == 0);
    REQUIRE(session.mme->serviceRequestPayloads.size() == 2);
    CHECK(session.mme->serviceRequestPayloads[0] == session.mme->serviceRequestPayloads[1]);
    CHECK(session.mme->protectedUplinks == 2);
    CHECK(session.mme->lastUplinkCount == 1);
    CHECK_FALSE(session.mme->restoreSent);
    CHECK(session.mme->failures.empty());
    CHECK(session.elapsed < std::chrono::seconds(5));
}
