//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Production-path tests for the bearer inventory a reselected cell is given.
//
// The claim this file makes is about the sender. After a real ECM-IDLE cell
// reselection the running UE itself has to open the new cell with a mobility
// uplink that declares the EPS bearer identities it still holds, and its
// retries have to repeat exactly that declaration. A target-side test that
// builds the declaration by hand cannot make either claim, because production
// was never asked to build one. Everything here therefore leaves through
// lte::ue::Run() and a real UDP socket and is observed on the far end.
//
// The source cell is a minimal fake MME that performs a real EPS AKA exchange
// and a real Attach over the public 3GPP TS 35.208 test subscriber already
// present in test/lte/ue.cpp. The reselected cell is a second, independent
// endpoint that never saw the source's context. Neither creates a subscriber,
// touches an HSS nor reaches a real EPC. The UE config asks for
// control-plane-only mode: the single requested route carries host bits, so the
// kernel rejects it and nothing is installed. No network namespace is created.

#include <ext/doctest/doctest.h>

#include "log_capture.hpp"

#include <lte/enb/codec.hpp>
#include <lte/ue/app.hpp>
#include <lte/ue/bearer_runtime.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>

#include <lib/udp/server.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
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
//
// The serving cell is at sourcePort inside tracking area 460/02/1. When a
// target cell is configured it is a different tracking area on its own radio
// endpoint, so a reselection out of the registered tracking area list is what
// the scenario exercises.
std::string UeConfig(uint16_t uePort, uint16_t sourcePort, const std::string &scenario,
                     std::optional<uint16_t> targetPort = std::nullopt, int triggerAfterMs = 1000,
                     int procedureTimeoutMs = 30000, int maxRetries = 2)
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
       << sourcePort << R"(
  tac: 1)";
    if (targetPort.has_value())
    {
        out << R"(
  targetCell:
    mcc: '460'
    mnc: '02'
    tac: 2
    address: 127.0.0.1
    port: )"
            << *targetPort;
    }
    out << R"(
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
// Fake network: one MME behind two independent radio endpoints
// ---------------------------------------------------------------------------

struct ObservedFrame
{
    link::MessageType type;
    std::vector<uint8_t> payload;
};

// What the network does with the Tracking Area Update it is handed.
enum class TauAction
{
    // Never answer, so the production retransmission path is observable.
    NoAnswer,
    // Accept the update and assign a new GUTI, so the UE owes the network a
    // protected TAU Complete before the procedure is terminated.
    AcceptWithNewGuti
};

// One EPS peer presented on two independent simulated radio endpoints: the
// serving cell the UE attaches to, and the reselected cell it must bootstrap at.
// Both speak the same NAS security context, which is what lets the target
// unprotect the mobility uplink and prove the protected NAS inside it is the
// genuine protected Tracking Area Update Request and nothing else.
class FakeNetwork
{
  public:
    FakeNetwork(const std::string &address, uint16_t sourcePort, uint16_t targetPort)
        : m_source(address, sourcePort), m_target(address, targetPort)
    {
    }
    ~FakeNetwork()
    {
        stop();
    }

    void start(const Config &config, TauAction action, std::vector<uint8_t> activate,
               std::vector<uint8_t> deactivate, uint8_t attachEbi)
    {
        m_config = config;
        m_action = action;
        m_activate = std::move(activate);
        m_deactivate = std::move(deactivate);
        m_attachEbi = attachEbi;
        m_thread = std::thread([this] { run(); });
    }

    void stop()
    {
        m_stop = true;
        if (m_thread.joinable())
            m_thread.join();
    }

    // Observations the tests assert on. They are written on the network thread
    // and read only after stop() has joined it.
    std::vector<std::string> failures;
    std::vector<ObservedFrame> sourceFrames;
    std::vector<ObservedFrame> targetFrames;
    // The bearer inventory every mobility uplink declared, decoded back out of
    // the frame the UE actually sent.
    std::vector<link::BearerInventory> declarations;
    // The protected NAS bytes every mobility uplink carried, kept verbatim so a
    // retransmission can be compared against the original byte for byte.
    std::vector<std::vector<uint8_t>> mobilityNas;
    // Every Tracking Area Update Request the network unpaired, paired with the
    // radio message type it arrived on.
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
                if (!pump(m_source))
                    return;
                if (!pump(m_target))
                    return;
            }
        }
        catch (const std::exception &e)
        {
            fail(e.what());
        }
    }

    // Every reply goes back out of the endpoint the uplink arrived on, so a
    // serving-cell message can never be mistaken for a target-cell one.
    bool pump(udp::UdpServer &socket)
    {
        uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
        InetAddress peer;
        const int received = socket.Receive(buffer, sizeof(buffer), 10, peer);
        if (received <= 0)
            return true;
        const auto frame = link::Decode(buffer, static_cast<size_t>(received));
        if (frame.ueId != m_config.ueId)
        {
            fail("radio frame carried an unexpected UE identity");
            return false;
        }
        m_reply = &socket;
        (m_reply == &m_source ? sourceFrames : targetFrames).push_back({frame.type, frame.payload});
        return handle(frame, peer);
    }

    static bool IsTauRequest(const std::vector<uint8_t> &plain)
    {
        return plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x48;
    }

    bool handle(const link::Message &frame, const InetAddress &peer)
    {
        switch (frame.type)
        {
        case link::MessageType::NAS_UPLINK:
            return onNas(frame.type, frame.payload, peer);
        case link::MessageType::NAS_UPLINK_MOBILITY:
            // The legacy identity-only form. It carries no declaration, so a
            // reselected cell cannot restore anything from it.
            fail("the production UE opened a reselected cell without a bearer inventory");
            return false;
        case link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT:
            return onMobilityContext(frame.payload, peer);
        case link::MessageType::S1_CONTEXT_RELEASE_REQUEST:
            // The controlled idle trigger answers with the S1 context release
            // that puts the UE into ECM-IDLE.
            send(link::MessageType::S1_CONTEXT_RELEASED, link::EncodeBearerRestoration(m_attachEbi, 1), peer);
            return true;
        case link::MessageType::BEARER_ACTIVATED:
            return true;
        default:
            fail("radio frame type is not part of the scripted Attach/reselection exchange");
            return false;
        }
    }

    // The reselected cell's half of the contract: split the declaration from the
    // protected NAS, believe neither until both parse, and unprotect the NAS
    // under the context the serving cell established.
    bool onMobilityContext(const std::vector<uint8_t> &payload, const InetAddress &peer)
    {
        if (payload.size() < 8)
        {
            fail("truncated bearer-inventory mobility uplink");
            return false;
        }
        if (payload[0] != kMmeCode)
        {
            fail("the mobility uplink carried a foreign MME code");
            return false;
        }
        const uint32_t mTmsi = (static_cast<uint32_t>(payload[1]) << 24U) |
                               (static_cast<uint32_t>(payload[2]) << 16U) |
                               (static_cast<uint32_t>(payload[3]) << 8U) | payload[4];
        if (mTmsi != kMTmsi)
        {
            fail("the mobility uplink carried a foreign M-TMSI");
            return false;
        }
        link::BearerInventory inventory{};
        size_t consumed = 0;
        try
        {
            consumed = link::DecodeBearerInventory(payload.data() + 5, payload.size() - 5, inventory);
        }
        catch (const std::exception &e)
        {
            fail(std::string("the mobility uplink declared an unencodable inventory: ") + e.what());
            return false;
        }
        if (consumed + 1 > payload.size() - 5)
        {
            fail("the mobility uplink carried no protected NAS");
            return false;
        }
        declarations.push_back(inventory);
        const std::vector<uint8_t> protectedNas(payload.begin() + 5 + consumed, payload.end());
        mobilityNas.push_back(protectedNas);
        return onNas(link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT, protectedNas, peer);
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
            advancePlan(peer);
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

    // The scripted bearer plan runs once the Attach is complete. Activation and
    // deactivation are separate protected downlink messages, so they reach the
    // UE as separate datagrams in this order and the bearer runtime has settled
    // on the final set long before the controlled idle trigger is due.
    void advancePlan(const InetAddress &peer)
    {
        for (const uint8_t ebi : m_activate)
            sendNas(peer, ProtectDownlink(ActivateDedicated(ebi), /*newContext=*/false));
        for (const uint8_t ebi : m_deactivate)
            sendNas(peer, ProtectDownlink(DeactivateDedicated(ebi), /*newContext=*/false));
    }

    void sendNas(const InetAddress &peer, std::vector<uint8_t> nas)
    {
        send(link::MessageType::NAS_DOWNLINK, std::move(nas), peer);
    }

    void send(link::MessageType type, std::vector<uint8_t> payload, const InetAddress &peer)
    {
        const auto frame = link::Encode({type, m_config.ueId, std::move(payload)});
        m_reply->Send(peer, frame.data(), frame.size());
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

        // Activate Default EPS Bearer Context Request: the assigned default
        // EBI, PTI 1, QCI 5, APN "internet", PDN address 10.0.0.1.
        const std::vector<uint8_t> esm{static_cast<uint8_t>((m_attachEbi << 4U) | 0x02U), 0x01, 0xC1,
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

    // A network-authored Activate Dedicated EPS Bearer Context Request: EBI,
    // PTI, linked default EBI, a one-octet EPS QoS and an empty TFT. The UE
    // accepts it into its own bearer runtime and from then on owns the identity.
    std::vector<uint8_t> ActivateDedicated(uint8_t ebi) const
    {
        return {static_cast<uint8_t>((ebi << 4U) | 0x02U), 0x01, 0xC5, m_attachEbi, 0x01, 0x09, 0x00};
    }

    // A network-authored Deactivate EPS Bearer Context Request with an explicit
    // ESM cause.
    static std::vector<uint8_t> DeactivateDedicated(uint8_t ebi)
    {
        return {static_cast<uint8_t>((ebi << 4U) | 0x02U), 0x01, 0xCD, 0x01, 0x24};
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
    std::vector<uint8_t> m_activate;
    std::vector<uint8_t> m_deactivate;
    uint8_t m_attachEbi{kDefaultEbi};
    udp::UdpServer m_source;
    udp::UdpServer m_target;
    udp::UdpServer *m_reply{};
    SecurityContext m_security{};
    std::vector<uint8_t> m_lastProtectedUplink;
    std::vector<uint8_t> m_lastUplinkPlain;
    std::thread m_thread;
    std::atomic_bool m_stop{false};
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Plan
{
    std::vector<uint8_t> activate;
    std::vector<uint8_t> deactivate;
    // The EPS bearer identity the Attach Accept assigns. It is a fixture knob
    // only, so a test can make the network author an identity the encoding must
    // refuse to declare.
    uint8_t attachEbi{kDefaultEbi};
};

struct Session
{
    std::unique_ptr<lte::test::LogCapture> capture;
    std::unique_ptr<FakeNetwork> network;
    std::atomic_bool shutdown{false};
    int exitCode{-1};
    std::string log;
    Clock::duration elapsed{};

    void start(const std::string &yaml, const Plan &plan, TauAction action, uint16_t sourcePort, uint16_t targetPort)
    {
        const auto config = ParseConfig(yaml);
        capture = std::make_unique<lte::test::LogCapture>();
        network = std::make_unique<FakeNetwork>("127.0.0.1", sourcePort, targetPort);
        network->start(config, action, plan.activate, plan.deactivate, plan.attachEbi);
        m_config = config;
        m_started = Clock::now();
        m_ue = std::thread([this] { exitCode = lte::ue::Run(m_config, shutdown); });
    }

    // Runs to completion and records the outcome; used where the run is expected
    // to terminate on its own bounded retransmission budget.
    void finish()
    {
        if (m_ue.joinable())
            m_ue.join();
        elapsed = Clock::now() - m_started;
        network->stop();
        log = capture->text();
        // Restore std::cout before any assertion so a failure is visible.
        capture.reset();
    }

    // Stops the UE once it reports the outcome under test, so the run cannot
    // wander into an unrelated later stage.
    void stopAfter(const std::string &needle, int timeoutMs = 8000)
    {
        capture->waitFor(needle, timeoutMs);
        shutdown = true;
        finish();
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

// A short reselection run whose reselected cell never answers, so the production
// retransmission path is what completes the run.
std::string SilentTargetConfig(uint16_t uePort, uint16_t sourcePort, uint16_t targetPort, int procedureTimeoutMs = 200)
{
    return UeConfig(uePort, sourcePort, "idle-reselection", targetPort, /*triggerAfterMs=*/1000, procedureTimeoutMs,
                    /*maxRetries=*/1);
}

} // namespace

// ---------------------------------------------------------------------------
// The reselected cell is opened with a bearer inventory
// ---------------------------------------------------------------------------

TEST_CASE("lte/mobility/context: the production UE declares its bearer inventory to a reselected cell")
{
    // A default-only session is the smallest one that must still declare
    // something: the network-assigned default EBI. The reselected endpoint is
    // independent of the serving one and answers the update, so the protected
    // NAS that travelled beside the declaration is also proved genuine: it
    // unprotects under the security context the Attach established and is a
    // Normal Tracking Area Update carrying exactly the declared identities.
    Session session;
    session.start(UeConfig(47301, 47302, "idle-reselection", 47303), Plan{}, TauAction::AcceptWithNewGuti, 47302,
                  47303);
    session.stopAfter("Tracking Area Update accepted");

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "ECM-IDLE cell reselection 460/02/1 -> 460/02/2"));
    CHECK(Contains(session.log, "Protected Normal Tracking Area Update Request sent through the reselected cell"));
    CHECK(Contains(session.log, "Tracking Area Update accepted; context preserved; TAU Complete sent for new GUTI"));
    CHECK(Contains(session.log, "LTE UE shutdown complete"));

    // Exactly one bootstrap reached the reselected cell, and it carried the
    // context-carrying form rather than the identity-only legacy form. The
    // message type is the primary claim, so it is asserted first.
    REQUIRE(session.network->targetFrames.size() >= 1);
    REQUIRE(session.network->targetFrames.front().type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    REQUIRE(session.network->declarations.size() == 1);
    CHECK(session.network->declarations[0].defaultEbi == kDefaultEbi);
    CHECK(session.network->declarations[0].dedicatedEbis.empty());

    // The protected NAS the declaration travelled beside is the genuine
    // protected Tracking Area Update Request the UE built.
    REQUIRE(session.network->tauRequests.size() == 1);
    CHECK(session.network->tauRequests[0].first == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    REQUIRE(session.network->mobilityNas.size() == 1);
    CHECK(session.network->tauRequests[0].second == session.network->mobilityNas[0]);

    // Security Mode Complete, Attach Complete and one fresh Tracking Area
    // Update Request. The TAU Complete follows the Accept.
    CHECK(session.network->protectedUplinks == 4);
    CHECK(session.network->lastUplinkCount == 3);
    CHECK(session.network->tauCompletes == 1);
    CHECK(session.network->attachComplete);
    CHECK(session.network->failures.empty());
    CHECK(Contains(session.log, "NAS security counts: UL-next=4 DL-last=2"));
    CHECK(Contains(session.log, "Control-plane-only mode: LTE TUN unavailable"));
}

TEST_CASE("lte/mobility/context: a retransmission repeats the declaration byte for byte on the same route")
{
    // The reselected cell stays silent, so the production retransmission path is
    // what runs. The retry must repeat the same radio message type, the same
    // declaration and the same protected NAS, and must not consume another
    // uplink NAS COUNT or rebuild the declaration from bearer state that may
    // have moved on since the first transmission.
    Session session;
    session.start(SilentTargetConfig(47304, 47305, 47306), Plan{}, TauAction::NoAnswer, 47305, 47306);
    session.finish();

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Protected Normal Tracking Area Update Request sent through the reselected cell"));
    CHECK(Contains(session.log, "Retransmitted TAU_NORMAL_PENDING, retry=1"));
    CHECK(Contains(session.log, "TAU_NORMAL_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(session.log, "Tracking Area Update accepted"));

    REQUIRE(session.network->declarations.size() == 2);
    REQUIRE(session.network->targetFrames.size() == 2);
    CHECK(session.network->targetFrames[0].type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(session.network->targetFrames[1].type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(session.network->targetFrames[0].payload == session.network->targetFrames[1].payload);
    CHECK(session.network->declarations[0].defaultEbi == session.network->declarations[1].defaultEbi);
    CHECK(session.network->declarations[0].dedicatedEbis == session.network->declarations[1].dedicatedEbis);
    REQUIRE(session.network->mobilityNas.size() == 2);
    CHECK(session.network->mobilityNas[0] == session.network->mobilityNas[1]);

    // Security Mode Complete, Attach Complete and one fresh Tracking Area
    // Update Request. The retransmission is a repeat, not a fourth uplink.
    CHECK(session.network->protectedUplinks == 3);
    CHECK(session.network->lastUplinkCount == 2);
    CHECK(session.network->tauCompletes == 0);
    CHECK(session.network->failures.empty());
    CHECK_FALSE(Contains(session.log, "NAS security counts:"));
    CHECK(session.elapsed < std::chrono::seconds(10));
}

// ---------------------------------------------------------------------------
// The declared identities are the ones the UE really holds
// ---------------------------------------------------------------------------

TEST_CASE("lte/mobility/context: several retained dedicated bearers are all declared")
{
    // The network activates two dedicated bearers after the Attach. Both are
    // live NAS-confirmed contexts at the moment of the reselection, so both have
    // to be declared, and the declaration has to be usable as written rather
    // than depending on the order the network happened to activate them in.
    Session session;
    session.start(SilentTargetConfig(47307, 47308, 47309), Plan{{6, 9}, {}}, TauAction::NoAnswer, 47308, 47309);
    session.finish();

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Dedicated EPS bearer 6 activated"));
    CHECK(Contains(session.log, "Dedicated EPS bearer 9 activated"));

    REQUIRE(session.network->declarations.size() == 2);
    CHECK(session.network->declarations[0].defaultEbi == kDefaultEbi);
    CHECK(session.network->declarations[0].dedicatedEbis == std::vector<uint8_t>{6, 9});
    CHECK(session.network->declarations[1].dedicatedEbis == std::vector<uint8_t>{6, 9});
    CHECK(session.network->targetFrames[0].type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(session.network->targetFrames[0].payload == session.network->targetFrames[1].payload);
    CHECK(session.network->failures.empty());
    CHECK(session.network->attachComplete);
}

TEST_CASE("lte/mobility/context: a deactivated dedicated bearer stops being declared")
{
    // Three dedicated bearers are accepted and the network then releases one.
    // The released identity is no longer an EPS bearer the UE holds, so it must
    // not be presented to a fresh target that would then try to restore it.
    Session session;
    session.start(SilentTargetConfig(47310, 47311, 47312), Plan{{6, 7, 8}, {8}}, TauAction::NoAnswer, 47311, 47312);
    session.finish();

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Dedicated EPS bearer 8 deactivated; default bearer retained"));

    REQUIRE(session.network->declarations.size() == 2);
    CHECK(session.network->declarations[0].defaultEbi == kDefaultEbi);
    CHECK(session.network->declarations[0].dedicatedEbis == std::vector<uint8_t>{6, 7});
    CHECK(session.network->declarations[1].dedicatedEbis == std::vector<uint8_t>{6, 7});
    CHECK(session.network->failures.empty());
}

// ---------------------------------------------------------------------------
// The mobility declaration belongs only to a new-cell bootstrap
// ---------------------------------------------------------------------------

TEST_CASE("lte/mobility/context: a Tracking Area Update on an established S1 connection carries no declaration")
{
    // A standalone Normal TAU over an S1 context the MME already has must not
    // carry a bearer declaration and must not open a new cell: there is nothing
    // to bootstrap. The ordinary NAS uplink route is the only correct one, and a
    // global substitution of the mobility form would show up here as a second
    // endpoint carrying a frame it was never addressed to.
    Session session;
    session.start(UeConfig(47313, 47314, "tau-normal", std::nullopt, /*triggerAfterMs=*/100,
                           /*procedureTimeoutMs=*/30000, /*maxRetries=*/2),
                  Plan{{6}, {}}, TauAction::AcceptWithNewGuti, 47314, 47316);
    session.stopAfter("Tracking Area Update accepted");

    CHECK(session.exitCode == 0);
    CHECK(Contains(session.log, "Protected normal Tracking Area Update Request sent"));
    CHECK(session.network->attachComplete);
    CHECK(session.network->tauCompletes == 1);
    // No mobility uplink of either form was ever produced, and the reselected
    // endpoint was never addressed at all.
    CHECK(session.network->declarations.empty());
    CHECK(session.network->targetFrames.empty());
    REQUIRE(session.network->tauRequests.size() == 1);
    CHECK(session.network->tauRequests[0].first == link::MessageType::NAS_UPLINK);
    CHECK(session.network->failures.empty());
}

// ---------------------------------------------------------------------------
// An unusable declaration is refused before anything is transmitted
// ---------------------------------------------------------------------------

TEST_CASE("lte/mobility/context: a dedicated identity equal to the default is refused before anything leaves the UE")
{
    // A network that activates a dedicated bearer on the default identity has
    // produced a context the declaration cannot express: one EPS bearer cannot
    // be both the default and dedicated. The UE must refuse to describe the
    // session rather than send a declaration a fresh target would act on, and
    // nothing at all may reach the reselected cell.
    Session session;
    session.start(SilentTargetConfig(47317, 47318, 47319), Plan{{5}, {}, kDefaultEbi}, TauAction::NoAnswer, 47318,
                  47319);
    session.finish();

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Refusing to open the reselected cell without a valid bearer inventory"));
    CHECK_FALSE(Contains(session.log, "Protected Normal Tracking Area Update Request sent through the "
                                      "reselected cell"));
    // Nothing was declared and nothing reached the reselected endpoint: the
    // refusal happens before a frame exists, not after one has been sent.
    CHECK(session.network->declarations.empty());
    CHECK(session.network->targetFrames.empty());
    CHECK(session.network->attachComplete);
}

TEST_CASE("lte/mobility/context: the declared default identity is the network-assigned one")
{
    // The declaration must be read back out of the NAS-confirmed bearer state,
    // not from an assumed EBI 5 or 6. Here the network assigns default EBI 9 and
    // a dedicated bearer on top of it, and the reselected cell must be told
    // exactly that. A hardcoded identity would restore bearers this session
    // never had and leave the ones it does have unrestored.
    Session session;
    session.start(SilentTargetConfig(47320, 47321, 47322), Plan{{12}, {}, 9}, TauAction::NoAnswer, 47321, 47322);
    session.finish();

    CHECK(session.exitCode == 1);
    CHECK(Contains(session.log, "Dedicated EPS bearer 12 activated"));
    REQUIRE(session.network->declarations.size() == 2);
    CHECK(session.network->declarations[0].defaultEbi == 9);
    CHECK(session.network->declarations[0].dedicatedEbis == std::vector<uint8_t>{12});
    CHECK(session.network->declarations[1].defaultEbi == 9);
    CHECK(session.network->declarations[1].dedicatedEbis == std::vector<uint8_t>{12});
    CHECK(session.network->targetFrames[0].type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(session.network->failures.empty());
}

// ---------------------------------------------------------------------------
// The declaration itself refuses what the wire cannot express
// ---------------------------------------------------------------------------

namespace
{

DedicatedBearerRuntime MakeDedicated(uint8_t ebi, uint8_t linkedEbi)
{
    DedicatedBearerRuntime bearer;
    bearer.ebi = ebi;
    bearer.linkedEbi = linkedEbi;
    return bearer;
}

std::array<uint8_t, 11> TestGuti()
{
    std::array<uint8_t, 11> guti{};
    guti[0] = 0xF6;
    guti[6] = kMmeCode;
    guti[7] = 0xC0;
    guti[8] = 0x00;
    guti[9] = 0x01;
    guti[10] = 0x8E;
    return guti;
}

} // namespace

TEST_CASE("lte/mobility/context: an inventory the wire cannot express is refused before a frame exists")
{
    // Every form the encoding must refuse is refused here, at the point where
    // the declaration is built, which is before any radio frame exists at all.
    // There is no truncation, no rounding to a plausible identity and no
    // fallback to a plainer message type.
    constexpr uint32_t kUeId = 1;
    const std::vector<uint8_t> nas{0x37, 0x01, 0x02, 0x03};
    const auto guti = TestGuti();

    // An unassigned default identity.
    CHECK_THROWS(ValidateBearerInventory(0, {}));
    CHECK_THROWS(ValidateBearerInventory(4, {}));
    CHECK_THROWS(ValidateBearerInventory(16, {}));
    // A dedicated identity equal to the default one.
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(5, 5)}));
    // A dedicated identity linked to a different default bearer.
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(6, 7)}));
    // A dedicated identity outside the assignable range.
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(4, 5)}));
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(16, 5)}));
    // The same dedicated identity declared twice.
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(6, 5), MakeDedicated(6, 5)}));
    // More dedicated identities than one UE can hold.
    CHECK_THROWS(ValidateBearerInventory(5, {MakeDedicated(6, 5), MakeDedicated(7, 5), MakeDedicated(8, 5),
                                             MakeDedicated(9, 5), MakeDedicated(10, 5), MakeDedicated(11, 5),
                                             MakeDedicated(12, 5), MakeDedicated(13, 5)}));

    // The same refusals at the frame itself, so a caller that skips the
    // validation is still stopped before a message exists.
    const link::BearerInventory badDefault{4, {}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, badDefault, nas));
    const link::BearerInventory badDedicated{5, {5}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, badDedicated, nas));
    const link::BearerInventory badDuplicate{5, {6, 6}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, badDuplicate, nas));
    const link::BearerInventory badRange{5, {4, 6}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, badRange, nas));
    const link::BearerInventory tooMany{5, {6, 7, 8, 9, 10, 11, 12, 13}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, tooMany, nas));
    // A mobility uplink that carries no protected NAS has nothing to deliver.
    const link::BearerInventory fine{5, {6}};
    CHECK_THROWS(link::BuildMobilityContext(kUeId, guti, fine, {}));
}

TEST_CASE("lte/mobility/context: the declaration sits beside the protected NAS and never inside it")
{
    // The wire layout is the one the target decoder reads: the GUTI identity
    // prefix, then the bounded inventory, then the protected NAS untouched. The
    // NAS bytes are the procedure the MME must see, so they are carried
    // verbatim and are never rewritten to make room for the declaration.
    constexpr uint32_t kUeId = 1;
    const std::vector<uint8_t> nas{0x37, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    const auto guti = TestGuti();

    const auto inventory = ValidateBearerInventory(5, {MakeDedicated(9, 5), MakeDedicated(6, 5), MakeDedicated(11, 5)});
    // The declaration is a set of identities, so it is written in the ascending
    // order the encoding requires regardless of activation order.
    CHECK(inventory.defaultEbi == 5);
    CHECK(inventory.dedicatedEbis == std::vector<uint8_t>{6, 9, 11});

    const auto frame = link::BuildMobilityContext(kUeId, guti, inventory, nas);
    CHECK(frame.type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(frame.ueId == kUeId);

    const auto &payload = frame.payload;
    REQUIRE(payload.size() == 5 + 2 + 3 + nas.size());
    CHECK(payload[0] == kMmeCode);
    CHECK(payload[1] == 0xC0);
    CHECK(payload[2] == 0x00);
    CHECK(payload[3] == 0x01);
    CHECK(payload[4] == 0x8E);

    link::BearerInventory decoded{};
    const size_t consumed = link::DecodeBearerInventory(payload.data() + 5, payload.size() - 5, decoded);
    CHECK(consumed == 5);
    CHECK(decoded.defaultEbi == inventory.defaultEbi);
    CHECK(decoded.dedicatedEbis == inventory.dedicatedEbis);
    // The protected NAS follows the declaration unchanged.
    CHECK(std::vector<uint8_t>(payload.begin() + 5 + consumed, payload.end()) == nas);

    // The message the UE sends is the one the codec accepts and no larger than
    // the bounded form a single UE can declare.
    const auto wire = link::Encode(frame);
    const auto decodedFrame = link::Decode(wire.data(), wire.size());
    CHECK(decodedFrame.type == link::MessageType::NAS_UPLINK_MOBILITY_CONTEXT);
    CHECK(decodedFrame.payload == payload);
}
