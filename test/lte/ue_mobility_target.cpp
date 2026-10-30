//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Integration of the production UE sender with the production target eNB
// receiver.
//
// Every other test in this area proves one half of the reselection contract:
// test/lte/ue_mobility_context.cpp drives the real lte::ue::Run() sender against
// a scripted radio endpoint, and test/lte/mobility_target.cpp drives a real
// EnbMultiplexer against frames a test assembled by hand. Neither of them shows
// that the message the running UE leaves on the wire is the message the real
// target eNB accepts. This file closes that gap: the UE runs its real Run()
// path, the reselected cell is a real EnbMultiplexer bound to its own
// simulated-radio endpoint, and the network that answers it is authored here
// out of the public S1AP and NAS codecs.
//
// The serving cell is a minimal fake MME performing a real EPS AKA exchange
// over the 3GPP TS 35.208 test subscriber already present in test/lte/ue.cpp.
// The same security context that protected the Attach then answers the Tracking
// Area Update at the target, so the whole protected-NAS round trip is genuine
// and no HSS, EPC daemon or subscriber is involved.
//
// The UE asks for control-plane-only mode: the single requested route carries
// host bits, so the kernel rejects it and no TUN is created. That keeps the test
// deterministic and non-root, and it is also why the bearer transport
// confirmations of the target eNB cannot be exercised through the real UE here:
// they need the local user plane. Those legs are covered at the target in
// test/lte/mobility_target.cpp and are reported as TUN-gated rather than
// simulated.

#include <ext/doctest/doctest.h>

#include "log_capture.hpp"

#include <lib/udp/server.hpp>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/enb/user_plane.hpp>
#include <lte/ue/app.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>
#include <lte/ue/security.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace lte::enb;
using namespace lte::ue;
namespace link = lte::ue::link;
using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// The 3GPP TS 35.208 test subscriber, identical to test/lte/ue.cpp. It is
// fixture data only; no subscription is created and no HSS is consulted.
//
// The serving cell is at sourcePort inside tracking area 460/02/1. The
// reselected cell is the real target eNB on its own radio endpoint in tracking
// area 460/02/2, so leaving the registered tracking area list is what forces
// the reselection to open a new S1 connection there.
std::string UeYaml(uint16_t uePort, uint16_t sourcePort, uint16_t targetPort, int procedureTimeoutMs, int maxRetries)
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
  tac: 1
  targetCell:
    mcc: '460'
    mnc: '02'
    tac: 2
    address: 127.0.0.1
    port: )"
       << targetPort << R"(
  timeoutMs: 10000
tun:
  required: false
  routes: ['192.168.5.7/24']
lifecycle:
  scenario: idle-reselection
  triggerAfterMs: 1000
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

// The S-TMSI of the GUTI the Attach Accept below assigns.
constexpr uint8_t kMmeCode = 1;
constexpr uint32_t kMTmsi = 0xC000018Eu;
constexpr uint8_t kDefaultEbi = 5;

// The S-TMSI value the target eNB has to put in the Initial UE Message: the
// two preamble bits and the MMEC of X.691 aligned PER, then the M-TMSI.
const std::vector<uint8_t> kExpectedSTmsi{0x00, 0x40, 0xC0, 0x00, 0x01, 0x8E};

// ---------------------------------------------------------------------------
// S1AP capture
// ---------------------------------------------------------------------------

struct CapturedS1ap
{
    uint16_t stream{};
    std::vector<uint8_t> pdu;
};

// The stand-in MME association. The real multiplexer writes every S1AP PDU it
// produces through this interface, so what lands here is what a real MME would
// receive.
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

    // The first initiating message of a procedure code, or an empty vector when
    // the network never sent one. Returned rather than thrown so a test can
    // assert on the absence without a doctest macro firing inside the harness.
    [[nodiscard]] std::vector<uint8_t> first(uint8_t procedureCode) const
    {
        for (const auto &item : sent)
        {
            const auto pdu = s1ap::ProbeS1apPdu(item.pdu.data(), item.pdu.size());
            if (pdu.kind == s1ap::S1apPdu::Kind::INITIATING && pdu.procedureCode == procedureCode)
                return item.pdu;
        }
        return {};
    }

    std::vector<CapturedS1ap> sent;
};

// The target eNB the UE reselects into. It gets its own identifier, its own
// simulated-radio endpoint and its own S1-U endpoint, and it is never prepared
// by hand: nothing about the UE's session exists in its registry until the UE's
// own mobility uplink arrives.
EnbConfig TestEnbConfig(uint32_t enbId, const std::string &s1uAddress, uint16_t tac)
{
    EnbConfig config{};
    config.plmn = {"460", "02"};
    config.enbId = enbId;
    config.tac = tac;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.2";
    config.mmePort = 36412;
    config.ueLinkAddress = "127.0.0.1";
    config.ueLinkPort = 0;
    config.s1uAddress = s1uAddress;
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

bool Contains(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle)
{
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

bool Contains(const std::string &haystack, const std::string &needle)
{
    return haystack.find(needle) != std::string::npos;
}

// A network-authored E-RAB item for an Initial Context Setup Request or an
// E-RAB Setup Request.
s1ap::ErabToBeSetupItem Erab(uint8_t ebi, uint8_t qci, uint32_t sgwTeid)
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.transportLayerAddress = {127, 0, 0, 2};
    item.gtpTeid = TeidToBytes(sgwTeid);
    return item;
}

s1ap::ErabToBeSetupItem ErabWithNas(uint8_t ebi, uint8_t qci, uint32_t sgwTeid)
{
    auto item = Erab(ebi, qci, sgwTeid);
    item.nasPduPresent = true;
    item.nasPdu = {0x2E, 0x01};
    return item;
}

// ---------------------------------------------------------------------------
// The laboratory: a real UE, a fake serving MME and a real target eNB
// ---------------------------------------------------------------------------

// Everything the scripted serving cell and the scripted target MME do runs on
// the test thread, so the NAS security context is single-threaded and needs no
// synchronisation. Only lte::ue::Run() runs elsewhere.
//
// The harness deliberately never fires a doctest assertion of its own: the
// running UE logs through std::cout, which LogCapture owns until finish(), and
// an assertion reported into a captured stream is invisible. Every observation
// is instead recorded and asserted after the capture has been released.
class Lab
{
  public:
    Lab(uint16_t uePort, uint16_t sourcePort, int procedureTimeoutMs = 30000, int maxRetries = 2)
        : m_capture(std::make_unique<lte::test::LogCapture>()), m_source("127.0.0.1", sourcePort)
    {
        m_target = std::make_unique<EnbMultiplexer>(TestEnbConfig(0x2C1, "127.0.0.3", 2), m_targetWire);
        m_config = lte::ue::ParseConfig(UeYaml(uePort, sourcePort, m_target->ueLinkAddress().getPort(), procedureTimeoutMs,
                                      maxRetries));
    }

    void scriptDedicated(std::vector<uint8_t> activate) { m_activate = std::move(activate); }

    void startUe()
    {
        m_ue = std::thread([this] { m_exit = lte::ue::Run(m_config, m_shutdown); });
    }

    // Joins the UE, copies its log out and releases std::cout so every later
    // assertion is visible. Idempotent.
    void finish()
    {
        if (m_ue.joinable())
            m_ue.join();
        m_target->poll();
        if (m_capture)
        {
            log = m_capture->text();
            m_capture.reset();
        }
    }

    void shutdownUe()
    {
        m_shutdown = true;
        finish();
    }

    ~Lab()
    {
        m_shutdown = true;
        if (m_ue.joinable())
            m_ue.join();
    }

    // Drives both simulated endpoints until `done()` holds or the budget runs
    // out. Everything the scripted cells do happens here, on this thread.
    template <typename Done>
    bool drive(Done done, int timeoutMs)
    {
        const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (Clock::now() < deadline)
        {
            while (pumpSource())
            {
            }
            m_target->poll();
            if (done())
                return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return done();
    }

    bool driveUntilSourceAttachComplete(int timeoutMs = 8000)
    {
        return drive([this] { return m_attachComplete; }, timeoutMs);
    }

    bool driveUntilDedicatedConfirmed(const std::vector<uint8_t> &ebis, int timeoutMs = 8000)
    {
        return drive(
            [&] {
                for (const uint8_t ebi : ebis)
                    if (m_activated.count(ebi) == 0)
                        return false;
                return true;
            },
            timeoutMs);
    }

    bool driveUntilIdleReleased(int timeoutMs = 8000)
    {
        return drive([this] { return m_idleReleased; }, timeoutMs);
    }

    bool driveUntilTargetInitialUeMessage(int timeoutMs = 12000)
    {
        return drive([this] { return m_targetWire.count(kInitialUeMessage) == 1; }, timeoutMs);
    }

    bool driveUntilTargetRejects(int timeoutMs = 8000)
    {
        return drive([this] { return m_target->recoveryCounters().staleMessagesRejected >= 1; }, timeoutMs);
    }

    bool driveUntilUplinkNasTransport(int timeoutMs = 8000)
    {
        return drive([this] { return m_targetWire.count(kUplinkNasTransport) >= 1; }, timeoutMs);
    }

    // Blocks on the UE's own log line while the UE is still running. Nothing on
    // the network side needs pumping at that point.
    bool waitForUeLine(const std::string &needle, int timeoutMs = 8000)
    {
        return m_capture && m_capture->waitFor(needle, timeoutMs);
    }

    // A network-authored Initial Context Setup Request against the live target
    // registry entry the UE's own mobility uplink created.
    void deliverIcsr(const std::vector<s1ap::ErabToBeSetupItem> &erabs, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        s1ap::InitialContextSetupRequest request{};
        request.mmeUeS1apId = mmeUeS1apId;
        request.enbUeS1apId = entry->enbUeS1apId;
        request.ueAmbrUl = 1000;
        request.ueAmbrDl = 2000;
        request.erabs = erabs;
        const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // A network-authored E-RAB Setup Request adding one dedicated bearer on top
    // of the default one the target already established.
    void deliverErabSetup(const s1ap::ErabToBeSetupItem &item, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        s1ap::ErabSetupRequest setup{};
        setup.mmeUeS1apId = mmeUeS1apId;
        setup.enbUeS1apId = entry->enbUeS1apId;
        setup.erabs = {item};
        const auto pdu = s1ap::EncodeErabSetupRequest(setup);
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // A protected downlink NAS message from the same EPS peer that performed
    // the Attach, delivered through the real target eNB's Downlink NAS
    // Transport. The COUNT it uses is the one the UE is waiting for.
    void deliverProtectedDownlink(const std::vector<uint8_t> &plain, uint32_t mmeUeS1apId = 500)
    {
        const auto *entry = m_target->registry().find(m_config.ueId);
        if (entry == nullptr)
            return note("the target registry holds no entry for the UE");
        const auto pdu = s1ap::EncodeDownlinkNasTransport(mmeUeS1apId, entry->enbUeS1apId, ProtectDownlink(plain, /*newContext=*/false));
        m_target->handleS1ap(pdu.data(), pdu.size(), 1);
    }

    // Rebuilds the protected uplink the UE sends towards the target: the same
    // plain message, the same security context and the very next uplink NAS
    // COUNT. Matching against it is how the test reads the protected NAS back
    // out of an S1AP message that has no public decoder. It advances the
    // network's view of the uplink COUNT exactly as consuming the real message
    // would, because that uplink went to the target rather than to this cell.
    std::vector<uint8_t> expectedProtectedUplink(const std::vector<uint8_t> &plain)
    {
        auto predict = m_security;
        predict.ulNasCount = (m_security.ulNasCount + 1U) & 0xFFFFFFU;
        auto message = nas::Protect(predict, true, false, plain);
        m_security.ulNasCount = predict.ulNasCount;
        return message;
    }

    // The plain Tracking Area Update Request the production sender is expected
    // to protect: the same call the reselection branch of Run() makes, rebuilt
    // here from the bearer identities the network itself activated.
    std::vector<uint8_t> expectedTauRequest() const
    {
        std::vector<uint8_t> identities{kDefaultEbi};
        identities.insert(identities.end(), m_activate.begin(), m_activate.end());
        return nas::EncodeTauRequest(m_security.ksi, assignedGuti(), identities, false);
    }

    // The GUTI the Attach Accept assigned, in the eleven-octet form the UE
    // keeps and the Tracking Area Update Request is identified by.
    std::array<uint8_t, 11> assignedGuti() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);
        return {0xF6, plmn[0], plmn[1], plmn[2], 0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8E};
    }

    [[nodiscard]] std::vector<uint8_t> tauAccept() const { return TauAccept(); }

    [[nodiscard]] const Config &config() const { return m_config; }
    [[nodiscard]] EnbMultiplexer &target() { return *m_target; }
    [[nodiscard]] CaptureSender &targetWire() { return m_targetWire; }
    [[nodiscard]] int exitCode() const { return m_exit; }
    [[nodiscard]] const std::vector<std::string> &problems() const { return m_problems; }
    // The UE log so far: live while the capture owns std::cout, copied after
    // finish() has released it.
    [[nodiscard]] std::string captureText() const { return m_capture ? m_capture->text() : log; }

    std::string log;

  private:
    static constexpr uint8_t kInitialUeMessage = 12;
    static constexpr uint8_t kUplinkNasTransport = 13;

    void note(const std::string &reason) { m_problems.push_back(reason); }

    // One datagram from the UE to the serving cell, or a quiet tick.
    bool pumpSource()
    {
        uint8_t buffer[link::MaxDataPduSize + link::HeaderSize];
        InetAddress peer;
        const int received = m_source.Receive(buffer, sizeof(buffer), 1, peer);
        if (received <= 0)
            return false;
        link::Message frame{};
        try
        {
            frame = link::Decode(buffer, static_cast<size_t>(received));
        }
        catch (const std::exception &e)
        {
            note(std::string("the serving cell received a malformed radio frame: ") + e.what());
            return true;
        }
        if (frame.ueId != m_config.ueId)
        {
            note("radio frame carried an unexpected UE identity");
            return true;
        }
        m_uePeer = peer;
        handleSource(frame);
        return true;
    }

    void sendToUe(link::MessageType type, std::vector<uint8_t> payload)
    {
        const auto frame = link::Encode({type, m_config.ueId, std::move(payload)});
        m_source.Send(m_uePeer, frame.data(), frame.size());
    }

    void sendNasToUe(std::vector<uint8_t> nas) { sendToUe(link::MessageType::NAS_DOWNLINK, std::move(nas)); }

    void handleSource(const link::Message &frame)
    {
        if (frame.type == link::MessageType::S1_CONTEXT_RELEASE_REQUEST)
        {
            // The controlled idle trigger: the serving cell answers with the S1
            // context release that puts the UE into ECM-IDLE.
            if (m_idleReleased)
                return note("the UE asked for a second idle transition");
            m_idleReleased = true;
            sendToUe(link::MessageType::S1_CONTEXT_RELEASED,
                     link::EncodeBearerRestoration(kDefaultEbi, /*generation=*/1));
            return;
        }
        if (frame.type == link::MessageType::BEARER_ACTIVATED)
        {
            if (frame.payload.size() != 1)
                return note("a bearer activation confirmation did not name one EPS bearer identity");
            m_activated.insert(frame.payload[0]);
            return;
        }
        if (frame.type != link::MessageType::NAS_UPLINK)
            return note("the serving cell received a radio frame it does not script");
        const auto &payload = frame.payload;
        if (payload.size() < 2)
            return note("truncated NAS uplink at the serving cell");
        if (payload[0] == 0x07 && payload[1] == 0x41)
        {
            // Derive the same EPS AKA context the UE will, so both sides agree
            // on RES, CK, IK and KASME without consulting any credential store.
            const auto challenge = AuthRequestBytes();
            m_security = nas::Authenticate(m_config, nas::DecodeAuthenticationRequest(challenge.data(),
                                                                                     challenge.size()))
                             .context;
            m_security.advertisedSecurityCapabilities.assign(m_config.networkCapability.begin(),
                                                             m_config.networkCapability.end());
            sendNasToUe(challenge);
            return;
        }
        if (payload[0] == 0x07 && payload[1] == 0x53)
        {
            sendNasToUe(SecurityModeCommand());
            return;
        }
        std::vector<uint8_t> plain;
        uint32_t count = 0;
        try
        {
            const auto parsed = nas::ParseProtectedHeader(payload.data(), payload.size());
            const bool fresh = nas::StartsNewContext(parsed.headerType);
            count = fresh ? parsed.sequenceNumber : nas::EstimateNasCount(m_security.ulNasCount, parsed.sequenceNumber);
            if (!fresh && count <= m_security.ulNasCount)
                return note("the serving cell saw a replayed uplink NAS COUNT");
            plain = nas::UnprotectBody(m_security, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                       parsed.plain);
        }
        catch (const std::exception &e)
        {
            return note(std::string("the serving cell could not unprotect an uplink: ") + e.what());
        }
        m_security.ulNasCount = count;
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x5E)
        {
            // Security Mode Complete: the serving cell now assigns the bearer
            // and the GUTI the reselected cell will be addressed by.
            sendNasToUe(ProtectDownlink(AttachAccept(), /*newContext=*/false));
            return;
        }
        if (plain.size() >= 2 && plain[0] == 0x07 && plain[1] == 0x43)
        {
            m_attachComplete = true;
            for (const uint8_t ebi : m_activate)
                sendNasToUe(ProtectDownlink(ActivateDedicated(ebi), /*newContext=*/false));
            return;
        }
        // Anything else is the Activate Dedicated EPS Bearer Context Accept, and
        // the radio frame beside it is what records the confirmation.
    }

    std::vector<uint8_t> ProtectDownlink(const std::vector<uint8_t> &plain, bool newContext)
    {
        auto message = nas::Protect(m_security, /*uplink=*/false, newContext, plain);
        m_security.dlNasCount = (m_security.dlNasCount + 1U) & 0xFFFFFFU;
        return message;
    }

    // The Security Mode Command must reach the UE on the integrity-only "new
    // EPS security context" header so its information elements stay readable in
    // the clear. nas::Protect with a fresh context always selects the ciphered
    // new-context header, and this fixture negotiates EEA0, so the protected
    // body is already the plain message and only the header nibble has to be
    // corrected. The MAC covers sequenceNumber||body and is unchanged.
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

    static std::vector<uint8_t> AuthRequestBytes()
    {
        return {0x07, 0x52, 0x07,
                0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
                0x10, 0x55, 0xF3, 0x28, 0xB4, 0x35, 0x77, 0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF,
                0xB3};
    }

    // Attach Accept with a full tracking area list for the served PLMN/TAC and
    // the GUTI the Tracking Area Update Request is later identified by.
    std::vector<uint8_t> AttachAccept() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);

        // Activate Default EPS Bearer Context Request: the assigned default
        // EBI, PTI 1, QCI 5, APN "internet", PDN address 10.0.0.1.
        const std::vector<uint8_t> esm{static_cast<uint8_t>((kDefaultEbi << 4U) | 0x02U), 0x01, 0xC1,
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
    static std::vector<uint8_t> ActivateDedicated(uint8_t ebi)
    {
        return {static_cast<uint8_t>((ebi << 4U) | 0x02U), 0x01, 0xC5, kDefaultEbi, 0x01, 0x09, 0x00};
    }

    // A Tracking Area Update Accept the network itself would author: the plain
    // EPS-only "TA updated" result this procedure performs, a periodic timer, a
    // tracking area list for the reselected cell's PLMN/TAC and a fresh GUTI.
    std::vector<uint8_t> TauAccept() const
    {
        const auto plmn = s1ap::EncodePlmn(m_config.plmn);
        std::vector<uint8_t> out{0x07, 0x49, 0x00};
        out.push_back(0x5A); // GPRS timer T3412, type-1 optional IE
        out.push_back(0x30);
        out.insert(out.end(), {0x54, 0x06, 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x02});
        out.push_back(0x50); // GUTI optional IE with a new M-TMSI
        out.push_back(0x0B);
        out.push_back(0xF6);
        out.insert(out.end(), plmn.begin(), plmn.end());
        out.insert(out.end(), {0x00, 0x01, kMmeCode, 0xC0, 0x00, 0x01, 0x8F});
        return out;
    }

    std::unique_ptr<lte::test::LogCapture> m_capture;
    udp::UdpServer m_source;
    CaptureSender m_targetWire;
    std::unique_ptr<EnbMultiplexer> m_target;
    Config m_config;
    SecurityContext m_security{};
    InetAddress m_uePeer;
    std::vector<uint8_t> m_activate;
    std::set<uint8_t> m_activated;
    std::vector<std::string> m_problems;
    bool m_attachComplete{};
    bool m_idleReleased{};
    std::atomic_bool m_shutdown{false};
    int m_exit{-1};
    std::thread m_ue;
};

} // namespace

// ---------------------------------------------------------------------------
// The real UE opens a real target eNB and completes a Tracking Area Update
// ---------------------------------------------------------------------------

TEST_CASE("lte/ue_mobility_target: a real UE reselection reaches a real target eNB and completes a TAU there")
{
    Lab lab(47341, 47342);
    lab.scriptDedicated({6, 9});
    lab.startUe();

    // The serving cell brings the EPS session up: real AKA, a real Attach, and
    // two dedicated bearers the network activates on top of the default one.
    const bool attached = lab.driveUntilSourceAttachComplete();
    const bool dedicated = lab.driveUntilDedicatedConfirmed({6, 9});
    const bool idle = lab.driveUntilIdleReleased();

    // The UE reselects the target cell and opens it with its own mobility
    // uplink. The target eNB is a real EnbMultiplexer, so what appears on its
    // MME association is a real Initial UE Message built by production code.
    const bool arrived = lab.driveUntilTargetInitialUeMessage();
    const auto initial = lab.targetWire().first(12);
    const auto probe = s1ap::ProbeS1apPdu(initial.data(), initial.size());

    // The NAS PDU inside it is the genuine protected Tracking Area Update
    // Request the production sender built. It is recovered by rebuilding the
    // very message the UE's reselection branch builds — same plain, same
    // context, the one uplink NAS COUNT that opens the procedure — and matching
    // it against what actually left the UE.
    const auto expectedNas = lab.expectedProtectedUplink(lab.expectedTauRequest());
    const bool nasCarried = Contains(initial, expectedNas);

    // The Initial UE Message addresses the session by the S-TMSI of the GUTI
    // the UE's own NAS holds, not by anything the source cell allocated.
    const bool sTmsiCarried = Contains(initial, kExpectedSTmsi);

    // The target registry was empty before the UE arrived and now holds exactly
    // the declaration the UE made: the network-assigned default plus both
    // dedicated identities, on a fresh eNB-UE-S1AP-ID of this cell.
    auto *entry = lab.target().registry().find(lab.config().ueId);
    const bool registered = entry != nullptr;
    const bool declaredDefault = registered && entry->declaredBearers.has_value() &&
                                entry->declaredBearers->defaultEbi == kDefaultEbi;
    const bool declaredDedicated = registered && entry->declaredBearers.has_value() &&
                                   entry->declaredBearers->dedicatedEbis == std::vector<uint8_t>{6, 9};
    const bool pending = registered && entry->s1 == UeS1State::CONTEXT_PENDING && entry->mobilityBootstrap &&
                         entry->enbUeS1apId != 0;

    // The network restores the default bearer first. The declared dedicated
    // bearers are named in the declaration and are restored when the network
    // later asks for them, never guessed from the E-RAB list.
    lab.deliverIcsr({Erab(kDefaultEbi, 9, 30)});
    const bool established = registered && entry->s1 == UeS1State::CONTEXT_ESTABLISHED &&
                             entry->bearer.signalingEstablished() && entry->bearer.restorationPending() &&
                             !entry->bearer.active() && entry->bearer.parameters().erabId == kDefaultEbi &&
                             entry->dedicatedBearers.empty();

    // The UE accepts the target's generation-bound bearer restoration and only
    // then stops treating the cell as new.
    const bool restored = lab.waitForUeLine("bearer signaling restored in control-plane-only mode");
    const bool reselected = Contains(lab.captureText(), "ECM-IDLE cell reselection 460/02/1 -> 460/02/2");

    // The network answers the update over the real target eNB. The UE accepts
    // it only because its NAS security context survived the cell change, and it
    // owes the network a protected TAU Complete for the new GUTI.
    lab.deliverProtectedDownlink(lab.tauAccept());
    const bool accepted =
        lab.waitForUeLine("Tracking Area Update accepted; context preserved; TAU Complete sent for new GUTI");

    // That Complete leaves through the real target eNB as an ordinary Uplink NAS
    // Transport, which is the routing the correction deliberately preserved.
    const bool completed = lab.driveUntilUplinkNasTransport();
    const auto uplink = lab.targetWire().first(13);
    const bool completeCarried = Contains(uplink, lab.expectedProtectedUplink(nas::EncodeTauComplete()));

    lab.shutdownUe();
    REQUIRE(lab.problems().empty());
    REQUIRE(attached);
    REQUIRE(dedicated);
    REQUIRE(idle);
    REQUIRE(arrived);
    CHECK(probe.kind == s1ap::S1apPdu::Kind::INITIATING);
    CHECK(probe.procedureCode == 12);
    CHECK(nasCarried);
    CHECK(sTmsiCarried);
    REQUIRE(registered);
    CHECK(pending);
    CHECK(declaredDefault);
    CHECK(declaredDedicated);
    CHECK(established);
    CHECK(restored);
    CHECK(reselected);
    CHECK(accepted);
    REQUIRE(completed);
    CHECK(completeCarried);
    CHECK(lab.exitCode() == 0);

    // The declared dedicated bearer is later restored on top of the default
    // one, as a restoration of a bearer the UE's own NAS already confirmed
    // rather than as a brand-new one, and with target transport that is not the
    // source cell's. The UE-side confirmation of that transport needs the local
    // user plane and is covered at the target in test/lte/mobility_target.cpp.
    lab.deliverErabSetup(ErabWithNas(6, 7, 36));
    REQUIRE(lab.problems().empty());
    REQUIRE(entry->dedicatedBearers.size() == 1);
    const auto &dedicated6 = entry->dedicatedBearers.front();
    CHECK(dedicated6.parameters().erabId == 6);
    CHECK(dedicated6.parameters().linkedDefaultEbi == kDefaultEbi);
    CHECK(dedicated6.kind() == BearerKind::DEDICATED);
    CHECK(dedicated6.signalingEstablished());
    CHECK(dedicated6.restorationPending());
    CHECK_FALSE(dedicated6.active());
    CHECK(dedicated6.parameters().localTeid != entry->bearer.parameters().localTeid);
}

// ---------------------------------------------------------------------------
// A retransmission is a repeat of the frozen frame, and the target treats it
// as one
// ---------------------------------------------------------------------------

TEST_CASE("lte/ue_mobility_target: a repeated mobility uplink is refused by the target without disturbing its context")
{
    Lab lab(47343, 47344, /*procedureTimeoutMs=*/200, /*maxRetries=*/1);
    lab.scriptDedicated({6});
    lab.startUe();

    const bool attached = lab.driveUntilSourceAttachComplete();
    const bool dedicated = lab.driveUntilDedicatedConfirmed({6});
    const bool idle = lab.driveUntilIdleReleased();
    const bool arrived = lab.driveUntilTargetInitialUeMessage();

    auto *entry = lab.target().registry().find(lab.config().ueId);
    REQUIRE(entry != nullptr);
    const uint32_t enbUeS1apId = entry->enbUeS1apId;
    const bool hadDefault = entry->declaredBearers.has_value();
    const uint8_t declaredDefaultEbi = hadDefault ? entry->declaredBearers->defaultEbi : 0;
    const std::vector<uint8_t> declaredDedicated =
        hadDefault ? entry->declaredBearers->dedicatedEbis : std::vector<uint8_t>{};

    // The network never answers, so the production retransmission path is what
    // runs. The retry repeats the frozen frame, and the real target refuses to
    // let it open a second S1 connection on top of the one already pending.
    const bool rejected = lab.driveUntilTargetRejects();
    const size_t initials = lab.targetWire().count(12);
    const uint64_t stale = lab.target().recoveryCounters().staleMessagesRejected;

    // The pending context is untouched by the rejected repeat.
    auto *after = lab.target().registry().find(lab.config().ueId);
    const bool intact = after == entry && entry->s1 == UeS1State::CONTEXT_PENDING &&
                        entry->enbUeS1apId == enbUeS1apId && entry->declaredBearers.has_value() == hadDefault &&
                        (!hadDefault || (entry->declaredBearers->defaultEbi == declaredDefaultEbi &&
                                         entry->declaredBearers->dedicatedEbis == declaredDedicated));

    lab.finish();
    REQUIRE(lab.problems().empty());
    REQUIRE(attached);
    REQUIRE(dedicated);
    REQUIRE(idle);
    REQUIRE(arrived);
    CHECK(rejected);
    CHECK(initials == 1);
    CHECK(stale == 1);
    CHECK(intact);
    CHECK(lab.exitCode() == 1);
    CHECK(Contains(lab.log, "ECM-IDLE cell reselection 460/02/1 -> 460/02/2"));
    CHECK(Contains(lab.log, "Retransmitted TAU_NORMAL_PENDING, retry=1"));
    CHECK(Contains(lab.log, "TAU_NORMAL_PENDING timed out after bounded retransmissions"));
    CHECK_FALSE(Contains(lab.log, "Tracking Area Update accepted"));
}
