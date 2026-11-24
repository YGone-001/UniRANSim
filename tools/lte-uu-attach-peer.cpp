//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D4: a deterministic EPC peer for the two-process EPS lifecycle.
//
// Process 2 of the acceptance: it owns the real eNB-side SRB1 bridge and a
// deterministic MME that runs EPS AKA, NAS security, the Attach exchange and the
// UE-initiated Detach of the same session, against the production UE process
// over the simulated Uu socket. It writes a result file so the test can state
// what actually happened instead of inferring it from a log line.
//
// Usage: lte-uu-attach-peer <port> <ready-file> <result-file> [mode]
//
// Modes:
//   attach-only             stop after the Attach Complete (D3 behaviour, default)
//   attach-detach           continue and complete a UE-initiated Detach
//   duplicate-attach-accept send the Attach Accept twice
//   exit-on-detach          leave without answering the Detach Request
//   bad-detach-mac          answer with a deliberately corrupted MAC
//   service-request         release the UE, then accept its Service Request
//   paging                  release the UE, page it, then accept its Service Request
//   paging-timeout          release the UE and never page it
//   paging-wrong-identity   release the UE and page a different S-TMSI
//   paging-peer-exit        page the UE and leave before the Service Request
//   bad-service-mac         refuse the Service Request after MAC corruption
//   duplicate-detach-accept send the protected Detach Accept twice
#include <lte/enb/codec.hpp>
#include <lte/enb/enb_rrc_bridge.hpp>
#include <lte/rrc-runtime/rrc_connection_setup_complete.hpp>
#include <lte/security/as_security.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/security.hpp>
#include <lte/ue/types.hpp>

#include <lib/crypt/crypt.hpp>
#include <lib/crypt/milenage.hpp>
#include <utils/octet_string.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace
{

using Clock = std::chrono::steady_clock;

OctetString Octets(const std::vector<uint8_t> &bytes)
{
    return OctetString(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

template <size_t N> OctetString Octets(const std::array<uint8_t, N> &bytes)
{
    return OctetString(std::vector<uint8_t>(bytes.begin(), bytes.end()));
}

lte::ue::Config Subscriber()
{
    lte::ue::Config config{};
    config.imsi = "460020000000400";
    config.plmn = {"460", "02"};
    config.opc = std::array<uint8_t, 16>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    config.key = std::array<uint8_t, 16>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    config.op = std::array<uint8_t, 16>{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    config.amf = {0x80, 0x00};
    config.initialSqn = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    config.networkCapability = {0xA0, 0x20};
    return config;
}

struct Aka
{
    std::array<uint8_t, 16> rand{};
    std::array<uint8_t, 16> autn{};
    std::array<uint8_t, 8> res{};
    uint8_t sqn[6]{};
};

Aka RunMilenage(const lte::ue::Config &config)
{
    Aka aka{};
    for (size_t i = 0; i < aka.rand.size(); ++i)
        aka.rand[i] = static_cast<uint8_t>(0x10 + i * 3U);
    for (size_t i = 0; i < 6; ++i)
        aka.sqn[i] = config.initialSqn[i];
    const auto milenage = crypto::milenage::Calculate(Octets(*config.opc), Octets(config.key), Octets(aka.rand),
                                                      Octets(std::vector<uint8_t>(aka.sqn, aka.sqn + 6)),
                                                      Octets(config.amf));
    for (size_t i = 0; i < 6; ++i)
        aka.autn[i] = static_cast<uint8_t>(aka.sqn[i] ^ milenage.ak.get(static_cast<int>(i)));
    aka.autn[6] = config.amf[0];
    aka.autn[7] = config.amf[1];
    for (size_t i = 0; i < 8; ++i)
        aka.autn[8 + i] = milenage.mac_a.get(static_cast<int>(i));
    for (size_t i = 0; i < 8; ++i)
        aka.res[i] = milenage.res.get(static_cast<int>(i));
    return aka;
}

std::array<uint8_t, 32> DeriveKasme(const lte::ue::Config &config, const Aka &aka)
{
    const auto milenage = crypto::milenage::Calculate(Octets(*config.opc), Octets(config.key), Octets(aka.rand),
                                                      Octets(std::vector<uint8_t>(aka.sqn, aka.sqn + 6)),
                                                      Octets(config.amf));
    OctetString ckIk = OctetString::Concat(milenage.ck, milenage.ik);
    const auto sn = lte::enb::s1ap::EncodePlmn(config.plmn);
    OctetString parameters[2] = {Octets(sn), Octets(std::vector<uint8_t>(aka.autn.begin(), aka.autn.begin() + 6))};
    const auto kasme = crypto::CalculateKdfKey(ckIk, 0x10, parameters, 2);
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = kasme.get(static_cast<int>(i));
    return out;
}

std::vector<uint8_t> EncodeAuthenticationRequest(const Aka &aka)
{
    std::vector<uint8_t> out{0x07, 0x52, 0x00};
    out.insert(out.end(), aka.rand.begin(), aka.rand.end());
    out.push_back(16);
    out.insert(out.end(), aka.autn.begin(), aka.autn.end());
    return out;
}

std::vector<uint8_t> SecurityModeCommandPlain()
{
    // EEA0/EIA2, native KSI 0, replayed UE network capability.
    return {0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
}

// The GUTI this MME assigns in the Attach Accept. The UE sends it back in the
// Detach Request, so the peer builds the expected Detach Request from the same
// value instead of accepting any well-formed one.
const std::array<uint8_t, 11> AssignedGuti{0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01,
                                           0x01, 0x12, 0x34, 0x56, 0x78};

std::vector<uint8_t> AttachAcceptPlain()
{
    const std::vector<uint8_t> esm{0x52, 0x01, 0xC1, 0x01, 0x05, 0x09, 0x08, 0x69, 0x6E, 0x74,
                                   0x65, 0x72, 0x6E, 0x65, 0x74, 0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};
    // T3412=0x30 and the type-2 TAI list form a live MME sends: one PLMN
    // 460/02 and TAC 1, six content octets.
    std::vector<uint8_t> out{0x07, 0x42, 0x01, 0x30, 0x06, 0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
    out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esm.size()));
    out.insert(out.end(), esm.begin(), esm.end());
    // Optional GUTI (TS 24.301 9.9.3.12): IEI 0x50, length 11.
    out.push_back(0x50);
    out.push_back(0x0B);
    out.insert(out.end(), AssignedGuti.begin(), AssignedGuti.end());
    return out;
}

void WriteResult(const std::string &path, const std::string &text)
{
    std::ofstream out(path);
    out << text;
}

std::string Hex(const std::vector<uint8_t> &bytes)
{
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes)
    {
        out.push_back(digits[byte >> 4U]);
        out.push_back(digits[byte & 0x0FU]);
    }
    return out;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 5)
    {
        std::cerr << "usage: " << argv[0] << " <port> <ready-file> <result-file> [mode]" << std::endl;
        return 1;
    }
    const auto port = static_cast<uint16_t>(std::stoi(argv[1]));
    const std::string readyPath = argv[2];
    const std::string resultPath = argv[3];
    const std::string mode = argc == 5 ? argv[4] : "attach-only";
    const bool attachOnly = mode == "attach-only";
    const bool detachMode = mode == "attach-detach" || mode == "duplicate-attach-accept" ||
                            mode == "exit-on-detach" || mode == "bad-detach-mac" ||
                            mode == "duplicate-detach-accept";
    const bool pagingMode = mode == "paging" || mode == "paging-timeout" || mode == "paging-wrong-identity" ||
                            mode == "paging-peer-exit";
    const bool idleMode = mode == "service-request" || mode == "bad-service-mac" || pagingMode;
    const bool expectDetach = detachMode;
    const bool expectRelease = idleMode;
    if (!attachOnly && !detachMode && !idleMode)
    {
        WriteResult(resultPath, "result=FAILED\nreason=unknown mode " + mode + "\n");
        return 1;
    }

    std::string why;
    auto socket = lte::uu::Socket::Bind("127.0.0.1", port, &why);
    if (!socket)
    {
        WriteResult(resultPath, "result=FAILED\nreason=bind:" + why + "\n");
        std::cerr << "bind failed: " << why << std::endl;
        return 1;
    }

    lte::enb::EnbConfig enb{};
    enb.plmn = {"460", "02"};
    enb.enbId = 0x00ABCDE;
    enb.tac = 1;
    enb.localAddress = "127.0.0.1";
    enb.mmeAddress = "127.0.0.1";

    lte::enb::s1ap::EnbRrcBridge::Config bridgeConfig{};
    bridgeConfig.enb = enb;
    bridgeConfig.srb1.expectedPlmnIdentity = 1;
    auto &setup = bridgeConfig.srb1.setup;
    setup.transactionId = 0;
    setup.srbIdentity = 1;
    setup.tPollRetransmit = 2;
    setup.pollPdu = 7;
    setup.pollByte = 14;
    setup.maxRetxThreshold = 5;
    setup.tReordering = 1;
    setup.tStatusProhibit = 1;
    bridgeConfig.algorithms.ciphering.ordered = {2, 1, 0};
    bridgeConfig.algorithms.ciphering.generation = 5;
    bridgeConfig.algorithms.integrity.ordered = {2, 1, 0};
    bridgeConfig.algorithms.integrity.generation = 5;
    bridgeConfig.algorithms.nasIntegrityAlgorithm = 2;

    std::deque<std::vector<uint8_t>> s1ap;
    uint32_t nextEnbId = 0x100;
    uint32_t association = 0;
    auto bridge = std::make_unique<lte::enb::s1ap::EnbRrcBridge>(
        *socket, bridgeConfig,
        [&s1ap](uint32_t, const std::vector<uint8_t> &pdu) { s1ap.push_back(pdu); },
        [&nextEnbId]() { return nextEnbId++; },
        [&association](uint32_t id, uint32_t, uint16_t, const std::vector<uint8_t> &) { association = id; });

    {
        std::ofstream ready(readyPath);
        ready << "ready\n";
    }

    // Downlink NAS enters through the S1AP Downlink NAS Transport the owner
    // would deliver, so the bridge learns the MME identity exactly as it does
    // in production and its uplink path is not short-circuited.
    auto sendDownlinkNas = [&](const std::vector<uint8_t> &nas) {
        bridge->OnDownlinkNasTransport(lte::enb::s1ap::EncodeDownlinkNasTransport(
            0x4001, bridge->EnbUeS1apIdOf(association).value_or(0), nas));
    };

    const auto subscriber = Subscriber();
    const auto aka = RunMilenage(subscriber);
    const auto kasme = DeriveKasme(subscriber, aka);
    const auto authRequest = EncodeAuthenticationRequest(aka);
    const auto expectedAuthResponse = lte::ue::nas::EncodeAuthenticationResponse(aka.res);
    const auto expectedSmcComplete = lte::ue::nas::EncodeSecurityModeComplete(subscriber, false);
    const auto expectedAttachComplete =
        lte::ue::nas::EncodeAttachComplete(lte::ue::nas::EncodeActivateDefaultEpsBearerContextAccept(5, 1));
    // The production application sends a native-KSI, switch-off-clear EPS detach
    // for the GUTI it was assigned.
    const auto expectedDetachRequest = lte::ue::nas::EncodeDetachRequest(0, AssignedGuti, false);

    lte::ue::SecurityContext nas{};
    nas.valid = true;
    nas.keysDerived = true;
    nas.securityActive = true;
    nas.kasme = kasme;
    nas.integrity = lte::ue::IntegrityAlgorithm::EIA2;
    nas.ciphering = lte::ue::CipheringAlgorithm::EEA0;
    nas.ksi = 0;
    nas.kNasInt = lte::ue::nas::DeriveKnasInt(kasme, lte::ue::IntegrityAlgorithm::EIA2);
    nas.kNasEnc = lte::ue::nas::DeriveKnasEnc(kasme, lte::ue::CipheringAlgorithm::EEA0);
    nas.ulNasCount = 0;
    nas.dlNasCount = 0;

    enum class Stage
    {
        ATTACH,
        AUTH_RESPONSE,
        SMC_COMPLETE,
        ICS_SECURITY,
        ATTACH_COMPLETE,
        REGISTERED,
        RELEASED,
        SR_ICS,
        DONE,
        FAILED
    };
    Stage stage = Stage::ATTACH;
    std::string failure;
    size_t initialUeMessages = 0;
    size_t uplinkTransports = 0;
    std::vector<uint8_t> attachRequest;
    std::vector<uint8_t> detachRequestRaw;
    std::vector<uint8_t> detachProtectedRaw;
    bool authVerified = false;
    bool smcVerified = false;
    bool icsResponse = false;
    bool rrcAsSecurity = false;
    bool attachCompleteVerified = false;
    bool attachAcceptSent = false;
    bool detachVerified = false;
    bool detachAcceptSent = false;
    bool enbContextReleased = false;
    bool injectedCorruption = false;
    uint8_t lastUplinkSequence = 0;
    uint32_t detachUlCount = 0;
    uint32_t detachDlCount = 0;
    // ECM-IDLE restoration bookkeeping.
    bool releasePending = false;
    bool releaseCommandSent = false;
    bool releaseComplete = false;
    bool idleRetained = false;
    bool pagingSent = false;
    bool pagingWrongIdentity = false;
    bool serviceRequestVerified = false;
    bool injectedShortMac = false;
    bool contextRestored = false;
    std::vector<uint8_t> serviceRequestRaw;
    uint32_t serviceRequestCount = 0;
    uint8_t serviceRequestKsi = 0;
    auto releaseAt = Clock::now();
    auto pagingAt = Clock::now();

    auto fail = [&](const std::string &reason) {
        stage = Stage::FAILED;
        failure = reason;
    };

    auto verifyUplink = [&](const std::vector<uint8_t> &pdu) -> std::optional<std::vector<uint8_t>> {
        try
        {
            const auto parsed = lte::ue::nas::ParseProtectedHeader(pdu.data(), pdu.size());
            auto plain = lte::ue::nas::UnprotectBody(nas, true, parsed.headerType, parsed.sequenceNumber, parsed.mac,
                                                     parsed.plain);
            lastUplinkSequence = parsed.sequenceNumber;
            if (lte::ue::nas::StartsNewContext(parsed.headerType))
                nas.ulNasCount = parsed.sequenceNumber;
            else
                nas.ulNasCount = lte::ue::nas::EstimateNasCount(nas.ulNasCount, parsed.sequenceNumber);
            return plain;
        }
        catch (const std::exception &e)
        {
            fail(std::string("uplink NAS verification failed: ") + e.what());
            return std::nullopt;
        }
    };

    auto handleUplink = [&](const lte::enb::s1ap::UplinkNas &uplink) {
        const std::vector<uint8_t> &pdu = uplink.nasPdu;
        switch (stage)
        {
        case Stage::ATTACH:
        {
            attachRequest = pdu;
            if (pdu != lte::ue::nas::EncodeAttachRequest(subscriber))
                return fail("the Initial UE Message did not carry the production Attach Request");
            sendDownlinkNas(authRequest);
            stage = Stage::AUTH_RESPONSE;
            return;
        }
        case Stage::AUTH_RESPONSE:
        {
            if (pdu != expectedAuthResponse)
                return fail("the Authentication Response did not match the AKA result");
            authVerified = true;
            auto smc = lte::ue::nas::Protect(nas, false, true, SecurityModeCommandPlain(), false);
            nas.dlNasCount = 1;
            sendDownlinkNas(smc);
            stage = Stage::SMC_COMPLETE;
            return;
        }
        case Stage::SMC_COMPLETE:
        {
            const auto plain = verifyUplink(pdu);
            if (!plain.has_value())
                return;
            if (*plain != expectedSmcComplete)
                return fail("the Security Mode Complete did not match the production encoder");
            smcVerified = true;

            lte::enb::s1ap::InitialContextSetupRequest ics{};
            ics.mmeUeS1apId = 0x4001;
            ics.enbUeS1apId = bridge->EnbUeS1apIdOf(association).value_or(0);
            ics.ueAmbrUl = 100000000;
            ics.ueAmbrDl = 100000000;
            lte::enb::s1ap::ErabToBeSetupItem erab{};
            erab.erabId = 5;
            erab.qci = 9;
            erab.transportLayerAddress = {10, 0, 0, 1};
            erab.gtpTeid = {0x11, 0x22, 0x33, 0x44};
            ics.erabs.push_back(erab);
            ics.encryptionAlgorithms = {0xE0, 0x00};
            ics.integrityAlgorithms = {0xE0, 0x00};
            ics.securityKey = lte::security::DeriveKenb(kasme, nas.ulNasCount);
            bridge->OnInitialContextSetupRequest(lte::enb::s1ap::EncodeInitialContextSetupRequest(ics));
            stage = Stage::ICS_SECURITY;
            return;
        }
        case Stage::ATTACH_COMPLETE:
        {
            const auto plain = verifyUplink(pdu);
            if (!plain.has_value())
                return;
            if (*plain != expectedAttachComplete)
                return fail("the Attach Complete did not match the production encoder");
            attachCompleteVerified = true;
            if (attachOnly)
            {
                stage = Stage::DONE;
                return;
            }
            if (detachMode)
            {
                // D3/D4: the peer stays registered and waits for the UE to
                // detach the same session.
                stage = Stage::REGISTERED;
                return;
            }
            // D5: the network releases the access after a short controlled
            // delay, and the UE keeps its EPS registration and NAS context.
            releasePending = true;
            releaseAt = Clock::now() + std::chrono::milliseconds(120);
            stage = Stage::REGISTERED;
            return;
        }
        case Stage::REGISTERED:
        {
            const auto plain = verifyUplink(pdu);
            if (!plain.has_value())
                return;
            detachProtectedRaw = pdu;
            detachRequestRaw = *plain;
            detachUlCount = nas.ulNasCount;
            lte::ue::nas::DetachRequest decoded{};
            try
            {
                decoded = lte::ue::nas::DecodeDetachRequest(plain->data(), plain->size());
            }
            catch (const std::exception &e)
            {
                return fail(std::string("the Detach Request was not decodable: ") + e.what());
            }
            if (*plain != expectedDetachRequest)
                return fail("the Detach Request bytes differ from the production encoder");
            if (decoded.ksi != 0)
                return fail("the Detach Request carried a different KSI");
            if (decoded.switchOff)
                return fail("the Detach Request requested a switch-off this scenario did not ask for");
            if (decoded.guti != AssignedGuti)
                return fail("the Detach Request carried a different GUTI");
            // Security Mode Complete was UL COUNT 0 and Attach Complete 1, so the
            // Detach Request must be 2: the context is the same one, never reset.
            if (detachUlCount != 2)
                return fail("the Detach Request did not use the next uplink NAS COUNT");
            detachVerified = true;

            if (mode == "exit-on-detach")
                return fail("the peer exited during the Detach procedure (injected)");

            detachDlCount = nas.dlNasCount;
            auto accept = lte::ue::nas::Protect(nas, false, false, lte::ue::nas::EncodeDetachAccept(), false);
            nas.dlNasCount = (nas.dlNasCount + 1U) & 0xFFFFFFU;
            if (mode == "bad-detach-mac")
            {
                // Corrupt the first MAC octet: the UE must verify it and refuse,
                // never enter EMM_DEREGISTERED on an unverified message.
                accept[1] ^= 0x01U;
                sendDownlinkNas(accept);
                detachAcceptSent = true;
                injectedCorruption = true;
                return fail("the Detach Accept integrity was deliberately corrupted (injected)");
            }
            sendDownlinkNas(accept);
            if (mode == "duplicate-detach-accept")
                // The same protected bytes again: a replayed downlink COUNT.
                // The UE must complete the Detach once and release once.
                sendDownlinkNas(accept);
            detachAcceptSent = true;
            // A real MME releases the S1 UE context after a Detach. The peer
            // does the same through the bridge's association-loss path, so the
            // eNB-side release is observed rather than assumed.
            bridge->OnS1AssociationLost();
            enbContextReleased = !bridge->HasContext(association);
            stage = Stage::DONE;
            return;
        }
        case Stage::RELEASED:
        {
            // The compact EPS Service Request is the first NAS of the new RRC
            // connection. It is not a normal protected message: it carries the
            // KSI, a five-bit sequence and a two-octet short MAC.
            serviceRequestRaw = uplink.nasPdu;
            if (uplink.nasPdu.size() != 4 || uplink.nasPdu[0] != 0xC7)
                return fail("the Service Request is not the compact EPS Service Request");
            if (!uplink.sTmsi.has_value() || uplink.sTmsi->mmeCode != 1 || uplink.sTmsi->mTmsi != 0x12345678U)
                return fail("the Service Request did not name the retained S-TMSI");
            auto verificationCopy = uplink.nasPdu;
            if (mode == "bad-service-mac")
                // The MME receives tampered bytes: integrity must refuse them.
                verificationCopy[3] ^= 0x01U;
            try
            {
                lte::ue::nas::VerifyServiceRequest(nas, verificationCopy.data(), verificationCopy.size(),
                                                  nas.ulNasCount);
            }
            catch (const std::exception &e)
            {
                if (mode == "bad-service-mac")
                {
                    injectedShortMac = true;
                    return fail(std::string("the injected Service Request short MAC was refused: ") + e.what());
                }
                return fail(std::string("the Service Request short MAC was refused: ") + e.what());
            }
            serviceRequestKsi = static_cast<uint8_t>(uplink.nasPdu[1] >> 5U);
            serviceRequestCount = lte::ue::nas::EstimateServiceRequestCount(
                nas.ulNasCount, static_cast<uint8_t>(uplink.nasPdu[1] & 0x1FU));
            if (serviceRequestCount <= nas.ulNasCount)
                return fail("the Service Request did not advance the uplink NAS COUNT");
            nas.ulNasCount = serviceRequestCount;
            serviceRequestVerified = true;

            lte::enb::s1ap::InitialContextSetupRequest ics{};
            ics.mmeUeS1apId = 0x4001;
            ics.enbUeS1apId = uplink.enbUeS1apId;
            ics.ueAmbrUl = 100000000;
            ics.ueAmbrDl = 100000000;
            lte::enb::s1ap::ErabToBeSetupItem erab{};
            erab.erabId = 5;
            erab.qci = 9;
            erab.transportLayerAddress = {10, 0, 0, 1};
            erab.gtpTeid = {0x11, 0x22, 0x33, 0x44};
            ics.erabs.push_back(erab);
            ics.encryptionAlgorithms = {0xE0, 0x00};
            ics.integrityAlgorithms = {0xE0, 0x00};
            // TS 33.401 7.2.1: the new KeNB follows the Service Request's
            // uplink NAS COUNT.
            ics.securityKey = lte::security::DeriveKenb(kasme, serviceRequestCount);
            bridge->OnInitialContextSetupRequest(lte::enb::s1ap::EncodeInitialContextSetupRequest(ics));
            stage = Stage::SR_ICS;
            return;
        }
        case Stage::SR_ICS:
        {
            const auto plain = verifyUplink(pdu);
            if (!plain.has_value())
                return;
            return fail("unexpected uplink NAS while restoring the AS security context");
        }
        case Stage::ICS_SECURITY:
        case Stage::DONE:
        case Stage::FAILED:
            return fail("unexpected uplink NAS for the current stage");
        }
    };

    const auto deadline = Clock::now() + std::chrono::seconds(30);
    while (Clock::now() < deadline && stage != Stage::DONE && stage != Stage::FAILED)
    {
        bridge->Pump(5);
        bridge->Tick();
        while (!s1ap.empty())
        {
            auto pdu = std::move(s1ap.front());
            s1ap.pop_front();
            try
            {
                const auto uplink = lte::enb::s1ap::DecodeUplinkNas(pdu.data(), pdu.size());
                const bool initial = !uplink.mmeUeS1apId.has_value();
                if (initial)
                    ++initialUeMessages;
                else
                    ++uplinkTransports;
                handleUplink(uplink);
            }
            catch (const std::exception &)
            {
                // Not a NAS-carrying S1AP message. The release complete is the
                // one this peer must observe.
                try
                {
                    const auto complete = lte::enb::s1ap::DecodeUeContextReleaseComplete(pdu.data(), pdu.size());
                    if (complete.mmeUeS1apId == 0x4001)
                        releaseComplete = true;
                }
                catch (const std::exception &)
                {
                    // The Initial Context Setup Response this peer itself caused.
                }
            }
        }
        if (stage == Stage::REGISTERED && releasePending && Clock::now() >= releaseAt)
        {
            releasePending = false;
            const auto enbUeS1apId = bridge->EnbUeS1apIdOf(association);
            if (!enbUeS1apId.has_value())
                fail("the eNB holds no radio context to release");
            else
            {
                try
                {
                    bridge->OnUeContextReleaseCommand(lte::enb::s1ap::EncodeUeContextReleaseCommand(
                        0x4001, *enbUeS1apId, "nas", 0));
                    releaseCommandSent = true;
                    idleRetained = bridge->IdleUes() == 1;
                    stage = Stage::RELEASED;
                    pagingAt = Clock::now() + std::chrono::milliseconds(120);
                }
                catch (const std::exception &e)
                {
                    fail(std::string("the RRC/S1 release failed: ") + e.what());
                }
            }

            if (stage == Stage::RELEASED)
            {
                if (mode == "paging-timeout")
                    fail("no Paging was sent (injected)");
                else if (mode == "paging-wrong-identity")
                {
                    pagingWrongIdentity = true;
                    pagingSent = bridge->PageUe(lte::enb::s1ap::STmsi{1, 0xDEADBEEFu});
                    fail("a Paging for a different S-TMSI was sent (injected)");
                }
                else if (mode == "paging-peer-exit")
                {
                    pagingSent = bridge->PageUe(lte::enb::s1ap::STmsi{1, 0x12345678U});
                    fail("the peer exited after Paging (injected)");
                }
            }
        }

        if (stage == Stage::RELEASED && (mode == "paging") && !pagingSent && Clock::now() >= pagingAt)
        {
            pagingSent = bridge->PageUe(lte::enb::s1ap::STmsi{1, 0x12345678U});
            if (!pagingSent)
                fail("the retained idle UE was not found for Paging");
        }

        if (stage == Stage::SR_ICS && bridge->AsSecurityActive(association))
        {
            std::vector<lte::enb::s1ap::ErabSetupItem> established;
            established.push_back({5, {10, 0, 0, 1}, {0x11, 0x22, 0x33, 0x44}});
            bridge->CompleteInitialContextSetup(association, established);
            contextRestored = true;
            rrcAsSecurity = true;
            stage = Stage::DONE;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        if (stage == Stage::ICS_SECURITY && bridge->AsSecurityActive(association))
        {
            std::vector<lte::enb::s1ap::ErabSetupItem> established;
            established.push_back({5, {10, 0, 0, 1}, {0x11, 0x22, 0x33, 0x44}});
            bridge->CompleteInitialContextSetup(association, established);
            icsResponse = true;
            rrcAsSecurity = bridge->AsSecurityActive(association);
            auto accept = lte::ue::nas::Protect(nas, false, false, AttachAcceptPlain(), false);
            nas.dlNasCount = (nas.dlNasCount + 1U) & 0xFFFFFFU;
            sendDownlinkNas(accept);
            if (mode == "duplicate-attach-accept")
                // The same protected bytes again: a duplicate downlink with a
                // replayed COUNT. The UE must drop it and must not repeat the
                // Attach Complete or disturb the session.
                sendDownlinkNas(accept);
            attachAcceptSent = true;
            stage = Stage::ATTACH_COMPLETE;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (stage != Stage::DONE && stage != Stage::FAILED)
        fail(expectDetach ? "timed out before the Attach to Detach lifecycle completed"
                          : (expectRelease ? "timed out before the ECM-IDLE access restoration completed"
                                           : "timed out before the Attach exchange completed"));

    std::ostringstream result;
    result << "result=" << (stage == Stage::DONE ? "COMPLETE" : (injectedCorruption ? "INJECTED" : "FAILED")) << "\n";
    if (!failure.empty())
        result << "reason=" << failure << "\n";
    result << "mode=" << mode << "\n";
    result << "initial_ue_messages=" << initialUeMessages << "\n";
    result << "uplink_nas_transports=" << uplinkTransports << "\n";
    result << "attach_request=" << Hex(attachRequest) << "\n";
    result << "auth_response_verified=" << (authVerified ? 1 : 0) << "\n";
    result << "smc_complete_verified=" << (smcVerified ? 1 : 0) << "\n";
    result << "ics_response=" << (icsResponse ? 1 : 0) << "\n";
    result << "rrc_as_security=" << (rrcAsSecurity ? 1 : 0) << "\n";
    result << "attach_complete_verified=" << (attachCompleteVerified ? 1 : 0) << "\n";
    result << "attach_accept_sent=" << (attachAcceptSent ? 1 : 0) << "\n";
    result << "detach_request=" << Hex(detachRequestRaw) << "\n";
    result << "detach_protected_bytes=" << detachProtectedRaw.size() << "\n";
    result << "detach_request_verified=" << (detachVerified ? 1 : 0) << "\n";
    result << "detach_ul_count=" << detachUlCount << "\n";
    result << "detach_dl_count=" << detachDlCount << "\n";
    result << "detach_accept_sent=" << (detachAcceptSent ? 1 : 0) << "\n";
    result << "enb_context_released=" << (enbContextReleased ? 1 : 0) << "\n";
    result << "injected_corruption=" << (injectedCorruption ? 1 : 0) << "\n";
    result << "release_command_sent=" << (releaseCommandSent ? 1 : 0) << "\n";
    result << "release_complete=" << (releaseComplete ? 1 : 0) << "\n";
    result << "idle_retained=" << (idleRetained ? 1 : 0) << "\n";
    result << "paging_sent=" << (pagingSent ? 1 : 0) << "\n";
    result << "paging_wrong_identity=" << (pagingWrongIdentity ? 1 : 0) << "\n";
    result << "service_request=" << Hex(serviceRequestRaw) << "\n";
    result << "service_request_verified=" << (serviceRequestVerified ? 1 : 0) << "\n";
    result << "sr_ksi=" << static_cast<int>(serviceRequestKsi) << "\n";
    result << "sr_count=" << serviceRequestCount << "\n";
    result << "injected_bad_service_mac=" << (injectedShortMac ? 1 : 0) << "\n";
    result << "context_restored=" << (contextRestored ? 1 : 0) << "\n";
    result << "ecm_connected=" << (contextRestored ? 1 : 0) << "\n";
    result << "idle_ues=" << bridge->IdleUes() << "\n";
    WriteResult(resultPath, result.str());
    return stage == Stage::DONE ? 0 : 1;
}
