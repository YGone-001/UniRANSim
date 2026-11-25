//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// Phase 18-F-B6-D7: the production eNB + deterministic MME user-plane peer.
//
// Process 2 of the acceptance. It owns the production EnbMultiplexer (Uu/SRB1
// bridge, DRB runtime, S1-U GTP-U endpoint) and a deterministic MME that runs
// EPS AKA, NAS security, the Attach, the Initial Context Setup, the UE Context
// Release and the Service Request restoration. The MME is not an EPC: it talks
// to the eNB through the same S1AP codec a real MME would, and it writes the
// bearer map the deterministic SGW-U/PGW-U process installs.
//
// Usage:
//   lte-uu-user-plane-peer --uu-port <p> --s1u-address <veth-ip>
//     --sgw-address <veth-ip> [--sgw-port 2152] [--s1u-port 2152]
//     --ue-ip <ipv4> [--ebi 5] [--qci 9]
//     --map-file <path> --ready-file <path> --result-file <path>
//     --release-file <path> [--stop-file <path>] [--no-release]
#include <lte/enb/codec.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/security/as_security.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/security.hpp>
#include <lte/ue/types.hpp>

#include <lib/crypt/crypt.hpp>
#include <lib/crypt/milenage.hpp>
#include <utils/octet_string.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <csignal>
#include <cstdint>
#include <cstdio>
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
using lte::enb::EnbMultiplexer;
using namespace lte::enb::s1ap;

std::atomic_bool g_stop{false};
void Signal(int) { g_stop = true; }

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
    config.op = config.opc;
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
    const auto sn = EncodePlmn(config.plmn);
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
    return {0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
}

const std::array<uint8_t, 11> AssignedGuti{0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01,
                                           0x01, 0x12, 0x34, 0x56, 0x78};

std::vector<uint8_t> ActivateDefaultEsm(uint8_t ebi, uint8_t qci, const std::array<uint8_t, 4> &ueIpv4)
{
    // ESM header: EPS bearer identity in the high nibble, PTI below, then the
    // message type. The QoS byte is the same QCI the E-RAB carries.
    std::vector<uint8_t> esm{static_cast<uint8_t>(static_cast<uint8_t>(ebi << 4U) | 0x02U), 0x01, 0xC1, 0x01, qci,
                             0x09, 0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't', 0x05, 0x01};
    esm.insert(esm.end(), ueIpv4.begin(), ueIpv4.end());
    return esm;
}

std::vector<uint8_t> AttachAcceptPlain(uint8_t ebi, uint8_t qci, const std::array<uint8_t, 4> &ueIpv4)
{
    const auto esm = ActivateDefaultEsm(ebi, qci, ueIpv4);
    std::vector<uint8_t> out{0x07, 0x42, 0x01, 0x30, 0x06, 0x40, 0x64, 0xF0, 0x20, 0x00, 0x01};
    out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esm.size()));
    out.insert(out.end(), esm.begin(), esm.end());
    out.push_back(0x50);
    out.push_back(0x0B);
    out.insert(out.end(), AssignedGuti.begin(), AssignedGuti.end());
    return out;
}

void WriteFile(const std::string &path, const std::string &text)
{
    std::ofstream out(path);
    out << text;
}

void WriteAtomically(const std::string &path, const std::string &text)
{
    const std::string temporary = path + ".tmp";
    WriteFile(temporary, text);
    std::rename(temporary.c_str(), path.c_str());
}

std::array<uint8_t, 4> ParseIpv4(const std::string &text)
{
    std::array<uint8_t, 4> address{};
    std::istringstream stream(text);
    std::string part;
    int index = 0;
    while (std::getline(stream, part, '.'))
    {
        if (index >= 4)
            throw std::runtime_error("invalid IPv4 address: " + text);
        const int value = std::stoi(part);
        if (value < 0 || value > 255)
            throw std::runtime_error("invalid IPv4 address: " + text);
        address[index++] = static_cast<uint8_t>(value);
    }
    if (index != 4)
        throw std::runtime_error("invalid IPv4 address: " + text);
    return address;
}

std::array<uint8_t, 4> TeidBytes(uint32_t value)
{
    return {static_cast<uint8_t>(value >> 24U), static_cast<uint8_t>(value >> 16U),
            static_cast<uint8_t>(value >> 8U), static_cast<uint8_t>(value)};
}

uint32_t TeidValue(const std::array<uint8_t, 4> &bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24U) | (static_cast<uint32_t>(bytes[1]) << 16U) |
           (static_cast<uint32_t>(bytes[2]) << 8U) | static_cast<uint32_t>(bytes[3]);
}

struct Sender : lte::enb::IS1apSender
{
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override { queue.push_back(pdu); }
    std::deque<std::vector<uint8_t>> queue;
};

struct Options
{
    uint16_t uuPort{0};
    std::string s1uAddress;
    uint16_t s1uPort{2152};
    std::string sgwAddress;
    uint16_t sgwPort{2152};
    std::array<uint8_t, 4> ueIpv4{};
    uint8_t ebi{5};
    uint8_t qci{9};
    std::string mapPath;
    std::string readyPath;
    std::string resultPath;
    std::string releasePath;
    std::string stopPath;
    bool noRelease{false};
};

} // namespace

int main(int argc, char **argv)
{
    Options options;
    try
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string arg = argv[i];
            auto next = [&]() -> std::string {
                if (i + 1 >= argc)
                    throw std::runtime_error("missing value for " + arg);
                return argv[++i];
            };
            if (arg == "--uu-port")
                options.uuPort = static_cast<uint16_t>(std::stoi(next()));
            else if (arg == "--s1u-address")
                options.s1uAddress = next();
            else if (arg == "--s1u-port")
                options.s1uPort = static_cast<uint16_t>(std::stoi(next()));
            else if (arg == "--sgw-address")
                options.sgwAddress = next();
            else if (arg == "--sgw-port")
                options.sgwPort = static_cast<uint16_t>(std::stoi(next()));
            else if (arg == "--ue-ip")
                options.ueIpv4 = ParseIpv4(next());
            else if (arg == "--ebi")
                options.ebi = static_cast<uint8_t>(std::stoi(next()));
            else if (arg == "--qci")
                options.qci = static_cast<uint8_t>(std::stoi(next()));
            else if (arg == "--map-file")
                options.mapPath = next();
            else if (arg == "--ready-file")
                options.readyPath = next();
            else if (arg == "--result-file")
                options.resultPath = next();
            else if (arg == "--release-file")
                options.releasePath = next();
            else if (arg == "--stop-file")
                options.stopPath = next();
            else if (arg == "--no-release")
                options.noRelease = true;
            else
                throw std::runtime_error("unknown argument " + arg);
        }
        if (options.uuPort == 0 || options.s1uAddress.empty() || options.sgwAddress.empty() ||
            options.ueIpv4 == std::array<uint8_t, 4>{} || options.mapPath.empty() || options.readyPath.empty() ||
            options.resultPath.empty())
            throw std::runtime_error("missing a required argument");
        if (options.ebi < 5 || options.ebi > 15 || options.qci < 5 || options.qci > 9)
            throw std::runtime_error("the controlled profile requires EBI 5..15 and a non-GBR QCI");
    }
    catch (const std::exception &e)
    {
        std::cerr << "lte-uu-user-plane-peer: " << e.what() << std::endl;
        return 1;
    }

    try
    {
        std::signal(SIGINT, Signal);
        std::signal(SIGTERM, Signal);
        lte::enb::EnbConfig config{};
        config.plmn = {"460", "02"};
        config.enbId = 1;
        config.tac = 1;
        config.localAddress = "127.0.0.1";
        config.mmeAddress = "127.0.0.1";
        config.ueLinkAddress = "127.0.0.1";
        config.ueLinkPort = 0;
        config.uuAddress = "127.0.0.1";
        config.uuPort = options.uuPort;
        config.s1uAddress = options.s1uAddress;
        config.s1uPort = options.s1uPort;
        config.allowLoopbackS1u = false;
        config.maxUes = 4;

        Sender sender;
        EnbMultiplexer mux(config, sender);

        const auto subscriber = Subscriber();
        const auto aka = RunMilenage(subscriber);
        const auto kasme = DeriveKasme(subscriber, aka);
        const auto authRequest = EncodeAuthenticationRequest(aka);
        const auto expectedAuthResponse = lte::ue::nas::EncodeAuthenticationResponse(aka.res);
        const auto expectedSmcComplete = lte::ue::nas::EncodeSecurityModeComplete(subscriber, false);
        const auto expectedAttachComplete = lte::ue::nas::EncodeAttachComplete(
            lte::ue::nas::EncodeActivateDefaultEpsBearerContextAccept(options.ebi, 1));
        constexpr uint32_t MME_UE_ID = 0x4001;
        constexpr uint32_t SGW_TEID_GENERATION_1 = 0x51000001U;
        constexpr uint32_t SGW_TEID_GENERATION_2 = 0x52000002U;

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
            ICS_PENDING,
            REGISTERED,
            RELEASING,
            RELEASED,
            SR_ICS_PENDING,
            RESTORED,
            FAILED
        };
        Stage stage = Stage::ATTACH;
        std::string failure;
        uint32_t enbUeS1apId = 0;
        bool registered = false;
        bool attachCompleteVerified = false;
        bool releaseRequested = false;
        bool releaseComplete = false;
        bool serviceRequestVerified = false;
        bool contextRestored = false;
        uint64_t selectedGeneration = 0;
        uint32_t activeEnbTeid = 0;
        uint32_t activeSgwTeid = 0;
        uint32_t serviceRequestCount = 0;
        size_t icsResponses = 0;
        size_t initialUeMessages = 0;
        size_t uplinkTransports = 0;
        auto registeredAt = Clock::now();
        auto lastResult = Clock::now() - std::chrono::hours(1);

        auto fail = [&](const std::string &reason) {
            if (stage != Stage::FAILED)
            {
                stage = Stage::FAILED;
                failure = reason;
            }
        };

        auto writeBearerMap = [&](uint64_t generation, uint32_t sgwTeid, uint32_t enbTeid) {
            std::ostringstream map;
            map << "generation=" << generation << "\n";
            map << "ue_ip=" << static_cast<int>(options.ueIpv4[0]) << "." << static_cast<int>(options.ueIpv4[1]) << "."
                << static_cast<int>(options.ueIpv4[2]) << "." << static_cast<int>(options.ueIpv4[3]) << "\n";
            map << "ebi=" << static_cast<int>(options.ebi) << "\n";
            map << "sgw_teid=" << sgwTeid << "\n";
            map << "enb_teid=" << enbTeid << "\n";
            map << "enb_address=" << options.s1uAddress << "\n";
            map << "enb_port=" << options.s1uPort << "\n";
            WriteAtomically(options.mapPath, map.str());
        };

        auto sendIcs = [&](Stage next, uint32_t sgwTeid, bool withAttachAccept) {
            InitialContextSetupRequest ics{};
            ics.mmeUeS1apId = MME_UE_ID;
            ics.enbUeS1apId = enbUeS1apId;
            ics.ueAmbrUl = 100000000;
            ics.ueAmbrDl = 100000000;
            ErabToBeSetupItem erab{};
            erab.erabId = options.ebi;
            erab.qci = options.qci;
            erab.transportLayerAddress = ParseIpv4(options.sgwAddress);
            erab.gtpTeid = TeidBytes(sgwTeid);
            ics.erabs.push_back(erab);
            ics.encryptionAlgorithms = {0xE0, 0x00};
            ics.integrityAlgorithms = {0xE0, 0x00};
            ics.securityKey = lte::security::DeriveKenb(kasme, nas.ulNasCount);
            if (withAttachAccept)
            {
                const auto plain = AttachAcceptPlain(options.ebi, options.qci, options.ueIpv4);
                ics.nasPdu = lte::ue::nas::Protect(nas, false, false, plain, false);
                nas.dlNasCount = (nas.dlNasCount + 1U) & 0xFFFFFFU;
                ics.nasPduPresent = true;
            }
            const auto pdu = EncodeInitialContextSetupRequest(ics);
            mux.handleS1ap(pdu.data(), pdu.size(), 1);
            stage = next;
        };

        auto verifyUplink = [&](const std::vector<uint8_t> &pdu) -> std::optional<std::vector<uint8_t>> {
            try
            {
                const auto parsed = lte::ue::nas::ParseProtectedHeader(pdu.data(), pdu.size());
                auto plain = lte::ue::nas::UnprotectBody(nas, true, parsed.headerType, parsed.sequenceNumber,
                                                         parsed.mac, parsed.plain);
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

        auto handleUplinkNas = [&](const UplinkNas &uplink) {
            const std::vector<uint8_t> &pdu = uplink.nasPdu;
            const bool initial = !uplink.mmeUeS1apId.has_value();
            if (initial)
            {
                enbUeS1apId = uplink.enbUeS1apId;
                ++initialUeMessages;
                if (stage == Stage::ATTACH)
                {
                    if (pdu != lte::ue::nas::EncodeAttachRequest(subscriber))
                        return fail("the Initial UE Message did not carry the production Attach Request");
                    // The Authentication Request precedes NAS security and is
                    // therefore sent in the clear.
                    const auto downlink = EncodeDownlinkNasTransport(MME_UE_ID, enbUeS1apId, authRequest);
                    mux.handleS1ap(downlink.data(), downlink.size(), 1);
                    stage = Stage::AUTH_RESPONSE;
                    return;
                }
                if (stage == Stage::RELEASED)
                {
                    if (!uplink.sTmsi.has_value() || uplink.sTmsi->mmeCode != 1 || uplink.sTmsi->mTmsi != 0x12345678U)
                        return fail("the Service Request did not name the retained S-TMSI");
                    if (uplink.nasPdu.size() != 4 || uplink.nasPdu[0] != 0xC7)
                        return fail("the reconnection did not carry the compact EPS Service Request");
                    try
                    {
                        lte::ue::nas::VerifyServiceRequest(nas, uplink.nasPdu.data(), uplink.nasPdu.size(),
                                                          nas.ulNasCount);
                    }
                    catch (const std::exception &e)
                    {
                        return fail(std::string("the Service Request short MAC was refused: ") + e.what());
                    }
                    serviceRequestCount = lte::ue::nas::EstimateServiceRequestCount(
                        nas.ulNasCount, static_cast<uint8_t>(uplink.nasPdu[1] & 0x1FU));
                    if (serviceRequestCount <= nas.ulNasCount)
                        return fail("the Service Request did not advance the uplink NAS COUNT");
                    nas.ulNasCount = serviceRequestCount;
                    serviceRequestVerified = true;
                    sendIcs(Stage::SR_ICS_PENDING, SGW_TEID_GENERATION_2, false);
                    return;
                }
                return fail("an Initial UE Message arrived in an unexpected state");
            }
            ++uplinkTransports;
            switch (stage)
            {
            case Stage::AUTH_RESPONSE:
            {
                if (pdu != expectedAuthResponse)
                    return fail("the Authentication Response did not match the AKA result");
                const auto smc = lte::ue::nas::Protect(nas, false, true, SecurityModeCommandPlain(), false);
                const auto downlink = EncodeDownlinkNasTransport(MME_UE_ID, enbUeS1apId, smc);
                mux.handleS1ap(downlink.data(), downlink.size(), 1);
                nas.dlNasCount = 1;
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
                sendIcs(Stage::ICS_PENDING, SGW_TEID_GENERATION_1, true);
                return;
            }
            case Stage::ICS_PENDING:
            case Stage::REGISTERED:
            {
                const auto plain = verifyUplink(pdu);
                if (!plain.has_value())
                    return;
                if (*plain != expectedAttachComplete)
                    return fail("the Attach Complete did not match the production encoder");
                attachCompleteVerified = true;
                registered = true;
                registeredAt = Clock::now();
                if (stage != Stage::REGISTERED)
                    stage = Stage::REGISTERED;
                return;
            }
            default:
                return fail("unexpected uplink NAS for the current stage");
            }
        };

        auto handleS1ap = [&](const std::vector<uint8_t> &pdu) {
            try
            {
                handleUplinkNas(DecodeUplinkNas(pdu.data(), pdu.size()));
                return;
            }
            catch (const CodecError &)
            {
            }
            try
            {
                const auto response = DecodeInitialContextSetupResponse(pdu.data(), pdu.size());
                if (response.mmeUeS1apId != MME_UE_ID || response.enbUeS1apId != enbUeS1apId ||
                    response.established.empty())
                    return fail("the Initial Context Setup Response does not match this transaction");
                const auto &item = response.established.front();
                if (item.erabId != options.ebi)
                    return fail("the Initial Context Setup Response established a different E-RAB");
                const uint32_t enbTeid = TeidValue(item.gtpTeid);
                if (enbTeid == 0)
                    return fail("the Initial Context Setup Response names no eNB TEID");
                activeEnbTeid = enbTeid;
                if (stage == Stage::ICS_PENDING)
                {
                    selectedGeneration = 1;
                    activeSgwTeid = SGW_TEID_GENERATION_1;
                }
                else if (stage == Stage::SR_ICS_PENDING)
                {
                    selectedGeneration = 2;
                    activeSgwTeid = SGW_TEID_GENERATION_2;
                    contextRestored = true;
                    stage = Stage::RESTORED;
                }
                else
                    return fail("an Initial Context Setup Response arrived in an unexpected state");
                writeBearerMap(selectedGeneration, activeSgwTeid, enbTeid);
                ++icsResponses;
                return;
            }
            catch (const CodecError &)
            {
            }
            try
            {
                const auto complete = DecodeUeContextReleaseComplete(pdu.data(), pdu.size());
                if (complete.mmeUeS1apId == MME_UE_ID && complete.enbUeS1apId == enbUeS1apId && stage == Stage::RELEASING)
                {
                    releaseComplete = true;
                    stage = Stage::RELEASED;
                }
                return;
            }
            catch (const CodecError &)
            {
            }
            // Other S1AP traffic (none is expected from this eNB) is ignored.
        };

        WriteFile(options.readyPath, "ready\nuu=" + std::to_string(options.uuPort) + "\ns1u=" + options.s1uAddress +
                                         ":" + std::to_string(options.s1uPort) + "\n");

        const auto deadline = Clock::now() + std::chrono::seconds(120);
        auto drbTraceNext = Clock::now() + std::chrono::seconds(1);
        while (!g_stop && Clock::now() < deadline)
        {
            if (!options.stopPath.empty() && std::ifstream(options.stopPath).good())
                break;
            mux.poll(16, 16);
            while (!sender.queue.empty())
            {
                auto pdu = std::move(sender.queue.front());
                sender.queue.pop_front();
                handleS1ap(pdu);
            }
            if (!options.noRelease && registered && !releaseRequested && !releaseComplete && stage == Stage::REGISTERED &&
                Clock::now() - registeredAt >= std::chrono::milliseconds(500) && !options.releasePath.empty() &&
                std::ifstream(options.releasePath).good())
            {
                releaseRequested = true;
                try
                {
                    const auto release = EncodeUeContextReleaseCommand(MME_UE_ID, enbUeS1apId, "nas", 0);
                    mux.handleS1ap(release.data(), release.size(), 1);
                    stage = Stage::RELEASING;
                }
                catch (const std::exception &e)
                {
                    fail(std::string("the release command failed: ") + e.what());
                }
            }
            if (stage == Stage::FAILED)
                break;
            const auto now = Clock::now();
            if (std::getenv("UNIRANSIM_DRB_TRACE") != nullptr && now >= drbTraceNext)
            {
                drbTraceNext = now + std::chrono::seconds(1);
                if (const auto *drbs = mux.uuDrbs(46001); drbs != nullptr)
                {
                    if (const auto *bearer = drbs->Bearer(options.ebi); bearer != nullptr)
                    {
                        const auto &rlc = bearer->Rlc();
                        std::cout << "DRB trace(enb): state=" << lte::rlc::am::ToString(rlc.State())
                                  << " sn(vta/vts/vrr)=" << rlc.VtA() << "/" << rlc.VtS() << "/" << rlc.VrR()
                                  << " outstanding=" << rlc.OutstandingPdus()
                                  << " tx/retx=" << rlc.Transmissions() << "/" << rlc.Retransmissions()
                                  << " status-s/r=" << rlc.StatusSent() << "/" << rlc.StatusReceived()
                                  << " poll-s/r=" << rlc.PollsSent() << "/" << rlc.PollsReceived()
                                  << " oow=" << rlc.DroppedOutOfWindow()
                                  << " failed-sn=" << rlc.FailedSn() << std::endl;
                    }
                }
            }
            if (now - lastResult >= std::chrono::milliseconds(200))
            {
                lastResult = now;
                std::ostringstream out;
                out << "stage=";
                switch (stage)
                {
                case Stage::ATTACH: out << "ATTACH"; break;
                case Stage::AUTH_RESPONSE: out << "AUTH_RESPONSE"; break;
                case Stage::SMC_COMPLETE: out << "SMC_COMPLETE"; break;
                case Stage::ICS_PENDING: out << "ICS_PENDING"; break;
                case Stage::REGISTERED: out << "REGISTERED"; break;
                case Stage::RELEASING: out << "RELEASING"; break;
                case Stage::RELEASED: out << "RELEASED"; break;
                case Stage::SR_ICS_PENDING: out << "SR_ICS_PENDING"; break;
                case Stage::RESTORED: out << "RESTORED"; break;
                case Stage::FAILED: out << "FAILED"; break;
                }
                out << "\nregistered=" << (registered ? 1 : 0) << "\n";
                out << "attach_complete_verified=" << (attachCompleteVerified ? 1 : 0) << "\n";
                out << "ics_responses=" << icsResponses << "\n";
                out << "initial_ue_messages=" << initialUeMessages << "\n";
                out << "uplink_nas_transports=" << uplinkTransports << "\n";
                out << "release_requested=" << (releaseRequested ? 1 : 0) << "\n";
                out << "release_complete=" << (releaseComplete ? 1 : 0) << "\n";
                out << "service_request_verified=" << (serviceRequestVerified ? 1 : 0) << "\n";
                out << "service_request_count=" << serviceRequestCount << "\n";
                out << "context_restored=" << (contextRestored ? 1 : 0) << "\n";
                out << "map_generation=" << selectedGeneration << "\n";
                out << "active_sgw_teid=" << activeSgwTeid << "\n";
                out << "active_enb_teid=" << activeEnbTeid << "\n";
                out << "ue_ip=" << static_cast<int>(options.ueIpv4[0]) << "." << static_cast<int>(options.ueIpv4[1])
                    << "." << static_cast<int>(options.ueIpv4[2]) << "." << static_cast<int>(options.ueIpv4[3])
                    << "\n";
                out << "ebi=" << static_cast<int>(options.ebi) << "\n";
                if (const auto *drbs = mux.uuDrbs(46001); drbs != nullptr)
                {
                    const auto *bearer = drbs->Bearer(options.ebi);
                    if (bearer != nullptr)
                    {
                        const auto &rlc = bearer->Rlc();
                        out << "rlc_transmissions=" << rlc.Transmissions() << "\n";
                        out << "rlc_retransmissions=" << rlc.Retransmissions() << "\n";
                        out << "rlc_dropped_out_of_window=" << rlc.DroppedOutOfWindow() << "\n";
                        out << "rlc_vta=" << rlc.VtA() << "\n";
                        out << "rlc_vts=" << rlc.VtS() << "\n";
                        out << "rlc_vrr=" << rlc.VrR() << "\n";
                        out << "rlc_state=" << static_cast<int>(rlc.State()) << "\n";
                    }
                }
                if (!failure.empty())
                    out << "failure=" << failure << "\n";
                WriteFile(options.resultPath, out.str());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        if (failure.empty() && (!registered || (!options.noRelease && (!releaseComplete || !contextRestored))))
            failure = "the lifecycle ended before the registered/restored state was reached";
        std::ostringstream result;
        result << (failure.empty() ? "result=COMPLETE" : "result=FAILED") << "\n";
        if (!failure.empty())
            result << "failure=" << failure << "\n";
        result << "registered=" << (registered ? 1 : 0) << "\n";
        result << "attach_complete_verified=" << (attachCompleteVerified ? 1 : 0) << "\n";
        result << "ics_responses=" << icsResponses << "\n";
        result << "release_complete=" << (releaseComplete ? 1 : 0) << "\n";
        result << "service_request_verified=" << (serviceRequestVerified ? 1 : 0) << "\n";
        result << "context_restored=" << (contextRestored ? 1 : 0) << "\n";
        result << "map_generation=" << selectedGeneration << "\n";
        result << "active_sgw_teid=" << activeSgwTeid << "\n";
        result << "active_enb_teid=" << activeEnbTeid << "\n";
        if (const auto *drbs = mux.uuDrbs(46001); drbs != nullptr)
        {
            if (const auto *bearer = drbs->Bearer(options.ebi); bearer != nullptr)
            {
                const auto &rlc = bearer->Rlc();
                result << "rlc_transmissions=" << rlc.Transmissions() << "\n";
                result << "rlc_retransmissions=" << rlc.Retransmissions() << "\n";
                result << "rlc_dropped_out_of_window=" << rlc.DroppedOutOfWindow() << "\n";
                result << "rlc_vta=" << rlc.VtA() << "\n";
                result << "rlc_vts=" << rlc.VtS() << "\n";
                result << "rlc_vrr=" << rlc.VrR() << "\n";
                result << "rlc_state=" << static_cast<int>(rlc.State()) << "\n";
            }
        }
        WriteFile(options.resultPath, result.str());
        mux.shutdown();
        std::cout << "lte-uu-user-plane-peer: " << (failure.empty() ? "complete" : failure)
                  << " stage=" << static_cast<int>(stage) << " ics=" << icsResponses << std::endl;
        return failure.empty() ? 0 : 1;
    }
    catch (const std::exception &e)
    {
        WriteFile(options.resultPath, std::string("result=FAILED\nfailure=") + e.what() + "\n");
        std::cerr << "lte-uu-user-plane-peer: " << e.what() << std::endl;
        return 1;
    }
}
