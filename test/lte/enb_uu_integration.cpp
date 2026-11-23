//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D1: one production EnbMultiplexer managing two SRB1 UE peers.
//
// The UEs are independent UeSrb1Runtime instances on their own UDP endpoints;
// the multiplexer owns the Uu socket and the bridge; the MME is a deterministic
// fixture that only ever talks through the S1AP boundary.
#include <ext/doctest/doctest.h>

#include <lte/enb/multiplexer.hpp>
#include <lte/rrc-runtime/rrc_srb1_runtime.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/types.hpp>

#include <deque>
#include <memory>
#include <string>
#include <vector>

using namespace lte;
using namespace lte::enb;
using namespace lte::enb::s1ap;
using namespace lte::rrc;

namespace
{

constexpr uint32_t AssocA = 0x7A01;
constexpr uint32_t AssocB = 0x7A02;
constexpr uint32_t MmeIdA = 0x4101;
constexpr uint32_t MmeIdB = 0x4102;

class Sender : public IS1apSender
{
  public:
    void sendS1ap(uint16_t, const std::vector<uint8_t> &pdu) override
    {
        sent.push_back(pdu);
    }
    std::vector<std::vector<uint8_t>> sent;
};

EnbConfig MakeConfig(uint16_t uuPort)
{
    EnbConfig config;
    config.plmn = {"460", "02"};
    config.enbId = 1;
    config.tac = 1;
    config.localAddress = "127.0.0.1";
    config.s1uAddress = "127.0.0.1";
    config.ueLinkAddress = "127.0.0.1";
    config.s1uPort = 0;
    config.ueLinkPort = 0;
    config.maxUes = 8;
    config.allowLoopbackS1u = true;
    config.uuAddress = "127.0.0.1";
    config.uuPort = uuPort;
    return config;
}

security::Key256 Kasme(uint8_t seed)
{
    security::Key256 key{};
    for (size_t i = 0; i < key.size(); i++)
        key[i] = static_cast<uint8_t>(seed + i);
    return key;
}

RrcConnectionSetupMessage Setup()
{
    RrcConnectionSetupMessage setup;
    setup.srbIdentity = 1;
    setup.tPollRetransmit = 2;
    setup.pollPdu = 7;
    setup.pollByte = 14;
    setup.maxRetxThreshold = 5;
    setup.tReordering = 1;
    setup.tStatusProhibit = 1;
    return setup;
}

std::vector<uint8_t> AttachRequest()
{
    lte::ue::Config config{};
    config.imsi = "460020000000400";
    config.plmn = {"460", "02"};
    return lte::ue::nas::EncodeAttachRequest(config);
}

// One Uu peer: its own socket, its own SRB1 runtime, its own NAS fixtures.
struct Peer
{
    uint32_t association{0};
    uint32_t mmeId{0};
    std::unique_ptr<uu::Socket> socket{};
    std::unique_ptr<UeSrb1Runtime> runtime{};
    std::vector<std::vector<uint8_t>> downlinkNas{};
    std::deque<std::vector<uint8_t>> uplinkNas{};
    std::vector<uint8_t> lastUplinkNas{};
    size_t responded{0};
    security::Key256 kasme{};

    bool Build(uint32_t assoc, uint32_t mme, uint8_t seed, uint16_t enbPort)
    {
        association = assoc;
        mmeId = mme;
        kasme = Kasme(seed);
        auto sock = uu::Socket::BindLoopback(0, nullptr);
        if (!sock)
            return false;
        socket = std::make_unique<uu::Socket>(std::move(*sock));

        UeSrb1Runtime::Config config;
        config.association = assoc;
        config.mmec = 0x01;
        config.mTmsi = 0xC0000000U | (assoc & 0xFFU);
        config.selectedPlmnIdentity = 1;
        runtime = std::make_unique<UeSrb1Runtime>(*socket, enbPort, config);
        runtime->SetNasCallback([this](const std::vector<uint8_t> &nas) {
            downlinkNas.push_back(nas);
            if (downlinkNas.size() == 1)
            {
                // The NAS Security Mode Command: NAS security is complete, so the
                // RRC layer may start the AS procedure.
                runtime->PrepareAsSecurity(kasme, 7, 1);
            }
        });
        return true;
    }
};

// A deterministic MME view of one UE.
struct MmeView
{
    uint32_t mmeId{0};
    uint32_t enbUeS1apId{0};
    size_t initialUeMessages{0};
    size_t uplinkNasTransports{0};
    size_t setupResponses{0};
    std::vector<std::vector<uint8_t>> uplinkNas{};
};

} // namespace

TEST_CASE("lte/enb-uu/one multiplexer manages two srb1 ues with independent s1ap and security state")
{
    // A free UDP port for the eNB's Uu endpoint.
    uint16_t uuPort = 0;
    {
        auto probe = uu::Socket::BindLoopback(0, nullptr);
        REQUIRE(probe.has_value());
        uuPort = probe->Port();
    }

    Sender sender;
    EnbMultiplexer mux(MakeConfig(uuPort), sender);
    REQUIRE(mux.uuEnabled());

    Peer a;
    Peer b;
    REQUIRE(a.Build(AssocA, MmeIdA, 0x11, uuPort));
    REQUIRE(b.Build(AssocB, MmeIdB, 0x71, uuPort));

    a.runtime->StartAccess();
    b.runtime->StartAccess();

    MmeView viewA;
    MmeView viewB;
    viewA.mmeId = MmeIdA;
    viewB.mmeId = MmeIdB;
    const auto attachRequest = AttachRequest();
    bool setupA = false;
    bool setupB = false;
    bool nasA = false;   // downlink NAS sent to A
    bool nasB = false;
    bool icsA = false;
    bool icsB = false;
    bool uplinkA = false;
    bool uplinkB = false;
    size_t responses = 0;

    auto findMme = [&](uint32_t mmeId) -> MmeView & { return mmeId == MmeIdA ? viewA : viewB; };

    for (int round = 0; round < 900; round++)
    {
        mux.poll();
        a.runtime->Pump(0);
        b.runtime->Pump(0);
        a.runtime->Tick();
        b.runtime->Tick();

        if (!setupA && a.runtime->State() == RrcState::RRC_SRB1_CONFIGURING)
        {
            a.runtime->SubmitSetupComplete(attachRequest);
            setupA = true;
        }
        if (!setupB && b.runtime->State() == RrcState::RRC_SRB1_CONFIGURING)
        {
            b.runtime->SubmitSetupComplete(attachRequest);
            setupB = true;
        }

        // Absorb Initial UE Messages and answer each with one downlink NAS.
        for (const auto &pdu : sender.sent)
        {
            if (pdu.empty())
                continue;
            const auto probe = ProbeS1apPdu(pdu.data(), pdu.size());
            if (probe.kind == S1apPdu::Kind::SUCCESSFUL_OUTCOME)
            {
                responses++;
                continue;
            }
            if (probe.kind != S1apPdu::Kind::INITIATING)
                continue;
            UplinkNas uplink;
            try
            {
                uplink = DecodeUplinkNas(pdu.data(), pdu.size());
            }
            catch (const CodecError &)
            {
                continue;  // not an uplink NAS carrier
            }
            if (uplink.mmeUeS1apId.has_value())
            {
                // An Uplink NAS Transport: count it for the right UE.
                auto &view = findMme(uplink.mmeUeS1apId.value());
                view.uplinkNasTransports++;
                view.uplinkNas.push_back(uplink.nasPdu);
                if (uplink.mmeUeS1apId.value() == MmeIdA)
                    uplinkA = true;
                else
                    uplinkB = true;
                continue;
            }
            // An Initial UE Message: bind the MME identity and answer.
            auto &view = (uplink.enbUeS1apId == viewA.enbUeS1apId || viewA.enbUeS1apId == 0) && !viewA.initialUeMessages
                             ? viewA
                             : viewB;
            if (view.initialUeMessages == 0)
            {
                view.enbUeS1apId = uplink.enbUeS1apId;
                view.initialUeMessages++;
                const std::vector<uint8_t> nas{0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
                const auto downlink = EncodeDownlinkNasTransport(view.mmeId, view.enbUeS1apId, nas);
                mux.handleS1ap(downlink.data(), downlink.size(), 1);
                if (view.mmeId == MmeIdA)
                    nasA = true;
                else
                    nasB = true;
            }
        }
        sender.sent.clear();

        // The UE answers each downlink NAS through ULInformationTransfer.
        for (Peer *peer : {&a, &b})
        {
            // One uplink NAS per downlink NAS, exactly as a NAS state machine
            // would answer, and never a second one for the same stimulus.
            if (peer->downlinkNas.size() > peer->responded)
            {
                peer->responded = peer->downlinkNas.size();
                peer->runtime->SubmitNas(std::vector<uint8_t>{0x07, 0x5E, 0x11, 0x22, 0x33});
            }
        }

        // Once both are connected and have answered, start their AS security with
        // the KeNB the MME derives.
        if (!icsA && viewA.initialUeMessages == 1 && uplinkA && viewA.enbUeS1apId != 0)
        {
            InitialContextSetupRequest request;
            request.mmeUeS1apId = MmeIdA;
            request.enbUeS1apId = viewA.enbUeS1apId;
            request.ueAmbrUl = request.ueAmbrDl = 100000000;
            ErabToBeSetupItem erab;
            erab.erabId = 5;
            erab.qci = 9;
            erab.transportLayerAddress = {10, 0, 0, 1};
            erab.gtpTeid = {0x11, 0x22, 0x33, 0x44};
            request.erabs.push_back(erab);
            request.encryptionAlgorithms = {0xE0, 0x00};
            request.integrityAlgorithms = {0xE0, 0x00};
            request.securityKey = security::DeriveKenb(a.kasme, 7);
            const auto pdu = EncodeInitialContextSetupRequest(request);
            mux.handleS1ap(pdu.data(), pdu.size(), 1);
            icsA = true;
        }
        if (!icsB && viewB.initialUeMessages == 1 && uplinkB && viewB.enbUeS1apId != 0)
        {
            InitialContextSetupRequest request;
            request.mmeUeS1apId = MmeIdB;
            request.enbUeS1apId = viewB.enbUeS1apId;
            request.ueAmbrUl = request.ueAmbrDl = 100000000;
            ErabToBeSetupItem erab;
            erab.erabId = 5;
            erab.qci = 9;
            erab.transportLayerAddress = {10, 0, 0, 2};
            erab.gtpTeid = {0x55, 0x66, 0x77, 0x88};
            request.erabs.push_back(erab);
            request.encryptionAlgorithms = {0xE0, 0x00};
            request.integrityAlgorithms = {0xE0, 0x00};
            request.securityKey = security::DeriveKenb(b.kasme, 7);
            const auto pdu = EncodeInitialContextSetupRequest(request);
            mux.handleS1ap(pdu.data(), pdu.size(), 1);
            icsB = true;
        }


        if (responses == 2)
            break;
    }

    // Both UEs are managed by this one multiplexer.
    CHECK(mux.bridgeAssociationCount() == 2);
    CHECK(mux.bridgeHasAssociation(AssocA));
    CHECK(mux.bridgeHasAssociation(AssocB));

    REQUIRE(viewA.initialUeMessages == 1);
    REQUIRE(viewB.initialUeMessages == 1);
    CHECK(viewA.enbUeS1apId != viewB.enbUeS1apId);
    CHECK(viewA.uplinkNasTransports == 1);
    CHECK(viewB.uplinkNasTransports == 1);
    CHECK(responses == 2);
    CHECK(mux.pendingInitialContextSetups() == 0);

    // AS security activated on both, from their own KeNB.
    CHECK(mux.asSecurityActive(AssocA));
    CHECK(mux.asSecurityActive(AssocB));
    CHECK(a.runtime->AsSecurityActive());
    CHECK(b.runtime->AsSecurityActive());
    CHECK(a.runtime->SecurityContext()->ActiveKenb() != b.runtime->SecurityContext()->ActiveKenb());

    // Each UE received only its own downlink NAS.
    REQUIRE(a.downlinkNas.size() == 1);
    REQUIRE(b.downlinkNas.size() == 1);
    CHECK(a.downlinkNas[0] == b.downlinkNas[0]);  // same fixture message
    CHECK(mux.bridgeDroppedLegacyFrames() == 0);
}
