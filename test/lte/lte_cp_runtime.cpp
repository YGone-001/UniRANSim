//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-C: the LTE control-plane slice over SRB1 and S1AP.
//
// UE -- SRB0/SRB1 over the simulated Uu -- eNB bridge -- S1AP codec -- MME
// fixture. The NAS that S1AP carries is opaque at the eNB, exactly as in
// production; the first one is the real EPS Attach Request from the production
// NAS encoder, and the UE side decodes the NAS Security Mode Command and the
// Attach Accept with the production NAS decoders.
#include <ext/doctest/doctest.h>

#include <lte/enb/enb_rrc_bridge.hpp>
#include <lte/rrc-runtime/rrc_information_transfer.hpp>
#include <lte/rrc-runtime/rrc_srb1_runtime.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/types.hpp>

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "uu_relay.hpp"

using namespace lte;
using namespace lte::rrc;
using namespace lte::enb::s1ap;
using namespace uu_test;

namespace
{

constexpr uint32_t Assoc = 0x6C01;
constexpr uint32_t AssocB = 0x6C02;
constexpr uint32_t UlNasCount = 7;

RrcConnectionSetupMessage Srb1Setup()
{
    RrcConnectionSetupMessage setup;
    setup.transactionId = 0;
    setup.srbIdentity = 1;
    setup.tPollRetransmit = 2;   // ms15
    setup.pollPdu = 7;           // pInfinity
    setup.pollByte = 14;         // kBinfinity
    setup.maxRetxThreshold = 5;  // t8
    setup.tReordering = 1;       // ms5
    setup.tStatusProhibit = 1;   // ms5
    return setup;
}

lte::ue::Config Subscriber()
{
    lte::ue::Config config{};
    config.imsi = "460020000000400";
    config.plmn = {"460", "02"};
    return config;
}

security::Key256 Kasme()
{
    security::Key256 kasme{};
    for (size_t i = 0; i < kasme.size(); i++)
        kasme[i] = static_cast<uint8_t>(0x50 + i);
    return kasme;
}

security::AsAlgorithmConfiguration Policy()
{
    security::AsAlgorithmConfiguration configuration;
    configuration.ciphering.ordered = {2, 1, 0};
    configuration.integrity.ordered = {2, 1, 0};
    configuration.ciphering.generation = 5;
    configuration.integrity.generation = 5;
    configuration.nasIntegrityAlgorithm = 2;
    return configuration;
}

const std::vector<uint8_t> AttachRequestNas()
{
    return lte::ue::nas::EncodeAttachRequest(Subscriber());
}

// TS 24.301 fixed NAS messages. They are opaque to the eNB, which is the point:
// the eNB never decodes, decrypts or rewrites them.
std::vector<uint8_t> AuthenticationRequest()
{
    std::vector<uint8_t> out{0x07, 0x52, 0x00};
    for (int i = 0; i < 16; i++)
        out.push_back(static_cast<uint8_t>(0x10 + i));
    for (int i = 0; i < 16; i++)
        out.push_back(static_cast<uint8_t>(0x90 + i));
    return out;
}
std::vector<uint8_t> AuthenticationResponse()
{
    return {0x07, 0x53, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
}
std::vector<uint8_t> NasSecurityModeCommand()
{
    // The pinned EIA2/EEA0 Security Mode Command the UE NAS tests use.
    return {0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
}
std::vector<uint8_t> NasSecurityModeComplete()
{
    return {0x07, 0x5E, 0x11, 0x22, 0x33, 0x44};
}
std::vector<uint8_t> AttachCompleteNas()
{
    return {0x07, 0x43, 0x05, 0x01, 0x02, 0x03, 0x04};
}

std::vector<uint8_t> AttachAcceptNas()
{
    const auto plmn = EncodePlmn({"460", "02"});
    const std::vector<uint8_t> esm{0x52, 0x01, 0xC1, 0x01, 0x05, 0x09, 0x08, 0x69, 0x6E,
                                   0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};
    std::vector<uint8_t> out{0x07, 0x42, 0x01, 0x30, 0x06, 0x40, plmn[0], plmn[1], plmn[2], 0x00, 0x01};
    out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esm.size()));
    out.insert(out.end(), esm.begin(), esm.end());
    return out;
}

// The MME fixture: owns KASME and the NAS COUNT, derives the KeNB it puts in the
// Initial Context Setup Request, and otherwise only moves opaque NAS bytes.
class TestMme
{
  public:
    void OnS1ap(const std::vector<uint8_t> &pdu)
    {
        UplinkNas uplink;
        try
        {
            uplink = DecodeUplinkNas(pdu.data(), pdu.size());
        }
        catch (const lte::enb::s1ap::CodecError &)
        {
            initialContextResponses++;
            // The initial context is set up, so the network sends the protected
            // Attach Accept the UE is waiting for.
            QueueDownlink(AttachAcceptNas());
            return;
        }

        uplinkNas.push_back(uplink.nasPdu);

        if (!initialUeSeen)
        {
            initialUeSeen = true;
            initialUeHadMmeId = uplink.mmeUeS1apId.has_value();
            attachRequest = uplink.nasPdu;
            enbUeS1apId = uplink.enbUeS1apId;
            QueueDownlink(AuthenticationRequest());
            QueueDownlink(NasSecurityModeCommand());
            return;
        }

        if (uplink.mmeUeS1apId.has_value() && *uplink.mmeUeS1apId == mmeUeS1apId)
            identityPairs++;
        if (uplink.nasPdu == AuthenticationResponse())
        {
            authenticationAnswers++;
            return;
        }
        if (uplink.nasPdu == NasSecurityModeComplete())
        {
            nasSecurityComplete = true;
            QueueInitialContextSetup();
            return;
        }
        if (uplink.nasPdu == AttachCompleteNas())
        {
            attachComplete = true;
            return;
        }
        refused++;
    }

    std::vector<uint8_t> Take()
    {
        if (queue_.empty())
            return {};
        auto out = queue_.front();
        queue_.pop_front();
        return out;
    }

    [[nodiscard]] bool Empty() const
    {
        return queue_.empty();
    }

    std::vector<uint8_t> attachRequest{};
    std::vector<std::vector<uint8_t>> uplinkNas{};
    uint32_t mmeUeS1apId{0x4001};
    uint32_t enbUeS1apId{0};
    size_t authenticationAnswers{0};
    size_t initialContextResponses{0};
    size_t identityPairs{0};
    bool initialUeSeen{false};
    bool initialUeHadMmeId{false};
    bool nasSecurityComplete{false};
    bool attachComplete{false};
    size_t refused{0};

  private:
    void QueueDownlink(const std::vector<uint8_t> &nas)
    {
        queue_.push_back(EncodeDownlinkNasTransport(mmeUeS1apId, enbUeS1apId, nas));
    }

    void QueueInitialContextSetup()
    {
        InitialContextSetupRequest request;
        request.mmeUeS1apId = mmeUeS1apId;
        request.enbUeS1apId = enbUeS1apId;
        request.ueAmbrUl = 100000000;
        request.ueAmbrDl = 100000000;
        ErabToBeSetupItem erab;
        erab.erabId = 5;
        erab.qci = 9;
        erab.transportLayerAddress = {10, 0, 0, 1};
        erab.gtpTeid = {0x11, 0x22, 0x33, 0x44};
        request.erabs.push_back(erab);
        // EEA0/EEA1/EEA2 and EIA0/EIA1/EIA2, as an MME sends them.
        request.encryptionAlgorithms = {0xE0, 0x00};
        request.integrityAlgorithms = {0xE0, 0x00};
        request.securityKey = security::DeriveKenb(Kasme(), UlNasCount);
        queue_.push_back(EncodeInitialContextSetupRequest(request));
    }

    std::deque<std::vector<uint8_t>> queue_{};
};

// One UE endpoint, one eNB endpoint and the MME fixture, with every asynchronous
// boundary turned into a queue so no entity is re-entered from its deliverer.
struct Slice
{
    uint32_t association{Assoc};
    std::unique_ptr<uu::Socket> ueSocket{};
    std::unique_ptr<uu::Socket> enbSocket{};
    std::unique_ptr<UuRelay> relay{};
    std::unique_ptr<UeSrb1Runtime> ue{};
    std::unique_ptr<EnbRrcBridge> bridge{};
    std::unique_ptr<TestMme> mme{};
    std::vector<std::vector<uint8_t>> downlinkNas{};
    std::deque<std::vector<uint8_t>> ueUplink{};
    std::vector<ErabSetupItem> erabs{};
    std::deque<std::vector<uint8_t>> downlinkNasLog{};

    bool Build(uint32_t id, bool relayed)
    {
        association = id;
        auto ueSock = uu::Socket::BindLoopback(0, nullptr);
        auto enbSock = uu::Socket::BindLoopback(0, nullptr);
        if (!ueSock || !enbSock)
            return false;
        uint16_t peer = enbSock->Port();
        if (relayed)
        {
            relay = std::make_unique<UuRelay>();
            if (!relay->Bind(nullptr))
                return false;
            relay->SetPeers(ueSock->Port(), enbSock->Port());
            peer = relay->UeFacingPort();
        }
        ueSocket = std::make_unique<uu::Socket>(std::move(*ueSock));
        enbSocket = std::make_unique<uu::Socket>(std::move(*enbSock));

        UeSrb1Runtime::Config config;
        config.association = association;
        config.mmec = 0x01;
        config.mTmsi = 0xC000038D;
        config.selectedPlmnIdentity = 1;
        ue = std::make_unique<UeSrb1Runtime>(*ueSocket, peer, config);
        ue->SetNasCallback([this](const std::vector<uint8_t> &nas) {
            downlinkNas.push_back(nas);
            if (downlinkNas.size() == 1)
            {
                ueUplink.push_back(AuthenticationResponse());
            }
            else if (downlinkNas.size() == 2)
            {
                // The production UE NAS decoder validates the command, then the
                // RRC layer is told that NAS security is complete.
                ueCommand = lte::ue::nas::DecodeSecurityModeCommand(nas.data(), nas.size());
                ue->PrepareAsSecurity(Kasme(), UlNasCount, 1);
                ueUplink.push_back(NasSecurityModeComplete());
            }
            else if (downlinkNas.size() == 3)
            {
                const auto message = lte::ue::nas::DecodeDownlink(nas.data(), nas.size());
                attachAcceptSeen = message.type == lte::ue::nas::DownlinkEmm::ATTACH_ACCEPT;
                ueUplink.push_back(AttachCompleteNas());
            }
        });

        mme = std::make_unique<TestMme>();
        EnbRrcBridge::Config config2;
        config2.enb.plmn = {"460", "02"};
        config2.enb.enbId = 0x00A1B2;
        config2.enb.tac = 1;
        config2.srb1.setup = Srb1Setup();
        config2.algorithms = Policy();
        bridge = std::make_unique<EnbRrcBridge>(*enbSocket, config2, [this](const std::vector<uint8_t> &pdu) {
            mme->OnS1ap(pdu);
        });

        ErabSetupItem erab;
        erab.erabId = 5;
        erab.transportLayerAddress = {10, 0, 0, 2};
        erab.gtpTeid = {0x55, 0x66, 0x77, 0x88};
        erabs.push_back(erab);
        return true;
    }

    void Round()
    {
        if (relay)
            relay->Pump();
        ue->Pump(0);
        bridge->Pump(0);
        ue->Tick();
        bridge->Tick();

        // The RRC connection is up: the UE's NAS sends its first message, the
        // EPS Attach Request, inside RRCConnectionSetupComplete.
        if (!setupSent && ue->State() == RrcState::RRC_SRB1_CONFIGURING)
        {
            ue->SubmitSetupComplete(AttachRequestNas());
            setupSent = true;
        }

        while (!mme->Empty())
        {
            const auto pdu = mme->Take();
            try
            {
                (void)DecodeDownlinkNasTransport(pdu.data(), pdu.size());
                bridge->OnDownlinkNasTransport(pdu);
            }
            catch (const lte::enb::s1ap::CodecError &)
            {
                bridge->OnInitialContextSetupRequest(pdu);
            }
        }
        while (!ueUplink.empty())
        {
            const auto nas = ueUplink.front();
            ueUplink.pop_front();
            ue->SubmitNas(nas);
        }
        if (!setupReported && bridge->AsSecurityActive(association))
        {
            bridge->CompleteInitialContextSetup(association, erabs);
            setupReported = true;
        }
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

    [[nodiscard]] bool Done() const
    {
        return mme->attachComplete && ue->State() == RrcState::RRC_CONNECTED &&
               bridge->AsSecurityActive(association);
    }

    bool setupSent{false};
    bool setupReported{false};
    bool attachAcceptSeen{false};
    lte::ue::nas::SecurityModeCommand ueCommand{};
};

} // namespace

TEST_CASE("lte/cp-runtime/information transfer round trips the nas payload and refuses an empty one")
{
    InformationTransferMessage message;
    message.dedicatedInfoNas = {0x07, 0x52, 0x01, 0x02, 0x03};

    const auto uplink = EncodeUlInformationTransfer(message);
    REQUIRE_FALSE(uplink.empty());
    InformationTransferMessage decoded;
    REQUIRE(DecodeUlInformationTransfer(uplink.data(), uplink.size(), decoded));
    CHECK(decoded.dedicatedInfoNas == message.dedicatedInfoNas);
    // A UL message is not a DL message.
    CHECK_FALSE(DecodeDlInformationTransfer(uplink.data(), uplink.size(), decoded));

    const auto downlink = EncodeDlInformationTransfer(message);
    REQUIRE_FALSE(downlink.empty());
    REQUIRE(DecodeDlInformationTransfer(downlink.data(), downlink.size(), decoded));
    CHECK(decoded.dedicatedInfoNas == message.dedicatedInfoNas);
    CHECK_FALSE(DecodeUlInformationTransfer(downlink.data(), downlink.size(), decoded));

    InformationTransferMessage empty;
    CHECK(EncodeUlInformationTransfer(empty).empty());
    CHECK(EncodeDlInformationTransfer(empty).empty());
    CHECK_FALSE(DecodeUlInformationTransfer(uplink.data(), uplink.size() - 1, decoded));

    // A SetupComplete is not an InformationTransfer.
    RrcConnectionSetupCompleteMessage complete;
    complete.dedicatedInfoNas = message.dedicatedInfoNas;
    const auto other = EncodeRrcConnectionSetupComplete(complete);
    REQUIRE_FALSE(other.empty());
    CHECK_FALSE(DecodeUlInformationTransfer(other.data(), other.size(), decoded));
    CHECK_FALSE(DecodeDlInformationTransfer(other.data(), other.size(), decoded));
}

TEST_CASE("lte/cp-runtime/the attach slice carries nas through s1ap and srb1 with as security activated")
{
    Slice slice;
    REQUIRE(slice.Build(Assoc, false));

    slice.ue->StartAccess();
    REQUIRE(slice.RunUntil([&] { return slice.Done(); }, 400));

    // The SetupComplete carried the real EPS Attach Request from the production
    // NAS encoder, and the Initial UE Message carried it unchanged.
    CHECK(slice.mme->attachRequest == AttachRequestNas());
    CHECK_FALSE(slice.mme->initialUeHadMmeId);
    CHECK(slice.mme->authenticationAnswers == 1);
    CHECK(slice.mme->nasSecurityComplete);
    CHECK(slice.mme->initialContextResponses == 1);
    CHECK(slice.mme->attachComplete);
    CHECK(slice.mme->identityPairs >= 3);
    CHECK(slice.mme->refused == 0);

    // The bridge sent one Initial UE Message, three Uplink NAS Transports (the
    // authentication response, the NAS Security Mode Complete and the Attach
    // Complete), three Downlink NAS Transports and one Initial Context Setup
    // Response.
    CHECK(slice.bridge->InitialUeMessages() == 1);
    CHECK(slice.bridge->UplinkNasTransports() == 3);
    CHECK(slice.bridge->DownlinkNasTransports() == 3);
    CHECK(slice.bridge->SetupResponses() == 1);

    // The UE's NAS decoder read the pinned Security Mode Command: EIA2 and EEA0.
    CHECK(slice.ueCommand.integrity == lte::ue::IntegrityAlgorithm::EIA2);
    CHECK(slice.ueCommand.ciphering == lte::ue::CipheringAlgorithm::EEA0);
    CHECK(slice.attachAcceptSeen);

    // AS security activated on both sides, from the MME's KeNB on the eNB and
    // from KASME on the UE.
    CHECK(slice.bridge->AsSecurityActive(Assoc));
    REQUIRE(slice.bridge->Runtime().SecurityContextOf(Assoc) != nullptr);
    CHECK(slice.bridge->Runtime().SecurityContextOf(Assoc)->Algorithms().rrcCiphering == 2);
    CHECK(slice.ue->AsSecurityActive());
    REQUIRE(slice.ue->SecurityContext() != nullptr);
    CHECK(slice.ue->SecurityContext()->ActiveKenb() ==
          slice.bridge->Runtime().SecurityContextOf(Assoc)->ActiveKenb());

    // The NAS bytes crossed unchanged.
    REQUIRE(slice.downlinkNas.size() == 3);
    CHECK(slice.downlinkNas[0] == AuthenticationRequest());
    CHECK(slice.downlinkNas[1] == NasSecurityModeCommand());
    CHECK(slice.downlinkNas[2] == AttachAcceptNas());
    REQUIRE(slice.mme->uplinkNas.size() == 4);
    CHECK(slice.mme->uplinkNas[0] == AttachRequestNas());
    CHECK(slice.mme->uplinkNas[1] == AuthenticationResponse());
    CHECK(slice.mme->uplinkNas[2] == NasSecurityModeComplete());
    CHECK(slice.mme->uplinkNas[3] == AttachCompleteNas());
}

TEST_CASE("lte/cp-runtime/a lost security mode command is recovered by rlc am")
{
    Slice slice;
    REQUIRE(slice.Build(Assoc, true));

    Impairment downlink;
    downlink.dropAmdAt = 1;  // the SecurityModeCommand PDU
    slice.relay->SetImpairments(Impairment{}, downlink);

    slice.ue->StartAccess();
    REQUIRE(slice.RunUntil([&] { return slice.Done(); }, 500));

    CHECK(slice.bridge->AsSecurityActive(Assoc));
    CHECK(slice.ue->AsSecurityActive());
    CHECK(slice.mme->attachComplete);
    // The UE never re-encoded the NAS because the radio lost a PDU: one NAS
    // Security Mode Complete was sent, and RLC carried it again.
    CHECK(slice.mme->uplinkNas.size() == 4);
    CHECK(slice.mme->uplinkNas[2] == NasSecurityModeComplete());
}

TEST_CASE("lte/cp-runtime/an s1 association loss invalidates the access context")
{
    Slice slice;
    REQUIRE(slice.Build(Assoc, false));
    slice.ue->StartAccess();
    REQUIRE(slice.RunUntil([&] { return slice.Done(); }, 400));
    REQUIRE(slice.bridge->HasContext(Assoc));

    slice.bridge->OnS1AssociationLost();
    CHECK_FALSE(slice.bridge->HasContext(Assoc));
    CHECK(slice.bridge->StateOf(Assoc) == RrcState::RRC_IDLE);
    CHECK_FALSE(slice.bridge->AsSecurityActive(Assoc));

    // A downlink NAS Transport for the released identity is refused and does not
    // revive the context.
    const auto pdu = EncodeDownlinkNasTransport(slice.mme->mmeUeS1apId, slice.mme->enbUeS1apId, AuthenticationRequest());
    slice.bridge->OnDownlinkNasTransport(pdu);
    CHECK_FALSE(slice.bridge->HasContext(Assoc));
    CHECK(slice.downlinkNas.size() == 3);
}

TEST_CASE("lte/cp-runtime/two ue contexts keep independent s1ap identity and security state")
{
    Slice first;
    Slice second;
    REQUIRE(first.Build(Assoc, false));
    REQUIRE(second.Build(AssocB, false));

    first.ue->StartAccess();
    second.ue->StartAccess();

    for (int i = 0; i < 400 && !(first.Done() && second.Done()); i++)
    {
        first.Round();
        second.Round();
    }
    REQUIRE(first.Done());
    REQUIRE(second.Done());

    CHECK(first.bridge->EnbUeS1apIdOf(Assoc).has_value());
    CHECK(second.bridge->EnbUeS1apIdOf(AssocB).has_value());
    CHECK(first.bridge->AssociationOf(*first.bridge->EnbUeS1apIdOf(Assoc)) == Assoc);
    CHECK(second.bridge->AssociationOf(*second.bridge->EnbUeS1apIdOf(AssocB)) == AssocB);

    CHECK(first.bridge->AsSecurityActive(Assoc));
    CHECK(second.bridge->AsSecurityActive(AssocB));
    REQUIRE(first.bridge->Runtime().SecurityContextOf(Assoc) != nullptr);
    REQUIRE(second.bridge->Runtime().SecurityContextOf(AssocB) != nullptr);
    CHECK(first.bridge->Runtime().SecurityContextOf(Assoc)->ActiveKenb() ==
          second.bridge->Runtime().SecurityContextOf(AssocB)->ActiveKenb());

    // Both carried the same NAS because the fixture is the same subscriber, but
    // through separate associations, identities and PDCP state.
    CHECK(first.mme->attachRequest == second.mme->attachRequest);
    CHECK(first.ue->Evidence().uplinkNas == 3);
    CHECK(second.ue->Evidence().uplinkNas == 3);
}


TEST_CASE("lte/cp-runtime/the bridge can take the owners identity allocator and report the binding")
{
    auto ueSocket = uu::Socket::BindLoopback(0, nullptr);
    auto enbSocket = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(ueSocket.has_value());
    REQUIRE(enbSocket.has_value());

    UeSrb1Runtime::Config ueRuntime;
    ueRuntime.association = Assoc;
    ueRuntime.mmec = 0x01;
    ueRuntime.mTmsi = 0xC000038D;
    ueRuntime.selectedPlmnIdentity = 1;
    UeSrb1Runtime ue(*ueSocket, enbSocket->Port(), ueRuntime);

    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> sent;
    std::optional<std::tuple<uint32_t, uint32_t, uint16_t, std::vector<uint8_t>>> binding;

    EnbRrcBridge::Config config;
    config.enb.plmn = {"460", "02"};
    config.enb.enbId = 0x00A1B2;
    config.enb.tac = 1;
    config.srb1.setup = Srb1Setup();
    config.algorithms = Policy();
    EnbRrcBridge bridge(
        *enbSocket, config,
        [&sent](uint32_t enbUeS1apId, const std::vector<uint8_t> &pdu) { sent.emplace_back(enbUeS1apId, pdu); },
        [] { return 0x777U; },
        [&binding](uint32_t association, uint32_t enbUeS1apId, uint16_t peerPort, const std::vector<uint8_t> &nas) {
            binding = std::make_tuple(association, enbUeS1apId, peerPort, nas);
        });

    ue.StartAccess();
    bool setupSent = false;
    for (int i = 0; i < 40 && sent.empty(); i++)
    {
        ue.Pump(0);
        bridge.Pump(0);
        ue.Tick();
        bridge.Tick();
        if (!setupSent && ue.State() == RrcState::RRC_SRB1_CONFIGURING)
        {
            ue.SubmitSetupComplete(AttachRequestNas());
            setupSent = true;
        }
    }
    REQUIRE(setupSent);
    for (int i = 0; i < 40 && sent.empty(); i++)
    {
        ue.Pump(0);
        bridge.Pump(0);
        ue.Tick();
        bridge.Tick();
    }

    // The owner's allocator, not the bridge's own counter, named the UE.
    REQUIRE(sent.size() == 1);
    CHECK(sent[0].first == 0x777U);
    CHECK(bridge.EnbUeS1apIdOf(Assoc).has_value());
    CHECK(*bridge.EnbUeS1apIdOf(Assoc) == 0x777U);

    const UplinkNas initial = DecodeUplinkNas(sent[0].second.data(), sent[0].second.size());
    CHECK(initial.enbUeS1apId == 0x777U);
    CHECK_FALSE(initial.mmeUeS1apId.has_value());
    CHECK(initial.nasPdu == AttachRequestNas());

    // The owner learned the association, the identifier, the radio endpoint and
    // the NAS before any S1AP answer can arrive.
    REQUIRE(binding.has_value());
    CHECK(std::get<0>(*binding) == Assoc);
    CHECK(std::get<1>(*binding) == 0x777U);
    CHECK(std::get<2>(*binding) == ueSocket->Port());
    CHECK(std::get<3>(*binding) == AttachRequestNas());
}

