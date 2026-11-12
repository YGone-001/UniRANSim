//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 18-F-A: the live S1AP handover ingress.
//
// Every case here drives the production dispatcher, `EnbMultiplexer::handleS1ap`,
// with a real encoded S1AP PDU. The fixtures are the byte-pinned vectors the
// Phase 18-A wire tests established with Wireshark tshark; the negative frames
// are those same bytes with a single, asserted change, so a failure names the
// field that caused it.
//
// What these cases prove is narrow and deliberate: the handover family is
// recognised, its messages are validated as far as this build can validate
// them, and every one of them is refused before anything is allocated, moved,
// notified or released. None of them proves a live handover.

#include <ext/doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <lte/enb/codec.hpp>
#include <lte/enb/handover_live_ingress.hpp>
#include <lte/enb/handover_preparation.hpp>
#include <lte/enb/handover_source_release.hpp>
#include <lte/enb/multiplexer.hpp>
#include <lte/enb/ue_registry.hpp>
#include <lte/ue/radio_link.hpp>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;
namespace link = lte::ue::link;

constexpr uint32_t SourceEnbId = 0x0012345u;
constexpr uint32_t MmeUeS1apId = 201;
constexpr uint32_t UeRadioId = 7;

const Plmn &TestPlmn()
{
    static const Plmn plmn{"460", "02"};
    return plmn;
}

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
    for (size_t i = 0; i + 1 < text.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    return out;
}

// The Phase 18-A cross-checked APER vector for a Handover Request. It is
// reproduced here verbatim from `test/lte/handover_s1.cpp` (case
// `lte/handover/wire: handover request matches the cross-checked aper vector`),
// where tshark 4.2.2 dissected it over SCTP with PPID 18. The production
// encoder is asserted against the same octets there, so the two copies cannot
// drift apart silently.
std::vector<uint8_t> PinnedHandoverRequest()
{
    return Hex("000100808000000800000002000700010001000002400202000042000A1808F0D18060047868C0003500230"
               "1001B400D0A1FC00002010A0B0C0D00053C001B400D0C1FC00002010E0F101100060D0068000504010203040"
               "06B000510000400000028002118A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE"
               "BF");
}

// The Phase 18-A cross-checked APER vector for a Handover Command, from the
// case `lte/handover/wire: handover command matches the cross-checked aper
// vector`, dissected the same way.
std::vector<uint8_t> PinnedHandoverCommand()
{
    return Hex("2000001D0000040000000200070008000200090001000100007B000504CAFEBABE");
}

size_t FindPattern(const std::vector<uint8_t> &haystack, const std::vector<uint8_t> &needle, size_t from)
{
    const auto at = std::search(haystack.begin() + static_cast<long>(from), haystack.end(), needle.begin(),
                                needle.end());
    if (at == haystack.end())
        return std::string::npos;
    return static_cast<size_t>(at - haystack.begin());
}

struct CaptureSender final : IS1apSender
{
    void sendS1ap(uint16_t stream, const std::vector<uint8_t> &pdu) override
    {
        sent.emplace_back(stream, pdu);
    }
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> sent;
};

EnbConfig Config(uint32_t enbId = SourceEnbId, const std::string &address = "127.0.0.1", uint16_t tac = 1)
{
    EnbConfig config{};
    config.plmn = TestPlmn();
    config.enbId = enbId;
    config.tac = tac;
    config.localAddress = "127.0.0.1";
    config.mmeAddress = "127.0.0.1";
    config.ueLinkAddress = address;
    config.ueLinkPort = 0;
    config.s1uAddress = address;
    config.s1uPort = 0;
    config.allowLoopbackS1u = true;
    config.maxUes = 8;
    return config;
}

struct FakeUe
{
    explicit FakeUe(uint32_t id) : radio("127.0.0.1", 0), radioUeId(id) {}
    udp::UdpServer radio;
    uint32_t radioUeId;
};

void SendRadio(EnbMultiplexer &mux, const FakeUe &ue, link::MessageType type, const std::vector<uint8_t> &payload)
{
    const auto frame = link::Encode({type, ue.radioUeId, payload});
    mux.handleRadioFrame(frame.data(), frame.size(), ue.radio.LocalAddress());
}

std::vector<link::Message> DrainRadio(FakeUe &ue)
{
    std::vector<link::Message> frames;
    uint8_t buffer[4096];
    InetAddress peer;
    for (;;)
    {
        const int received = ue.radio.Receive(buffer, sizeof(buffer), 10, peer);
        if (received <= 0)
            break;
        frames.push_back(link::Decode(buffer, static_cast<size_t>(received)));
    }
    return frames;
}

s1ap::ErabToBeSetupItem Item(uint8_t ebi, uint8_t qci, uint32_t sgwTeid)
{
    s1ap::ErabToBeSetupItem item{};
    item.erabId = ebi;
    item.qci = qci;
    item.priorityLevel = 5;
    item.transportLayerAddress = {127, 0, 0, 2};
    item.gtpTeid = TeidToBytes(sgwTeid);
    return item;
}

// One eNB, the sink everything it transmits lands in, and a UE socket.
struct LiveLab
{
    CaptureSender wire;
    EnbMultiplexer mux{Config(), wire};
    FakeUe ue{UeRadioId};
};

// One UE's EPS session, established through the production radio and S1AP
// entry points only.
void Establish(EnbMultiplexer &mux, FakeUe &ue, uint32_t mmeUeS1apId = MmeUeS1apId)
{
    SendRadio(mux, ue, link::MessageType::NAS_UPLINK, {0x41, 0x01, 0x02, 0x03});
    EnbUeEntry *entry = mux.registry().find(ue.radioUeId);
    REQUIRE(entry != nullptr);

    s1ap::InitialContextSetupRequest request{};
    request.mmeUeS1apId = mmeUeS1apId;
    request.enbUeS1apId = entry->enbUeS1apId;
    request.ueAmbrUl = 1000;
    request.ueAmbrDl = 2000;
    request.erabs = {Item(5, 9, 30)};
    const auto pdu = s1ap::EncodeInitialContextSetupRequest(request);
    mux.handleS1ap(pdu.data(), pdu.size(), 1);
    REQUIRE(entry->bearer.signalingEstablished());

    SendRadio(mux, ue, link::MessageType::BEARER_READY, {5, 10, 0, 0, 1});
    REQUIRE(entry->bearer.active());

    DrainRadio(ue);
}

LiveHandoverContext ContextOf(EnbMultiplexer &mux, const std::vector<HandoverSourceRecord> &records)
{
    LiveHandoverContext context;
    context.registry = &mux.registry();
    context.sourceRecords = &records;
    context.associationEpoch = mux.associationEpoch();
    context.associationBound = mux.associationBound();
    return context;
}

} // namespace

// --- The capability model ---------------------------------------------------

TEST_CASE("lte/handover/live: the capability model names every missing live prerequisite")
{
    const LiveHandoverReadiness readiness = AssessLiveHandoverCapabilities();

    // What exists, exists because the code and its tests exist.
    CHECK(readiness.available(HandoverCapability::ISOLATED_SIMULATOR_READY));
    CHECK(readiness.available(HandoverCapability::S1AP_CODEC_READY));
    CHECK(readiness.available(HandoverCapability::S1AP_RUNTIME_INGRESS_READY));
    CHECK(readiness.available(HandoverCapability::LTE_RRC_UPER_CODEC_READY));
    CHECK(readiness.available(HandoverCapability::S1AP_TRANSPARENT_CONTAINER_CODEC_READY));
    CHECK(readiness.available(HandoverCapability::RRC_RUNTIME_INPUT_AVAILABLE));

    // What does not exist is named, not hidden behind a switch.
    CHECK_FALSE(readiness.available(HandoverCapability::RRC_CONFIGURATION_COMPLETE));
    CHECK_FALSE(readiness.available(HandoverCapability::SOURCE_PROVENANCE_READY));
    CHECK_FALSE(readiness.available(HandoverCapability::TARGET_CONTEXT_READY));
    CHECK_FALSE(readiness.available(HandoverCapability::HANDOVER_SECURITY_READY));
    CHECK_FALSE(readiness.available(HandoverCapability::UE_RADIO_EXECUTION_READY));

    CHECK_FALSE(readiness.available(HandoverCapability::LIVE_HANDOVER_EXECUTION_READY));
    CHECK_FALSE(readiness.liveExecutionReady());

    // Execution prerequisites: what a running eNB needs before it may execute.
    const auto missing = readiness.missing();
    REQUIRE(missing.size() == 5);
    CHECK(missing[0] == HandoverCapability::RRC_CONFIGURATION_COMPLETE);
    CHECK(missing[1] == HandoverCapability::SOURCE_PROVENANCE_READY);
    CHECK(missing[2] == HandoverCapability::TARGET_CONTEXT_READY);
    CHECK(missing[3] == HandoverCapability::HANDOVER_SECURITY_READY);
    CHECK(missing[4] == HandoverCapability::UE_RADIO_EXECUTION_READY);

    // External acceptance evidence is reported separately: no eNB reads the
    // SGW's forwarding map to perform a handover, and a future live campaign
    // obtains this from the core side.
    const auto external = readiness.externalEvidenceGaps();
    REQUIRE(external.size() == 1);
    CHECK(external[0] == HandoverCapability::MME_PATH_UPDATE_OBSERVABLE);
    CHECK_FALSE(readiness.available(HandoverCapability::MME_PATH_UPDATE_OBSERVABLE));

    // Every assessment carries the fact it rests on.
    REQUIRE(readiness.assessments.size() == 13);
    for (const auto &assessment : readiness.assessments)
    {
        CHECK_FALSE(assessment.evidence.empty());
        CHECK(std::string(ToString(assessment.capability)).rfind("UNKNOWN", 0) != 0);
    }
}

// --- A. A valid Handover Request -------------------------------------------

TEST_CASE("lte/handover/live: a handover request is recognised and refused without preparing anything")
{
    LiveLab lab;
    const auto bytes = PinnedHandoverRequest();
    const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());
    REQUIRE(ClassifyHandoverMessage(probe) == LiveHandoverMessage::HANDOVER_REQUEST);

    const uint64_t rejectedBefore = lab.mux.recoveryCounters().staleMessagesRejected;
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);

    const auto &counters = lab.mux.liveHandoverCounters();
    CHECK(counters.requests == 1);
    CHECK(counters.notExecutable == 1);
    CHECK(counters.rejected == 0);
    CHECK(counters.executed == 0);
    // The dispatcher no longer treats a handover message as an unknown
    // procedure: it is classified, refused and answered.
    CHECK(lab.mux.recoveryCounters().staleMessagesRejected == rejectedBefore);
    CHECK(counters.responsesSent == 1);
    CHECK(counters.responsesUnsent == 0);
    CHECK(counters.mutations == 0);

    // Nothing was prepared: no UE, no provisional context, no transport.
    CHECK(lab.mux.registry().size() == 0);
    CHECK(lab.mux.registry().all().empty());

    // The refusal is the standard Handover Failure, naming the UE and the
    // target-side cause, and it is the only thing this eNB transmitted.
    REQUIRE(lab.wire.sent.size() == 1);
    const auto &response = lab.wire.sent.front().second;
    const auto failure = DecodeHandoverFailure(response.data(), response.size());
    CHECK(failure.mmeUeS1apId == 7);
    CHECK(failure.causeCategory == "radioNetwork");
    CHECK(failure.causeValue == CauseHoFailureInTargetEnbOrTargetSystem);
}

TEST_CASE("lte/handover/live: the refusal names every missing capability and mutates nothing")
{
    LiveLab lab;
    const auto bytes = PinnedHandoverRequest();
    const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());

    const std::vector<HandoverSourceRecord> noRecords;
    const auto outcome = HandleLiveHandoverPdu(probe, bytes.data(), bytes.size(), ContextOf(lab.mux, noRecords));

    CHECK(outcome.message == LiveHandoverMessage::HANDOVER_REQUEST);
    CHECK(outcome.disposition == LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE);
    CHECK(outcome.refusal == HandoverIngressRefusal::SOURCE_PROVENANCE_NOT_ESTABLISHED);
    CHECK(outcome.mmeUeS1apId == 7);
    CHECK_FALSE(outcome.mutatedState);
    REQUIRE(outcome.missing.size() == 5);
    CHECK_FALSE(outcome.responsePdu.empty());
    CHECK(lab.mux.registry().size() == 0);
    CHECK(lab.wire.sent.empty());
}

// --- B. A valid Handover Command -------------------------------------------

TEST_CASE("lte/handover/live: a handover command is recognised and refused for a ue this cell does not hold")
{
    LiveLab lab;
    const auto bytes = PinnedHandoverCommand();
    const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());
    REQUIRE(ClassifyHandoverMessage(probe) == LiveHandoverMessage::HANDOVER_COMMAND);

    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
    const auto &counters = lab.mux.liveHandoverCounters();
    CHECK(counters.commands == 1);
    CHECK(counters.rejected == 1);
    CHECK(counters.mutations == 0);
    // A Handover Command has no negative response in this direction, so
    // nothing was transmitted.
    CHECK(lab.wire.sent.empty());

    const std::vector<HandoverSourceRecord> noRecords;
    const auto outcome = HandleLiveHandoverPdu(probe, bytes.data(), bytes.size(), ContextOf(lab.mux, noRecords));
    CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
    CHECK(outcome.refusal == HandoverIngressRefusal::UNKNOWN_UE_CONTEXT);
}

TEST_CASE("lte/handover/live: a handover command for a connected ue changes nothing")
{
    LiveLab lab;
    Establish(lab.mux, lab.ue);
    EnbUeEntry *entry = lab.mux.registry().find(UeRadioId);
    REQUIRE(entry != nullptr);
    const uint32_t teid = entry->bearer.parameters().localTeid;
    const uint32_t generation = entry->accessGeneration;

    HandoverCommand command;
    command.mmeUeS1apId = entry->mmeUeS1apId;
    command.enbUeS1apId = entry->enbUeS1apId;
    command.handoverType = HandoverType::INTRA_LTE;
    command.targetToSource = {0x40, 0x01, 0x02, 0x03};
    const auto bytes = EncodeHandoverCommand(command);

    // No source record: this cell never asked for a handover of this UE.
    const std::vector<HandoverSourceRecord> noRecords;
    const auto outcome =
        HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                              ContextOf(lab.mux, noRecords));
    CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
    CHECK(outcome.refusal == HandoverIngressRefusal::NO_PENDING_HANDOVER);
    CHECK_FALSE(outcome.mutatedState);

    CHECK(lab.mux.registry().find(UeRadioId) == entry);
    CHECK(entry->bearer.parameters().localTeid == teid);
    CHECK(entry->accessGeneration == generation);
    CHECK(entry->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(lab.mux.registry().isRetiredTeid(teid) == false);
}

TEST_CASE("lte/handover/live: a handover command with a pending handover is refused because no rrc can be consumed")
{
    LiveLab lab;
    Establish(lab.mux, lab.ue);
    EnbUeEntry *entry = lab.mux.registry().find(UeRadioId);
    REQUIRE(entry != nullptr);

    HandoverSourceRecord record;
    record.transaction = HandoverTransactionId{entry->mmeUeS1apId, lab.mux.associationEpoch(), 1};
    record.radioUeId = entry->radioUeId;
    record.enbUeS1apId = entry->enbUeS1apId;
    record.mmeUeS1apId = entry->mmeUeS1apId;
    record.accessGeneration = entry->accessGeneration;
    record.associationEpoch = lab.mux.associationEpoch();
    record.target = EnbIdentity{TestPlmn(), 0x00ABCDEu, 2};
    lab.mux.noteHandoverSourceCommand(record);

    HandoverCommand command;
    command.mmeUeS1apId = entry->mmeUeS1apId;
    command.enbUeS1apId = entry->enbUeS1apId;
    command.handoverType = HandoverType::INTRA_LTE;
    command.targetToSource = {0x40, 0x11, 0x22, 0x33};
    const auto bytes = EncodeHandoverCommand(command);

    const auto outcome =
        HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                              ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
    CHECK(outcome.disposition == LiveHandoverDisposition::RECOGNIZED_BUT_NOT_EXECUTABLE);
    CHECK(outcome.refusal == HandoverIngressRefusal::RRC_CONTAINER_NOT_READY);
    CHECK_FALSE(outcome.mutatedState);
    REQUIRE(outcome.missing.size() == 5);

    // The UE is still where it was, on the same transport, and nothing was
    // handed to it over the radio.
    CHECK(lab.mux.registry().find(UeRadioId) == entry);
    CHECK(entry->bearer.active());
    CHECK(entry->enbUeS1apId == record.enbUeS1apId);
    for (const auto &frame : DrainRadio(lab.ue))
        CHECK(frame.type != link::MessageType::SIMULATED_HANDOVER_COMMAND);
}

TEST_CASE("lte/handover/live: a stale association epoch or a wrong identity refuses the command")
{
    LiveLab lab;
    Establish(lab.mux, lab.ue);
    EnbUeEntry *entry = lab.mux.registry().find(UeRadioId);
    REQUIRE(entry != nullptr);

    HandoverSourceRecord record;
    record.transaction = HandoverTransactionId{entry->mmeUeS1apId, lab.mux.associationEpoch(), 1};
    record.radioUeId = entry->radioUeId;
    record.enbUeS1apId = entry->enbUeS1apId;
    record.mmeUeS1apId = entry->mmeUeS1apId;
    record.accessGeneration = entry->accessGeneration;
    record.associationEpoch = lab.mux.associationEpoch();
    lab.mux.noteHandoverSourceCommand(record);

    HandoverCommand command;
    command.mmeUeS1apId = entry->mmeUeS1apId;
    command.enbUeS1apId = entry->enbUeS1apId;
    command.targetToSource = {0x40, 0x01};
    const auto bytes = EncodeHandoverCommand(command);
    const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());

    SUBCASE("the identity pair disagrees with the context")
    {
        auto wrong = command;
        wrong.mmeUeS1apId = command.mmeUeS1apId + 1;
        const auto wrongBytes = EncodeHandoverCommand(wrong);
        const auto outcome = HandleLiveHandoverPdu(ProbeS1apPdu(wrongBytes.data(), wrongBytes.size()),
                                                   wrongBytes.data(), wrongBytes.size(),
                                                   ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::IDENTITY_MISMATCH);
    }
    SUBCASE("the source association moved on")
    {
        // Rebinding the association advances the epoch, so the record made
        // under the previous one is stale.
        CaptureSender second;
        lab.mux.unbindAssociation();
        const uint32_t epoch = lab.mux.bindAssociation(second, 1);
        REQUIRE(epoch != record.associationEpoch);
        const auto outcome = HandleLiveHandoverPdu(probe, bytes.data(), bytes.size(),
                                                   ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::STALE_ASSOCIATION);
        CHECK(lab.mux.registry().find(UeRadioId) == entry);
    }
}

// --- C. Invalid messages ----------------------------------------------------

TEST_CASE("lte/handover/live: malformed and misdirected handover pdus are rejected without side effects")
{
    LiveLab lab;

    SUBCASE("a truncated aper frame")
    {
        auto bytes = PinnedHandoverRequest();
        bytes.resize(bytes.size() - 3);
        lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
        CHECK(lab.mux.liveHandoverCounters().requests == 1);
        CHECK(lab.mux.liveHandoverCounters().rejected == 1);
        CHECK(lab.mux.liveHandoverCounters().mutations == 0);
        CHECK(lab.wire.sent.empty());
    }
    SUBCASE("a handover resource allocation that claims to be a successful outcome")
    {
        auto bytes = PinnedHandoverRequest();
        bytes[0] = 0x20; // the PDU category, changed from initiating to successful outcome
        const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());
        CHECK(probe.kind == S1apPdu::Kind::SUCCESSFUL_OUTCOME);
        CHECK(ClassifyHandoverMessage(probe) == LiveHandoverMessage::NONE);
        const uint64_t before = lab.mux.recoveryCounters().staleMessagesRejected;
        lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
        CHECK(lab.mux.recoveryCounters().staleMessagesRejected == before + 1);
        CHECK(lab.mux.liveHandoverCounters().requests == 0);
        CHECK(lab.wire.sent.empty());
    }
    SUBCASE("a handover preparation that is not a handover preparation")
    {
        auto bytes = PinnedHandoverRequest();
        bytes[1] = 0x03; // procedure code 3, path switch request
        const auto probe = ProbeS1apPdu(bytes.data(), bytes.size());
        CHECK(probe.procedureCode == 3);
        CHECK(ClassifyHandoverMessage(probe) == LiveHandoverMessage::NONE);
        const uint64_t before = lab.mux.recoveryCounters().staleMessagesRejected;
        lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
        CHECK(lab.mux.recoveryCounters().staleMessagesRejected == before + 1);
        CHECK(lab.wire.sent.empty());
    }
    SUBCASE("a request with no mme ue identity")
    {
        auto bytes = PinnedHandoverRequest();
        const auto at = FindPattern(bytes, {0x00, 0x00, 0x00, 0x02, 0x00, 0x07}, 0);
        REQUIRE(at != std::string::npos);
        bytes[at + 1] = 0x03; // MME-UE-S1AP-ID IE id becomes an id this message does not carry
        const auto outcome =
            HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                                  ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::MALFORMED_PDU);
    }
    SUBCASE("an unsupported handover type")
    {
        auto bytes = PinnedHandoverRequest();
        const auto at = FindPattern(bytes, {0x00, 0x01, 0x00, 0x01, 0x00}, 0);
        REQUIRE(at != std::string::npos);
        REQUIRE(DecodeHandoverRequest(bytes.data(), bytes.size()).handoverType == HandoverType::INTRA_LTE);
        // HandoverType is an extensible ENUMERATED: one extension bit and a
        // three-bit root index, so ltetoutran (1) is 0b0_001 padded to 0x10.
        bytes[at + 4] = 0x10;
        const auto outcome =
            HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                                  ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::UNSUPPORTED_HANDOVER_TYPE);
        // The codec refuses the message before any identifier has been read,
        // so there is no MME-UE-S1AP-ID a Handover Failure could be addressed
        // to. The refusal is recorded and nothing is invented on the wire.
        CHECK(outcome.responsePdu.empty());
        CHECK(lab.mux.registry().size() == 0);
    }
    SUBCASE("a handover message with no association bound")
    {
        EnbMultiplexer unbound{Config()};
        const auto bytes = PinnedHandoverRequest();
        const auto outcome =
            HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                                  LiveHandoverContext{&unbound.registry(), nullptr, 0, false});
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::STALE_ASSOCIATION);
        CHECK(unbound.registry().size() == 0);
    }
    SUBCASE("a handover cancel, which has no codec here")
    {
        // Procedure 4, initiating. The envelope is the request's with the
        // procedure code changed, so the classification is about the code and
        // nothing else.
        auto bytes = PinnedHandoverRequest();
        bytes[1] = 0x04;
        const auto outcome =
            HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                                  ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
        CHECK(outcome.message == LiveHandoverMessage::HANDOVER_CANCEL);
        CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
        CHECK(outcome.refusal == HandoverIngressRefusal::UNSUPPORTED_PROCEDURE);
        CHECK(outcome.responsePdu.empty());
        CHECK(lab.mux.registry().size() == 0);
    }
}

TEST_CASE("lte/handover/live: the request checks refuse an unusable bearer or security set")
{
    const auto bytes = PinnedHandoverRequest();
    const HandoverRequest valid = DecodeHandoverRequest(bytes.data(), bytes.size());
    HandoverIngressRefusal refusal = HandoverIngressRefusal::NONE;
    std::string detail;

    CHECK(ValidateHandoverRequestForTarget(valid, &refusal, &detail));
    CHECK(refusal == HandoverIngressRefusal::NONE);

    SUBCASE("no bearer at all")
    {
        auto request = valid;
        request.erabs.clear();
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::ERAB_INVENTORY_INVALID);
    }
    SUBCASE("the same e-rab twice")
    {
        auto request = valid;
        request.erabs.push_back(request.erabs.front());
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::ERAB_INVENTORY_INVALID);
    }
    SUBCASE("an e-rab identity outside the identifier range")
    {
        auto request = valid;
        request.erabs.front().erabId = 16;
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::ERAB_INVENTORY_INVALID);
    }
    SUBCASE("a bearer with no qci")
    {
        auto request = valid;
        request.erabs.front().qos.qci = 0;
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::ERAB_INVENTORY_INVALID);
    }
    SUBCASE("a bearer with no sgw tunnel")
    {
        auto request = valid;
        request.erabs.front().sgwTeid = {0, 0, 0, 0};
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::ERAB_INVENTORY_INVALID);
    }
    SUBCASE("an inter-rat handover")
    {
        auto request = valid;
        request.handoverType = HandoverType::LTE_TO_UTRAN;
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::UNSUPPORTED_HANDOVER_TYPE);
    }
    SUBCASE("no container")
    {
        auto request = valid;
        request.sourceToTarget.clear();
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::TRANSPARENT_CONTAINER_INVALID);
    }
    SUBCASE("an all-zero next hop parameter")
    {
        auto request = valid;
        request.securityContext.nextHopParameter.fill(0);
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::SECURITY_CONTEXT_INVALID);
    }
    SUBCASE("no algorithm this cell could apply")
    {
        auto request = valid;
        request.encryptionAlgorithms = {0, 0};
        CHECK_FALSE(ValidateHandoverRequestForTarget(request, &refusal, &detail));
        CHECK(refusal == HandoverIngressRefusal::SECURITY_CONTEXT_INVALID);
    }
}

TEST_CASE("lte/handover/live: a request with fabricated security material is rejected rather than accepted")
{
    LiveLab lab;
    HandoverRequest request;
    request.mmeUeS1apId = MmeUeS1apId;
    request.handoverType = HandoverType::INTRA_LTE;
    request.causeCategory = "radioNetwork";
    request.causeValue = 16;
    request.ueAmbr.downlink = 1000;
    request.ueAmbr.uplink = 1000;
    ErabToBeSetupItemHoReq bearer;
    bearer.erabId = 5;
    bearer.sgwAddress = {127, 0, 0, 2};
    bearer.sgwTeid = {0, 0, 0, 30};
    bearer.qos.qci = 9;
    bearer.qos.priorityLevel = 15;
    request.erabs = {bearer};
    request.sourceToTarget = {0x40, 0x01, 0x02};
    request.encryptionAlgorithms = {0x80, 0x00};
    request.integrityAlgorithms = {0x40, 0x00};
    request.securityContext.nextHopChainingCount = 1;
    // The exact thing the work order forbids treating as usable.
    request.securityContext.nextHopParameter.fill(0);

    const auto bytes = EncodeHandoverRequest(request);
    const auto outcome =
        HandleLiveHandoverPdu(ProbeS1apPdu(bytes.data(), bytes.size()), bytes.data(), bytes.size(),
                              ContextOf(lab.mux, lab.mux.handoverSourceRecords()));
    CHECK(outcome.disposition == LiveHandoverDisposition::REJECTED);
    CHECK(outcome.refusal == HandoverIngressRefusal::SECURITY_CONTEXT_INVALID);
    CHECK_FALSE(outcome.mutatedState);
    CHECK(lab.mux.registry().size() == 0);
    // A rejected request still gets the standard failure, not silence.
    REQUIRE_FALSE(outcome.responsePdu.empty());
    CHECK(DecodeHandoverFailure(outcome.responsePdu.data(), outcome.responsePdu.size()).mmeUeS1apId == MmeUeS1apId);
}

// --- D. Cross-UE isolation --------------------------------------------------

TEST_CASE("lte/handover/live: a refused handover message for one ue leaves another ue untouched")
{
    LiveLab lab;
    FakeUe other{8};
    Establish(lab.mux, lab.ue, MmeUeS1apId);
    Establish(lab.mux, other, MmeUeS1apId + 1);

    EnbUeEntry *first = lab.mux.registry().find(UeRadioId);
    EnbUeEntry *second = lab.mux.registry().find(8);
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    const uint32_t firstTeid = first->bearer.parameters().localTeid;
    const uint32_t secondTeid = second->bearer.parameters().localTeid;
    const uint32_t secondGeneration = second->accessGeneration;
    const uint32_t secondEnbId = second->enbUeS1apId;

    // A handover request naming a UE identity neither context holds, and a
    // malformed frame, both arrive on the shared association.
    auto bytes = PinnedHandoverRequest();
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);
    bytes.resize(bytes.size() - 5);
    lab.mux.handleS1ap(bytes.data(), bytes.size(), 1);

    CHECK(lab.mux.liveHandoverCounters().mutations == 0);
    CHECK(lab.mux.registry().find(UeRadioId) == first);
    CHECK(lab.mux.registry().find(8) == second);
    CHECK(first->bearer.parameters().localTeid == firstTeid);
    CHECK(second->bearer.parameters().localTeid == secondTeid);
    CHECK(second->accessGeneration == secondGeneration);
    CHECK(second->enbUeS1apId == secondEnbId);
    CHECK(second->bearer.active());
    CHECK(lab.mux.registry().findByLocalTeid(secondTeid) == second);
    CHECK_FALSE(lab.mux.registry().isRetiredTeid(secondTeid));
    CHECK(lab.mux.registry().size() == 2);
}

// --- E. Source/target isolation ---------------------------------------------

TEST_CASE("lte/handover/live: a handover message on one cell does not reach another cell")
{
    LiveLab first;
    CaptureSender secondWire;
    EnbMultiplexer second{Config(0x00ABCDEu, "127.0.0.3", 2), secondWire};

    FakeUe secondUe{8};
    Establish(second, secondUe, MmeUeS1apId + 1);
    EnbUeEntry *entry = second.registry().find(8);
    REQUIRE(entry != nullptr);
    const uint32_t teid = entry->bearer.parameters().localTeid;
    const uint32_t generation = entry->accessGeneration;

    const auto bytes = PinnedHandoverRequest();
    first.mux.handleS1ap(bytes.data(), bytes.size(), 1);

    // The second cell is exactly as it was: its own registry, its own
    // transport, its own counters.
    CHECK(second.liveHandoverCounters().requests == 0);
    CHECK(second.registry().size() == 1);
    CHECK(second.registry().find(8) == entry);
    CHECK(entry->bearer.parameters().localTeid == teid);
    CHECK(entry->accessGeneration == generation);
    CHECK(second.registry().findByLocalTeid(teid) == entry);
    CHECK(first.mux.registry().size() == 0);
    CHECK(first.mux.registry().findByLocalTeid(teid) == nullptr);
}

// --- H. No premature transition --------------------------------------------

TEST_CASE("lte/handover/live: no refused handover message produces a notify, a release or a radio frame")
{
    LiveLab lab;
    Establish(lab.mux, lab.ue);
    EnbUeEntry *entry = lab.mux.registry().find(UeRadioId);
    REQUIRE(entry != nullptr);
    DrainRadio(lab.ue);
    // The establishment's own S1AP responses are not part of this case.
    lab.wire.sent.clear();

    // A request, a command for a different ue, and a preparation failure.
    auto request = PinnedHandoverRequest();
    lab.mux.handleS1ap(request.data(), request.size(), 1);

    HandoverCommand command;
    command.mmeUeS1apId = entry->mmeUeS1apId;
    command.enbUeS1apId = entry->enbUeS1apId;
    command.targetToSource = {0x40};
    const auto commandBytes = EncodeHandoverCommand(command);
    lab.mux.handleS1ap(commandBytes.data(), commandBytes.size(), 1);

    HandoverPreparationFailure preparationFailure;
    preparationFailure.mmeUeS1apId = entry->mmeUeS1apId;
    preparationFailure.enbUeS1apId = entry->enbUeS1apId;
    preparationFailure.causeValue = 6;
    const auto failureBytes = EncodeHandoverPreparationFailure(preparationFailure);
    lab.mux.handleS1ap(failureBytes.data(), failureBytes.size(), 1);

    // Exactly one message left this eNB: the Handover Failure answering the
    // request. Nothing else.
    REQUIRE(lab.wire.sent.size() == 1);
    const auto response = ProbeS1apPdu(lab.wire.sent.front().second.data(), lab.wire.sent.front().second.size());
    CHECK(response.kind == S1apPdu::Kind::UNSUCCESSFUL_OUTCOME);
    CHECK(response.procedureCode == 1);

    // The UE never received a handover command, and its context is intact.
    for (const auto &frame : DrainRadio(lab.ue))
        CHECK(frame.type != link::MessageType::SIMULATED_HANDOVER_COMMAND);
    CHECK(lab.mux.registry().find(UeRadioId) == entry);
    CHECK(entry->s1 == UeS1State::BEARER_ACTIVE);
    CHECK(entry->bearer.active());
    CHECK(lab.mux.liveHandoverCounters().mutations == 0);
    CHECK(lab.mux.liveHandoverCounters().executed == 0);
    CHECK(lab.mux.liveHandoverCounters().requests == 1);
    CHECK(lab.mux.liveHandoverCounters().commands == 1);
    CHECK(lab.mux.liveHandoverCounters().preparationFailures == 1);
}
