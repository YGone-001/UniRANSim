//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-A: simulated Uu transport, RLC TM, SRB0 and the initial RRC
// access exchange (RRCConnectionRequest / Setup / Reject) over CCCH.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/rlc_tm.hpp>
#include <lte/rrc-runtime/rrc_initial_access.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

#include <functional>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using namespace lte;

namespace
{

constexpr uint32_t Association = 0x01020304U;

} // namespace

TEST_CASE("lte/b6a/transport envelope carries the payload and rejects malformed frames")
{
    uu::Frame frame;
    frame.association = Association;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::CCCH;
    frame.payload = {0x30, 0x02, 0x20};

    const auto bytes = uu::EncodeFrame(frame);
    CHECK(bytes.size() == uu::EnvelopeSize + 3);

    uu::Frame decoded;
    std::string why;
    REQUIRE(uu::DecodeFrame(bytes.data(), bytes.size(), decoded, &why));
    CHECK(decoded.association == Association);
    CHECK(decoded.direction == uu::Direction::UPLINK);
    CHECK(decoded.channel == uu::LogicalChannel::CCCH);
    CHECK(decoded.payload == frame.payload);

    auto badMagic = bytes;
    badMagic[0] = 'X';
    CHECK_FALSE(uu::DecodeFrame(badMagic.data(), badMagic.size(), decoded, &why));

    auto badVersion = bytes;
    badVersion[2] = 9;
    CHECK_FALSE(uu::DecodeFrame(badVersion.data(), badVersion.size(), decoded, &why));

    auto badLength = bytes;
    badLength[11] = 0x7F;
    CHECK_FALSE(uu::DecodeFrame(badLength.data(), badLength.size(), decoded, &why));

    auto truncated = bytes;
    truncated.resize(bytes.size() - 1);
    CHECK_FALSE(uu::DecodeFrame(truncated.data(), truncated.size(), decoded, &why));

    CHECK_FALSE(uu::DecodeFrame(bytes.data(), 4, decoded, &why));
}

TEST_CASE("lte/b6a/rlc tm preserves the sdu and refuses what it cannot carry")
{
    auto entity = rlc::TmEntity::Create(Association);
    const std::vector<uint8_t> sdu = {1, 2, 3, 4, 5};

    // TM adds no header, no SN and no MAC-I: the PDU is the SDU.
    CHECK(entity.Submit(sdu) == sdu);
    CHECK(entity.Deliver(sdu) == sdu);

    CHECK_THROWS_AS(entity.Submit({}), rlc::TmException);
    const std::vector<uint8_t> oversized(rlc::TmEntity::MaxSduBytes + 1, 0xAA);
    try
    {
        (void)entity.Submit(oversized);
        FAIL("oversized SDU was accepted");
    }
    catch (const rlc::TmException &error)
    {
        CHECK(error.Reason() == rlc::TmError::OVERSIZED_SDU);
    }

    entity.Release();
    CHECK(entity.Released());
    CHECK_THROWS_AS(entity.Submit(sdu), rlc::TmException);
}

TEST_CASE("lte/b6a/rrc initial access messages round trip")
{
    rrc::RrcConnectionRequestMessage request;
    request.mmec = 0x01;
    request.mTmsi = 0xC000038D;
    const auto requestBytes = rrc::EncodeRrcConnectionRequest(request);
    REQUIRE_FALSE(requestBytes.empty());

    rrc::RrcConnectionRequestMessage decodedRequest;
    REQUIRE(rrc::DecodeRrcConnectionRequest(requestBytes.data(), requestBytes.size(), decodedRequest));
    CHECK(decodedRequest.mmec == request.mmec);
    CHECK(decodedRequest.mTmsi == request.mTmsi);

    rrc::RrcConnectionSetupMessage setup;
    setup.transactionId = 0;
    setup.srbIdentity = 1;
    setup.tPollRetransmit = 2;
    setup.pollPdu = 1;
    setup.pollByte = 1;
    setup.maxRetxThreshold = 5;
    setup.tReordering = 1;
    setup.tStatusProhibit = 1;
    const auto setupBytes = rrc::EncodeRrcConnectionSetup(setup);
    REQUIRE_FALSE(setupBytes.empty());

    rrc::RrcConnectionSetupMessage decodedSetup;
    REQUIRE(rrc::DecodeRrcConnectionSetup(setupBytes.data(), setupBytes.size(), decodedSetup));
    CHECK(decodedSetup.srbIdentity == 1);
    CHECK(decodedSetup.maxRetxThreshold == 5);
    CHECK(decodedSetup.tReordering == 1);

    rrc::RrcConnectionRejectMessage reject;
    reject.waitTime = 4;
    const auto rejectBytes = rrc::EncodeRrcConnectionReject(reject);
    rrc::RrcConnectionRejectMessage decodedReject;
    REQUIRE(rrc::DecodeRrcConnectionReject(rejectBytes.data(), rejectBytes.size(), decodedReject));
    CHECK(decodedReject.waitTime == 4);

    // A request is not a setup and must not decode as one.
    CHECK_FALSE(rrc::DecodeRrcConnectionSetup(requestBytes.data(), requestBytes.size(), decodedSetup));
}

TEST_CASE("lte/b6a/the ue stops at srb1 configuring and never claims rrc connected")
{
    auto ue = rrc::UeInitialAccess::Idle(Association, 0x01, 0xC000038D);
    const auto request = ue.BuildRequest();
    CHECK(ue.State() == rrc::RrcState::RRC_CONNECTION_REQUEST_PENDING);

    rrc::EnbInitialAccess enb;
    const auto answer = enb.OnRequest(Association, request);
    CHECK(enb.StateOf(Association) == rrc::RrcState::RRC_SETUP_PENDING);

    ue.OnDownlink(answer);
    CHECK(ue.State() == rrc::RrcState::RRC_SRB1_CONFIGURING);
    REQUIRE(ue.StagedSrb1().has_value());
    CHECK(ue.StagedSrb1()->srbIdentity == 1);
    CHECK(ue.State() != rrc::RrcState::RRC_CONNECTED);
}

TEST_CASE("lte/b6a/duplicate requests, rejection, timeout and cross-ue isolation")
{
    auto ue = rrc::UeInitialAccess::Idle(Association, 0x01, 0xC000038D);
    const auto request = ue.BuildRequest();

    rrc::EnbInitialAccess enb;
    const auto first = enb.OnRequest(Association, request);
    const auto second = enb.OnRequest(Association, request);
    // The same request returns the same answer and creates one context.
    CHECK(first == second);
    CHECK(enb.ContextCount() == 1);

    // A different TMSI on the same association is not the same UE.
    rrc::RrcConnectionRequestMessage other = {0x01, 0xC0000999, 0};
    const auto otherBytes = rrc::EncodeRrcConnectionRequest(other);
    CHECK_THROWS_AS(enb.OnRequest(Association, otherBytes), rrc::AccessException);
    CHECK(enb.ContextCount() == 1);

    // A second association is a second context, untouched by the first.
    const auto otherAssociation = Association + 1;
    (void)enb.OnRequest(otherAssociation, otherBytes);
    CHECK(enb.ContextCount() == 2);
    CHECK(enb.StateOf(Association) == rrc::RrcState::RRC_SETUP_PENDING);

    // Rejection.
    rrc::EnbInitialAccess rejecting;
    rejecting.SetReject(true, 3);
    const auto rejectAnswer = rejecting.OnRequest(Association, request);
    rrc::RrcConnectionRejectMessage reject;
    REQUIRE(rrc::DecodeRrcConnectionReject(rejectAnswer.data(), rejectAnswer.size(), reject));
    CHECK(reject.waitTime == 3);
    CHECK(rejecting.StateOf(Association) == rrc::RrcState::RRC_CONNECTION_REJECTED);

    // Timeout leaves the UE failed, not connected.
    auto timedOut = rrc::UeInitialAccess::Idle(Association, 0x01, 0xC000038D);
    (void)timedOut.BuildRequest();
    timedOut.OnTimeout();
    CHECK(timedOut.State() == rrc::RrcState::RRC_CONNECTION_FAILED);

    // A malformed request creates nothing.
    rrc::EnbInitialAccess strict;
    const std::vector<uint8_t> garbage = {0xDE, 0xAD};
    CHECK_THROWS_AS(strict.OnRequest(Association, garbage), rrc::AccessException);
    CHECK(strict.ContextCount() == 0);
}

TEST_CASE("lte/b6a/loss is observable and never silently retried")
{
    auto ueSocket = uu::Socket::BindLoopback(0, nullptr);
    auto enbSocket = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(ueSocket.has_value());
    REQUIRE(enbSocket.has_value());

    uu::LinkModel lossy;
    lossy.dropEveryNth = 1;  // every frame is lost
    ueSocket->SetLinkModel(lossy);

    auto ue = rrc::UeInitialAccess::Idle(Association, 0x01, 0xC000038D);
    const auto request = ue.BuildRequest();

    uu::Frame frame;
    frame.association = Association;
    frame.direction = uu::Direction::UPLINK;
    frame.channel = uu::LogicalChannel::CCCH;
    frame.payload = request;
    REQUIRE(ueSocket->Send(enbSocket->Port(), frame, nullptr));
    CHECK(ueSocket->Dropped() == 1);

    uu::Frame received;
    CHECK_FALSE(enbSocket->Receive(received, 50, nullptr));
    ue.OnTimeout();
    CHECK(ue.State() == rrc::RrcState::RRC_CONNECTION_FAILED);
}

TEST_CASE("lte/b6a/an independent ue process completes the setup exchange with the enb process")
{
    auto ueSocket = uu::Socket::BindLoopback(0, nullptr);
    auto enbSocket = uu::Socket::BindLoopback(0, nullptr);
    REQUIRE(ueSocket.has_value());
    REQUIRE(enbSocket.has_value());

    const uint16_t uePort = ueSocket->Port();
    const uint16_t enbPort = enbSocket->Port();

    const pid_t child = ::fork();
    REQUIRE(child >= 0);

    if (child == 0)
    {
        // The UE runs in its own process, with its own socket and its own state.
        auto ue = rrc::UeInitialAccess::Idle(Association, 0x01, 0xC000038D);
        uu::Frame request;
        request.association = Association;
        request.direction = uu::Direction::UPLINK;
        request.channel = uu::LogicalChannel::CCCH;
        request.payload = ue.BuildRequest();
        if (!ueSocket->Send(enbPort, request, nullptr))
            ::_exit(2);

        uu::Frame downlink;
        if (!ueSocket->Receive(downlink, 2000, nullptr))
            ::_exit(3);
        if (downlink.direction != uu::Direction::DOWNLINK || downlink.channel != uu::LogicalChannel::CCCH)
            ::_exit(4);
        try
        {
            ue.OnDownlink(downlink.payload);
        }
        catch (...)
        {
            ::_exit(5);
        }
        ::_exit(ue.State() == rrc::RrcState::RRC_SRB1_CONFIGURING ? 0 : 6);
    }

    // The eNB process.
    uu::Frame uplink;
    REQUIRE(enbSocket->Receive(uplink, 2000, nullptr));
    CHECK(uplink.association == Association);
    CHECK(uplink.direction == uu::Direction::UPLINK);
    CHECK(uplink.channel == uu::LogicalChannel::CCCH);

    rrc::EnbInitialAccess enb;
    const auto answer = enb.OnRequest(uplink.association, uplink.payload);
    CHECK(enb.StateOf(Association) == rrc::RrcState::RRC_SETUP_PENDING);

    uu::Frame downlink;
    downlink.association = Association;
    downlink.direction = uu::Direction::DOWNLINK;
    downlink.channel = uu::LogicalChannel::CCCH;
    downlink.payload = answer;
    REQUIRE(enbSocket->Send(uePort, downlink, nullptr));

    int status = 0;
    ::waitpid(child, &status, 0);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
    // The eNB never claims a connected UE: SetupComplete belongs to B6-B.
    CHECK(enb.StateOf(Association) != rrc::RrcState::RRC_CONNECTED);
}
