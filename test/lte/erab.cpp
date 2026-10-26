//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>

#include <cstdint>
#include <vector>

namespace
{

// The field values below are the ones the laboratory Open5GS MME actually sent
// in the E-RAB Setup Request that created the Phase 7 dedicated bearer. The
// capture itself is not committed; only these observable values are pinned so a
// silent codec change cannot go unnoticed.
lte::enb::s1ap::ErabSetupRequest SampleSetupRequest()
{
    lte::enb::s1ap::ErabSetupRequest request;
    request.mmeUeS1apId = 23;
    request.enbUeS1apId = 1;

    lte::enb::s1ap::ErabToBeSetupItem item;
    item.erabId = 6;
    item.qci = 7;
    item.priorityLevel = 8;
    item.preemptionCapability = false;
    item.preemptionVulnerability = false;
    item.transportLayerAddress = {192, 168, 64, 128};
    item.gtpTeid = {0x00, 0x00, 0xFF, 0x52};
    item.nasPduPresent = true;
    item.nasPdu = {0x27, 0x3F, 0x90, 0x7E, 0x36, 0x03, 0x62, 0x00, 0xC5, 0x05};
    request.erabs = {item};
    return request;
}

} // namespace

TEST_CASE("lte/erab: setup request round-trip preserves identity, QoS and transport")
{
    const auto request = SampleSetupRequest();
    const auto encoded = lte::enb::s1ap::EncodeErabSetupRequest(request);
    const auto decoded = lte::enb::s1ap::DecodeErabSetupRequest(encoded.data(), encoded.size());

    CHECK(decoded.mmeUeS1apId == 23);
    CHECK(decoded.enbUeS1apId == 1);
    REQUIRE(decoded.erabs.size() == 1);

    const auto &erab = decoded.erabs.front();
    CHECK(erab.erabId == 6);
    CHECK(erab.qci == 7);
    CHECK(erab.priorityLevel == 8);
    CHECK(erab.transportLayerAddress == std::array<uint8_t, 4>{192, 168, 64, 128});
    CHECK(erab.gtpTeid == std::array<uint8_t, 4>{0x00, 0x00, 0xFF, 0x52});
    REQUIRE(erab.nasPduPresent);
    CHECK(erab.nasPdu == request.erabs[0].nasPdu);
}

TEST_CASE("lte/erab: adding a dedicated E-RAB is not mistaken for Initial Context Setup")
{
    // Procedures 5 and 9 both carry an E-RAB list; only the procedure code
    // separates adding a bearer from creating the whole UE context.
    const auto encoded = lte::enb::s1ap::EncodeErabSetupRequest(SampleSetupRequest());

    CHECK_THROWS_AS(lte::enb::s1ap::DecodeInitialContextSetupRequest(encoded.data(), encoded.size()),
                    lte::enb::s1ap::CodecError);
}

TEST_CASE("lte/erab: an encoder refuses a request without an E-RAB")
{
    auto request = SampleSetupRequest();
    request.erabs.clear();

    CHECK_THROWS_AS(lte::enb::s1ap::EncodeErabSetupRequest(request), lte::enb::s1ap::CodecError);
}

TEST_CASE("lte/erab: an encoder refuses a zero UE S1AP identity")
{
    auto request = SampleSetupRequest();
    request.enbUeS1apId = 0;

    CHECK_THROWS_AS(lte::enb::s1ap::EncodeErabSetupRequest(request), lte::enb::s1ap::CodecError);
}

TEST_CASE("lte/erab: a setup response carries procedure code 5 as a successful outcome")
{
    lte::enb::s1ap::ErabSetupItem established;
    established.erabId = 6;
    established.transportLayerAddress = {127, 0, 0, 5};
    established.gtpTeid = {0x11, 0x22, 0x33, 0x44};

    const auto encoded = lte::enb::s1ap::EncodeErabSetupResponse(23, 1, {established}, {});
    REQUIRE(encoded.size() > 4);
    CHECK(encoded[1] == 0x05);
}

TEST_CASE("lte/erab: a setup response can report a failed E-RAB alongside a successful one")
{
    lte::enb::s1ap::ErabSetupItem established;
    established.erabId = 6;
    established.transportLayerAddress = {127, 0, 0, 5};
    established.gtpTeid = {0x11, 0x22, 0x33, 0x44};

    lte::enb::s1ap::ErabFailedItem failed;
    failed.erabId = 7;
    failed.causeCategory = "radioNetwork";
    failed.causeValue = 0;

    const auto withFailure = lte::enb::s1ap::EncodeErabSetupResponse(23, 1, {established}, {failed});
    const auto withoutFailure = lte::enb::s1ap::EncodeErabSetupResponse(23, 1, {established}, {});

    // The failed list is optional, so reporting a failure must change the
    // message rather than being silently dropped.
    CHECK(withFailure.size() > withoutFailure.size());
    CHECK(withFailure[1] == 0x05);
}

TEST_CASE("lte/erab: a setup response cannot claim success without any established E-RAB")
{
    CHECK_THROWS_AS(lte::enb::s1ap::EncodeErabSetupResponse(23, 1, {}, {}), lte::enb::s1ap::CodecError);
}

TEST_CASE("lte/erab: release command round-trip preserves the target E-RAB")
{
    lte::enb::s1ap::ErabReleaseCommand command;
    command.mmeUeS1apId = 23;
    command.enbUeS1apId = 1;
    command.erabIds = {6};
    command.causeCategory = "radioNetwork";
    command.causeValue = 0;

    const auto encoded = lte::enb::s1ap::EncodeErabReleaseCommand(command);
    const auto decoded = lte::enb::s1ap::DecodeErabReleaseCommand(encoded.data(), encoded.size());

    CHECK(decoded.mmeUeS1apId == 23);
    CHECK(decoded.enbUeS1apId == 1);
    REQUIRE(decoded.erabIds.size() == 1);
    CHECK(decoded.erabIds[0] == 6);
    CHECK(decoded.causeCategory == "radioNetwork");
    CHECK(decoded.causeValue == 0);
}

TEST_CASE("lte/erab: a release command for several E-RABs keeps every requested identity")
{
    lte::enb::s1ap::ErabReleaseCommand command;
    command.mmeUeS1apId = 23;
    command.enbUeS1apId = 1;
    command.erabIds = {6, 7};

    const auto encoded = lte::enb::s1ap::EncodeErabReleaseCommand(command);
    const auto decoded = lte::enb::s1ap::DecodeErabReleaseCommand(encoded.data(), encoded.size());

    REQUIRE(decoded.erabIds.size() == 2);
    CHECK(decoded.erabIds[0] == 6);
    CHECK(decoded.erabIds[1] == 7);
}

TEST_CASE("lte/erab: a release command without a cause leaves the cause unset")
{
    lte::enb::s1ap::ErabReleaseCommand command;
    command.mmeUeS1apId = 23;
    command.enbUeS1apId = 1;
    command.erabIds = {6};

    const auto encoded = lte::enb::s1ap::EncodeErabReleaseCommand(command);
    const auto decoded = lte::enb::s1ap::DecodeErabReleaseCommand(encoded.data(), encoded.size());

    CHECK(decoded.causeCategory.empty());
}

TEST_CASE("lte/erab: a release response carries procedure code 7")
{
    const auto encoded = lte::enb::s1ap::EncodeErabReleaseResponse(23, 1, {6});
    REQUIRE(encoded.size() > 4);
    CHECK(encoded[1] == 0x07);
}

TEST_CASE("lte/erab: a release response requires at least one E-RAB")
{
    CHECK_THROWS_AS(lte::enb::s1ap::EncodeErabReleaseResponse(23, 1, {}), lte::enb::s1ap::CodecError);
}

TEST_CASE("lte/erab: a truncated setup request is rejected")
{
    const auto encoded = lte::enb::s1ap::EncodeErabSetupRequest(SampleSetupRequest());
    std::vector<uint8_t> truncated(encoded.begin(), encoded.begin() + 6);

    CHECK_THROWS_AS(lte::enb::s1ap::DecodeErabSetupRequest(truncated.data(), truncated.size()),
                    lte::enb::s1ap::CodecError);
}
