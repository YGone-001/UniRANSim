//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/config.hpp>
#include <lte/enb/types.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace
{

std::vector<uint8_t> FromHex(const std::string &hex)
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i < hex.size();)
    {
        while (i < hex.size() && std::isspace(static_cast<unsigned char>(hex[i])))
            ++i;
        if (i == hex.size())
            break;
        result.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        i += 2;
    }
    return result;
}

const char *ValidConfig = R"(
mcc: '460'
mnc: '02'
enbId: 0x19B
tac: 1
enbName: UERANSIM-lte-enb
s1apIp: 127.0.0.1
mme:
  address: 127.0.0.2
  port: 36412
pagingDrx: 128
sctp:
  maxAttempts: 4
  retryDelayMs: 10
  responseTimeoutMs: 1000
  connectMaxAttempts: 2
  connectTimeoutMs: 500
)";

} // namespace

TEST_CASE("lte/enb/config: a valid LTE eNB configuration is parsed")
{
    auto config = lte::enb::ParseConfig(ValidConfig);
    CHECK(config.plmn.mcc == "460");
    CHECK(config.plmn.mnc == "02");
    CHECK(config.enbId == 0x19B);
    CHECK(config.tac == 1);
    CHECK(config.mmePort == 36412);
    CHECK(config.pagingDrx == 128);
    CHECK(config.retry.maxAttempts == 4);
}

TEST_CASE("lte/enb/config: malformed identifiers and ports are rejected")
{
    CHECK_THROWS(
        lte::enb::ParseConfig(std::string(ValidConfig).replace(std::string(ValidConfig).find("'460'"), 5, "'41'")));
    CHECK_THROWS(
        lte::enb::ParseConfig(std::string(ValidConfig).replace(std::string(ValidConfig).find("'02'"), 4, "'0x'")));
    CHECK_THROWS(
        lte::enb::ParseConfig(std::string(ValidConfig).replace(std::string(ValidConfig).find("0x19B"), 5, "0x100000")));
    CHECK_THROWS(lte::enb::ParseConfig(
        std::string(ValidConfig).replace(std::string(ValidConfig).find("tac: 1"), 6, "tac: 65536")));
    CHECK_THROWS(lte::enb::ParseConfig(
        std::string(ValidConfig).replace(std::string(ValidConfig).find("port: 36412"), 11, "port: 0")));
}

TEST_CASE("lte/enb/codec: PLMN TBCD encoding handles two- and three-digit MNCs")
{
    auto twoDigit = lte::enb::s1ap::EncodePlmn({"460", "02"});
    CHECK(twoDigit == std::array<uint8_t, 3>{0x64, 0xF0, 0x20});
    auto threeDigit = lte::enb::s1ap::EncodePlmn({"310", "260"});
    CHECK(threeDigit == std::array<uint8_t, 3>{0x13, 0x00, 0x62});
    CHECK(lte::enb::s1ap::DecodePlmn(twoDigit.data(), twoDigit.size()).mnc == "02");
    CHECK(lte::enb::s1ap::DecodePlmn(threeDigit.data(), threeDigit.size()).mnc == "260");
}

TEST_CASE("lte/enb/codec: S1 Setup Request encodes and decodes all mandatory information")
{
    auto config = lte::enb::ParseConfig(ValidConfig);
    auto encoded = lte::enb::s1ap::EncodeS1SetupRequest(config);
    REQUIRE(!encoded.empty());
    auto decoded = lte::enb::s1ap::DecodeS1SetupRequest(encoded.data(), encoded.size());
    CHECK(decoded.plmn.mcc == "460");
    CHECK(decoded.plmn.mnc == "02");
    CHECK(decoded.enbId == 0x19B);
    CHECK(decoded.tac == 1);
    REQUIRE(decoded.broadcastPlmns.size() == 1);
    CHECK(decoded.broadcastPlmns[0].toString() == "460/02");
    CHECK(decoded.pagingDrx == 128);
    CHECK(decoded.enbName == "UERANSIM-lte-enb");

    // This exact request was accepted by Open5GS 2.8.0 serving PLMN 460/02.
    auto open5gsAccepted = lte::enb::s1ap::EncodeS1SetupRequest(config);
    CHECK(open5gsAccepted == FromHex("00 11 00 35 00 00 04 00 3b 00 08 00 64 f0 20 00 00 19 b0 00 3c 40 12 07 80 "
                                     "55 45 52 41 4e 53 49 4d 2d 6c 74 65 2d 65 6e 62 00 40 00 07 00 00 00 40 64 f0 20 "
                                     "00 89 40 01 40"));
}

TEST_CASE("lte/enb/codec: independently captured srsRAN S1 Setup Response is decoded")
{
    // srsRAN_4G bef8680d5, srsenb/test/s1ap/s1ap_test.cc::run_s1_setup.
    auto fixture = FromHex("20 11 00 25 00 00 03 00 3d 40 0a 03 80 73 72 73 6d 6d 65 30 31 "
                           "00 69 00 0b 00 00 00 f1 10 00 00 01 00 00 1a 00 57 40 01 ff");
    auto outcome = lte::enb::s1ap::DecodeS1SetupOutcome(fixture.data(), fixture.size());
    CHECK(outcome.type == lte::enb::s1ap::OutcomeType::RESPONSE);
    CHECK(outcome.mmeName == "srsmme01");
    CHECK(outcome.relativeMmeCapacity == 255);
    REQUIRE(outcome.servedGummeis.size() == 1);
    CHECK(outcome.servedGummeis[0].plmns[0].toString() == "001/01");
    CHECK(outcome.servedGummeis[0].groupIds[0] == 0x0100);
    CHECK(outcome.servedGummeis[0].mmeCodes[0] == 0x1A);
}

TEST_CASE("lte/enb/codec: S1 Setup Failure exposes Cause and TimeToWait")
{
    // TS 36.413 APER: unsuccessfulOutcome/S1SetupFailure, misc/unknown-PLMN, TimeToWait v5s.
    auto fixture = FromHex("40 11 00 0d 00 00 02 00 02 40 01 45 00 41 40 01 20");
    auto outcome = lte::enb::s1ap::DecodeS1SetupOutcome(fixture.data(), fixture.size());
    CHECK(outcome.type == lte::enb::s1ap::OutcomeType::FAILURE);
    CHECK(outcome.causeCategory == "misc");
    CHECK(outcome.causeValue == 5);
    CHECK(outcome.causeText == "unknown-PLMN");
    CHECK(outcome.timeToWaitSeconds == 5);
}

TEST_CASE("lte/enb/codec: every truncation of a valid response is rejected")
{
    auto fixture = FromHex("20 11 00 25 00 00 03 00 3d 40 0a 03 80 73 72 73 6d 6d 65 30 31 "
                           "00 69 00 0b 00 00 00 f1 10 00 00 01 00 00 1a 00 57 40 01 ff");
    for (size_t length = 0; length < fixture.size(); ++length)
        CHECK_THROWS(lte::enb::s1ap::DecodeS1SetupOutcome(fixture.data(), length));
}

TEST_CASE("lte/enb/codec: malformed and incomplete outcomes are rejected")
{
    auto missingCapacity = FromHex("20 11 00 20 00 00 02 00 3d 40 0a 03 80 73 72 73 6d 6d 65 30 31 "
                                   "00 69 00 0b 00 00 00 f1 10 00 00 01 00 00 1a");
    CHECK_THROWS(lte::enb::s1ap::DecodeS1SetupOutcome(missingCapacity.data(), missingCapacity.size()));

    auto wrongProcedure = FromHex("20 11 00 25 00 00 03 00 3d 40 0a 03 80 73 72 73 6d 6d 65 30 31 "
                                  "00 69 00 0b 00 00 00 f1 10 00 00 01 00 00 1a 00 57 40 01 ff");
    wrongProcedure[1] = 18;
    CHECK_THROWS(lte::enb::s1ap::DecodeS1SetupOutcome(wrongProcedure.data(), wrongProcedure.size()));
}

TEST_CASE("lte/enb/state: success, failure and connection loss use explicit transitions")
{
    lte::enb::ConnectionStateMachine state;
    CHECK(state.state() == lte::enb::ConnectionState::DISCONNECTED);
    CHECK(state.transition(lte::enb::ConnectionEvent::CONNECT_STARTED));
    CHECK(state.transition(lte::enb::ConnectionEvent::SCTP_CONNECTED));
    CHECK(state.transition(lte::enb::ConnectionEvent::SETUP_REQUEST_SENT));
    CHECK_FALSE(state.transition(lte::enb::ConnectionEvent::SETUP_REQUEST_SENT));
    CHECK(state.transition(lte::enb::ConnectionEvent::SETUP_ACCEPTED));
    CHECK(state.state() == lte::enb::ConnectionState::S1_SETUP_ESTABLISHED);
    CHECK(state.transition(lte::enb::ConnectionEvent::CONNECTION_LOST));
    CHECK(state.state() == lte::enb::ConnectionState::DISCONNECTED);

    CHECK(state.transition(lte::enb::ConnectionEvent::CONNECT_STARTED));
    CHECK(state.transition(lte::enb::ConnectionEvent::SCTP_CONNECTED));
    CHECK(state.transition(lte::enb::ConnectionEvent::SETUP_REQUEST_SENT));
    CHECK(state.transition(lte::enb::ConnectionEvent::SETUP_REJECTED));
    CHECK(state.state() == lte::enb::ConnectionState::S1_SETUP_FAILED);
}

TEST_CASE("lte/enb/codec: UE-associated NAS messages use the expected S1AP procedures and context")
{
    auto config = lte::enb::ParseConfig(ValidConfig);
    const std::vector<uint8_t> nas{0x07, 0x41, 0x71};

    auto initial = lte::enb::s1ap::EncodeInitialUeMessage(config, 1, nas);
    REQUIRE(initial.size() > nas.size());
    CHECK(initial[0] == 0x00); // initiatingMessage
    CHECK(initial[1] == 12);   // id-InitialUEMessage
    CHECK((initial[2] & 0xC0U) == 0x40U); // procedure criticality ignore
    // APER large-range constrained integers carry their encoded octet count.
    // This independent prefix is id=8, reject, open-type length=2, value=1.
    const std::vector<uint8_t> enbUeIdIe{0x00, 0x08, 0x00, 0x02, 0x00, 0x01};
    CHECK(std::search(initial.begin(), initial.end(), enbUeIdIe.begin(), enbUeIdIe.end()) != initial.end());

    lte::enb::s1ap::UeContext incomplete{1, std::nullopt};
    CHECK_THROWS(lte::enb::s1ap::EncodeUplinkNasTransport(config, incomplete, nas));
    lte::enb::s1ap::UeContext complete{1, 0x1234U};
    auto uplink = lte::enb::s1ap::EncodeUplinkNasTransport(config, complete, nas);
    REQUIRE(uplink.size() > nas.size());
    CHECK(uplink[0] == 0x00);
    CHECK(uplink[1] == 13); // id-UplinkNASTransport
    CHECK((uplink[2] & 0xC0U) == 0x40U);

    CHECK_THROWS(lte::enb::s1ap::EncodeInitialUeMessage(config, 0, nas));
    CHECK_THROWS(lte::enb::s1ap::DecodeDownlinkNasTransport(nullptr, 0));
}
