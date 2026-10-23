//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Phase 2 EPS NAS Security Mode Command, ESM and Attach Accept/Complete tests.
#include <ext/doctest/doctest.h>

#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>

#include <string>
#include <vector>

namespace
{

// Truthful EEA0+EEA2 / EIA2 capability (TS 24.301 9.9.3.34).
const char *A020Config = R"(
imsi: '460020123456789'
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
  localPort: 4999
  address: 127.0.0.1
  port: 4998
)";

// 07 5D, EIA2+EEA0 (0x02), native KSI 0, replayed caps A0 20.
std::vector<uint8_t> SmcEia2Eea0()
{
    return {0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x20};
}

// Activate Default EPS Bearer Context Request: EBI 5, PTI 1, QCI 5,
// APN "internet", PDN address 10.0.0.1.
// APN is an LV whose contents are the TS 24.008 label encoding (08 "internet").
std::vector<uint8_t> ActivateDefaultRequest()
{
    return {0x52, 0x01, 0xC1,
            0x01, 0x05,                               // EPS QoS: QCI 5
            0x09, 0x08, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, // APN internet
            0x05, 0x01, 0x0A, 0x00, 0x00, 0x01};       // PDN address IPv4 10.0.0.1
}

// Attach Accept carrying that default bearer in the ESM container.
std::vector<uint8_t> AttachAcceptWithBearer()
{
    const auto esm = ActivateDefaultRequest();
    std::vector<uint8_t> out{0x07, 0x42,
                             0x01, // EPS attach result: EPS
                             0x30, // GPRS timer T3412
                             0x02, 0x00, 0x01}; // TAI list: one entry, TAC 1
    out.push_back(static_cast<uint8_t>(esm.size() >> 8U));
    out.push_back(static_cast<uint8_t>(esm.size()));
    out.insert(out.end(), esm.begin(), esm.end());
    return out;
}

lte::ue::SecurityContext ValidContext()
{
    lte::ue::SecurityContext context{};
    context.valid = true;
    context.keysDerived = true;
    context.advertisedSecurityCapabilities = {0xA0, 0x20};
    return context;
}

} // namespace

TEST_CASE("lte/ue/nas: Security Mode Command decodes selected algorithms, KSI and replayed capabilities")
{
    auto command = lte::ue::nas::DecodeSecurityModeCommand(SmcEia2Eea0().data(), SmcEia2Eea0().size());
    CHECK(command.integrity == lte::ue::IntegrityAlgorithm::EIA2);
    CHECK(command.ciphering == lte::ue::CipheringAlgorithm::EEA0);
    CHECK(command.ksi == 0);
    CHECK(command.nativeContext);
    CHECK(command.replayedCapabilities == std::vector<uint8_t>{0xA0, 0x20});
    CHECK_FALSE(command.imeisvRequested);
    CHECK_FALSE(command.hashMmePresent);
}

TEST_CASE("lte/ue/nas: Security Mode Command algorithm octet is ciphering high nibble and integrity low nibble")
{
    // 0x22 = EEA2 | EIA2, 0x08 TSC bit means mapped (non-native) context, KSI 0.
    std::vector<uint8_t> body{0x07, 0x5D, 0x22, 0x08, 0x02, 0xA0, 0x20};
    auto command = lte::ue::nas::DecodeSecurityModeCommand(body.data(), body.size());
    CHECK(command.integrity == lte::ue::IntegrityAlgorithm::EIA2);
    CHECK(command.ciphering == lte::ue::CipheringAlgorithm::EEA2);
    CHECK_FALSE(command.nativeContext);
    CHECK(command.ksi == 0);
}

TEST_CASE("lte/ue/nas: Security Mode Command optional IMEISV request and HASHMME are decoded")
{
    std::vector<uint8_t> body = SmcEia2Eea0();
    body.push_back(0xC1); // IMEISV requested
    auto command = lte::ue::nas::DecodeSecurityModeCommand(body.data(), body.size());
    CHECK(command.imeisvRequested);

    std::vector<uint8_t> withHash = SmcEia2Eea0();
    withHash.push_back(0x4F);
    withHash.push_back(8);
    for (int i = 0; i < 8; ++i)
        withHash.push_back(static_cast<uint8_t>(i));
    auto hashed = lte::ue::nas::DecodeSecurityModeCommand(withHash.data(), withHash.size());
    CHECK(hashed.hashMmePresent);
    CHECK(hashed.hashMme[0] == 0);
    CHECK(hashed.hashMme[7] == 7);
}

TEST_CASE("lte/ue/nas: malformed Security Mode Command bodies are rejected")
{
    const auto valid = SmcEia2Eea0();
    for (size_t size = 0; size < valid.size(); ++size)
        CHECK_THROWS(lte::ue::nas::DecodeSecurityModeCommand(valid.data(), size));

    auto wrongType = valid;
    wrongType[1] = 0x5E;
    CHECK_THROWS(lte::ue::nas::DecodeSecurityModeCommand(wrongType.data(), wrongType.size()));

    auto wrongPd = valid;
    wrongPd[0] = 0x02;
    CHECK_THROWS(lte::ue::nas::DecodeSecurityModeCommand(wrongPd.data(), wrongPd.size()));

    auto shortCaps = valid;
    shortCaps[4] = 4; // claims four capability octets but only two follow
    CHECK_THROWS(lte::ue::nas::DecodeSecurityModeCommand(shortCaps.data(), shortCaps.size()));
}

TEST_CASE("lte/ue/nas: Security Mode Command validation accepts EIA2 with advertised EEA0 and EIA2")
{
    auto config = lte::ue::ParseConfig(A020Config);
    auto context = ValidContext();
    auto command = lte::ue::nas::DecodeSecurityModeCommand(SmcEia2Eea0().data(), SmcEia2Eea0().size());
    CHECK_NOTHROW(lte::ue::nas::ValidateSecurityModeCommand(config, command, context));
    CHECK(context.integrity == lte::ue::IntegrityAlgorithm::EIA2);
    CHECK(context.ciphering == lte::ue::CipheringAlgorithm::EEA0);
    CHECK(context.ksi == 0);
}

TEST_CASE("lte/ue/nas: Security Mode Command validation rejects EIA0 for an authenticated Attach")
{
    auto config = lte::ue::ParseConfig(A020Config);
    auto context = ValidContext();
    std::vector<uint8_t> body{0x07, 0x5D, 0x00, 0x00, 0x02, 0xA0, 0x20};
    auto command = lte::ue::nas::DecodeSecurityModeCommand(body.data(), body.size());
    CHECK(command.integrity == lte::ue::IntegrityAlgorithm::EIA0);
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(config, command, context));
}

TEST_CASE("lte/ue/nas: Security Mode Command validation rejects algorithms the UE did not advertise")
{
    auto config = lte::ue::ParseConfig(A020Config); // EEA0+EEA2 / EIA2
    auto context = ValidContext();

    // EIA1 is not in A020.
    std::vector<uint8_t> eia1{0x07, 0x5D, 0x01, 0x00, 0x02, 0xA0, 0x20};
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(
        config, lte::ue::nas::DecodeSecurityModeCommand(eia1.data(), eia1.size()), context));

    // EEA1 is not in A020.
    std::vector<uint8_t> eea1{0x07, 0x5D, 0x12, 0x00, 0x02, 0xA0, 0x20};
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(
        config, lte::ue::nas::DecodeSecurityModeCommand(eea1.data(), eea1.size()), context));
}

TEST_CASE("lte/ue/nas: Security Mode Command validation rejects a mismatched capability replay")
{
    auto config = lte::ue::ParseConfig(A020Config);
    auto context = ValidContext();
    context.advertisedSecurityCapabilities = {0xA0, 0x20};

    std::vector<uint8_t> flipped{0x07, 0x5D, 0x02, 0x00, 0x02, 0xA0, 0x21};
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(
        config, lte::ue::nas::DecodeSecurityModeCommand(flipped.data(), flipped.size()), context));

    std::vector<uint8_t> truncated{0x07, 0x5D, 0x02, 0x00, 0x01, 0xA0};
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(
        config, lte::ue::nas::DecodeSecurityModeCommand(truncated.data(), truncated.size()), context));
}

TEST_CASE("lte/ue/nas: Security Mode Command validation requires a valid EPS AKA context")
{
    auto config = lte::ue::ParseConfig(A020Config);
    auto context = ValidContext();
    context.valid = false;
    auto command = lte::ue::nas::DecodeSecurityModeCommand(SmcEia2Eea0().data(), SmcEia2Eea0().size());
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(config, command, context));
}

TEST_CASE("lte/ue/nas: Security Mode Command validation rejects an unusable mapped KSI 7")
{
    auto config = lte::ue::ParseConfig(A020Config);
    auto context = ValidContext();
    std::vector<uint8_t> body{0x07, 0x5D, 0x02, 0x0F, 0x02, 0xA0, 0x20}; // TSC=1, KSI=7
    auto command = lte::ue::nas::DecodeSecurityModeCommand(body.data(), body.size());
    CHECK(command.ksi == 7);
    CHECK_FALSE(command.nativeContext);
    CHECK_THROWS(lte::ue::nas::ValidateSecurityModeCommand(config, command, context));
}

TEST_CASE("lte/ue/nas: Security Mode Complete is encoded with and without an IMEISV")
{
    auto config = lte::ue::ParseConfig(A020Config);
    CHECK(lte::ue::nas::EncodeSecurityModeComplete(config, false) == std::vector<uint8_t>{0x07, 0x5E});

    auto withImeisv = lte::ue::nas::EncodeSecurityModeComplete(config, true);
    REQUIRE(withImeisv.size() > 2);
    CHECK(withImeisv[0] == 0x07);
    CHECK(withImeisv[1] == 0x5E);
    CHECK(withImeisv[2] == 0x23); // Mobile identity IEI, IMEISV
    CHECK(withImeisv[3] == 0x09); // TS 24.008 IMEISV identity is 9 octets
}

TEST_CASE("lte/ue/nas: Attach Accept decodes the embedded Activate Default EPS Bearer Context Request")
{
    auto accept = AttachAcceptWithBearer();
    auto message = lte::ue::nas::DecodeDownlink(accept.data(), accept.size());
    REQUIRE(message.type == lte::ue::nas::DownlinkEmm::ATTACH_ACCEPT);
    CHECK(message.messageType == 0x42);
    CHECK(message.attachAccept.attachResult == 0x01);
    CHECK(message.attachAccept.t3412 == 0x30);
    REQUIRE(message.attachAccept.bearer.has_value());
    const auto &bearer = *message.attachAccept.bearer;
    CHECK(bearer.epsBearerIdentity == 5);
    CHECK(bearer.procedureTransactionId == 1);
    CHECK(bearer.qci == 5);
    CHECK(bearer.apn == "internet");
    CHECK(bearer.pdnAddress == std::array<uint8_t, 4>{0x0A, 0x00, 0x00, 0x01});
}

TEST_CASE("lte/ue/nas: Attach Accept without a default bearer activation reports no bearer")
{
    // ESM container holds an Information Request instead of the default bearer.
    std::vector<uint8_t> accept{0x07, 0x42, 0x01, 0x30, 0x00,
                                0x00, 0x03,
                                0x52, 0x01, 0xD9};
    auto message = lte::ue::nas::DecodeDownlink(accept.data(), accept.size());
    REQUIRE(message.type == lte::ue::nas::DownlinkEmm::ATTACH_ACCEPT);
    CHECK_FALSE(message.attachAccept.bearer.has_value());
    CHECK(message.attachAccept.esmContainer == std::vector<uint8_t>({0x52, 0x01, 0xD9}));
}

TEST_CASE("lte/ue/nas: Attach Accept optional GUTI is decoded when present")
{
    auto accept = AttachAcceptWithBearer();
    // Append GUTI: IEI 0x50, length 11, 11 identity octets.
    accept.push_back(0x50);
    accept.push_back(0x0B);
    for (int i = 0; i < 11; ++i)
        accept.push_back(static_cast<uint8_t>(0x10 + i));
    auto message = lte::ue::nas::DecodeDownlink(accept.data(), accept.size());
    REQUIRE(message.attachAccept.guti.has_value());
    CHECK(message.attachAccept.guti->at(0) == 0x10);
    CHECK(message.attachAccept.guti->at(10) == 0x1A);
}

TEST_CASE("lte/ue/nas: truncated Attach Accept is rejected")
{
    auto accept = AttachAcceptWithBearer();
    for (size_t size = 0; size < accept.size(); ++size)
        CHECK_THROWS(lte::ue::nas::DecodeDownlink(accept.data(), size));
}

TEST_CASE("lte/ue/nas: Attach Reject carries the EMM cause")
{
    const std::vector<uint8_t> reject{0x07, 0x44, 0x0B}; // illegal UE
    auto message = lte::ue::nas::DecodeDownlink(reject.data(), reject.size());
    CHECK(message.type == lte::ue::nas::DownlinkEmm::ATTACH_REJECT);
    CHECK(message.emmCause == 0x0B);
}

TEST_CASE("lte/ue/nas: Activate Default EPS Bearer Context Accept is encoded inside the ESM container")
{
    const std::vector<uint8_t> expected{0x52, 0x01, 0xC2};
    CHECK(lte::ue::nas::EncodeActivateDefaultEpsBearerContextAccept(5, 1) == expected);
    CHECK(lte::ue::nas::EncodeActivateDefaultEpsBearerContextAccept(0, 0) == std::vector<uint8_t>{0x02, 0x00, 0xC2});
}

TEST_CASE("lte/ue/nas: Attach Complete carries the ESM acceptance in its container")
{
    const std::vector<uint8_t> esm{0x52, 0x01, 0xC2};
    auto complete = lte::ue::nas::EncodeAttachComplete(esm);
    REQUIRE(complete.size() == 7);
    CHECK(complete[0] == 0x07);
    CHECK(complete[1] == 0x43);
    CHECK(complete[2] == 0x00);
    CHECK(complete[3] == 0x03);
    CHECK(complete[4] == 0x52);
    CHECK(complete[5] == 0x01);
    CHECK(complete[6] == 0xC2);

    // The ESM acceptance is required; an empty container is not a valid complete.
    CHECK_THROWS(lte::ue::nas::EncodeAttachComplete({}));
}

TEST_CASE("lte/ue/nas: ESM Information Request and Response are handled")
{
    // ESM Information Request is not associated with a bearer: EBI = 0.
    const std::vector<uint8_t> request{0x02, 0x01, 0xD9};
    CHECK(lte::ue::nas::IsEsmInformationRequest(request.data(), request.size()));
    auto message = lte::ue::nas::DecodeDownlink(request.data(), request.size());
    REQUIRE(message.type == lte::ue::nas::DownlinkEmm::ESM_INFORMATION_REQUEST);
    CHECK(message.esmInformationRequest.procedureTransactionId == 1);
    CHECK_FALSE(message.esmInformationRequest.apn.has_value());

    CHECK(lte::ue::nas::EncodeEsmInformationResponse(1, std::nullopt) ==
          std::vector<uint8_t>({0x02, 0x01, 0xDA}));

    auto response = lte::ue::nas::EncodeEsmInformationResponse(1, std::string("internet"));
    REQUIRE(response.size() > 3);
    CHECK(response[0] == 0x02);
    CHECK(response[1] == 0x01);
    CHECK(response[2] == 0xDA);
    CHECK(response[3] == 0x28); // APN IEI
}

TEST_CASE("lte/ue/nas: ESM Information Request with an APN is decoded")
{
    // PTI 2, type 0xD9, APN "internet" in TS 24.008 label encoding.
    std::vector<uint8_t> request{0x02, 0x02, 0xD9, 0x28, 0x09, 0x08,
                                 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74};
    auto message = lte::ue::nas::DecodeDownlink(request.data(), request.size());
    REQUIRE(message.type == lte::ue::nas::DownlinkEmm::ESM_INFORMATION_REQUEST);
    REQUIRE(message.esmInformationRequest.apn.has_value());
    CHECK(*message.esmInformationRequest.apn == "internet");
}

TEST_CASE("lte/ue/nas: Security Mode Command is routed through the downlink decoder")
{
    auto message = lte::ue::nas::DecodeDownlink(SmcEia2Eea0().data(), SmcEia2Eea0().size());
    CHECK(message.type == lte::ue::nas::DownlinkEmm::SECURITY_MODE_COMMAND);
    CHECK(message.securityModeCommand.integrity == lte::ue::IntegrityAlgorithm::EIA2);
}

TEST_CASE("lte/ue/nas: unknown downlink messages are reported without inventing an Attach Accept")
{
    const std::vector<uint8_t> identityRequest{0x07, 0x55, 0x00};
    auto message = lte::ue::nas::DecodeDownlink(identityRequest.data(), identityRequest.size());
    CHECK(message.type == lte::ue::nas::DownlinkEmm::OTHER);
    CHECK_FALSE(message.attachAccept.bearer.has_value());

    CHECK_THROWS(lte::ue::nas::DecodeDownlink(nullptr, 0));
    const std::vector<uint8_t> neither{0x05, 0x00};
    CHECK_THROWS(lte::ue::nas::DecodeDownlink(neither.data(), neither.size()));
}
