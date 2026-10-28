//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include <ext/doctest/doctest.h>

#include <lte/ue/config.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/radio_link.hpp>

#include <array>

namespace
{
const char *ConfigText = R"(
imsi: '460020123456789'
mcc: '460'
mnc: '02'
k: '465B5CE8B199B49FAA5F0A2EE238A6BC'
opc: 'CD63CB71954A9F4E48A5994E37A02BAF'
amf: 'B9B9'
initialSqn: 'FF9BB4D0B607'
pdnType: IPv4
networkCapability: 'E0E0'
enbLink:
  localAddress: 127.0.0.1
  localPort: 4999
  address: 127.0.0.1
  port: 4998
)";

std::vector<uint8_t> AuthRequest()
{
    return {0x07, 0x52, 0x07,
            0x23, 0x55, 0x3C, 0xBE, 0x96, 0x37, 0xA8, 0x9D, 0x21, 0x8A, 0xE6, 0x4D, 0xAE, 0x47, 0xBF, 0x35,
            0x10, 0x55, 0xF3, 0x28, 0xB4, 0x35, 0x77, 0xB9, 0xB9, 0x4A, 0x9F, 0xFA, 0xC3, 0x54, 0xDF, 0xAF, 0xB3};
}
} // namespace

TEST_CASE("lte/ue/nas: EPS mobile identity and unprotected Attach Request are encoded")
{
    auto config = lte::ue::ParseConfig(ConfigText);
    CHECK(lte::ue::nas::EncodeImsi(config.imsi) == std::vector<uint8_t>{0x49, 0x06, 0x20, 0x10, 0x32, 0x54, 0x76, 0x98});
    auto attach = lte::ue::nas::EncodeAttachRequest(config);
    CHECK(attach == std::vector<uint8_t>{0x07, 0x41, 0x71, 0x08,
                                         0x49, 0x06, 0x20, 0x10, 0x32, 0x54, 0x76, 0x98,
                                         0x02, 0xE0, 0xE0, 0x00, 0x04,
                                         0x02, 0x01, 0xD0, 0x11});
}

TEST_CASE("lte/ue/nas: Milenage AUTN validation, RES and KASME use 3GPP vector")
{
    auto config = lte::ue::ParseConfig(ConfigText);
    auto challenge = AuthRequest();
    auto decoded = lte::ue::nas::DecodeAuthenticationRequest(challenge.data(), challenge.size());
    auto result = lte::ue::nas::Authenticate(config, decoded);
    CHECK(result.failure == lte::ue::nas::AkaFailure::NONE);
    CHECK(result.res == std::array<uint8_t, 8>{0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF});
    CHECK(result.context.ck == std::array<uint8_t, 16>{0xB4, 0x0B, 0xA9, 0xA3, 0xC5, 0x8B, 0x2A, 0x05,
                                                        0xBB, 0xF0, 0xD9, 0x87, 0xB2, 0x1B, 0xF8, 0xCB});
    CHECK(result.context.ik == std::array<uint8_t, 16>{0xF7, 0x69, 0xBC, 0xD7, 0x51, 0x04, 0x46, 0x04,
                                                        0x12, 0x76, 0x72, 0x71, 0x1C, 0x6D, 0x34, 0x41});
    CHECK(result.context.kasme == std::array<uint8_t, 32>{0xA2, 0x95, 0x51, 0xDE, 0x84, 0xC3, 0xDB, 0xE8,
                                                           0xA5, 0x0D, 0x90, 0x1A, 0xC9, 0xAD, 0xC6, 0x39,
                                                           0x58, 0xAD, 0xAA, 0x16, 0xAD, 0xF4, 0x4D, 0x57,
                                                           0x1D, 0xBE, 0xA2, 0xD4, 0x40, 0xCB, 0xE2, 0x5E});
    CHECK(lte::ue::nas::EncodeAuthenticationResponse(result.res) ==
          std::vector<uint8_t>{0x07, 0x53, 0x08, 0xA5, 0x42, 0x11, 0xD5, 0xE3, 0xBA, 0x50, 0xBF});
}

TEST_CASE("lte/ue/config: OP and OPc remain mutually exclusive")
{
    CHECK_NOTHROW(lte::ue::ParseConfig(ConfigText));
    std::string both = ConfigText;
    both.insert(both.find("opc:"), "op: '102132435465768798A9BACBDCEDFE0F'\n");
    CHECK_THROWS(lte::ue::ParseConfig(both));
    std::string neither = ConfigText;
    const auto start = neither.find("opc:");
    neither.erase(start, neither.find('\n', start) - start + 1);
    CHECK_THROWS(lte::ue::ParseConfig(neither));
}

TEST_CASE("lte/ue/config: PLMN, PDN type and APN are validated before signaling")
{
    std::string invalidMcc = ConfigText;
    invalidMcc.replace(invalidMcc.find("mcc: '460'"), 10, "mcc: '000'");
    CHECK_THROWS(lte::ue::ParseConfig(invalidMcc));

    std::string invalidPdn = ConfigText;
    invalidPdn.replace(invalidPdn.find("pdnType: IPv4"), 13, "pdnType: X25");
    CHECK_THROWS(lte::ue::ParseConfig(invalidPdn));

    std::string invalidApn = ConfigText;
    invalidApn.insert(invalidApn.find("networkCapability:"), "apn: 'internet.'\n");
    CHECK_THROWS(lte::ue::ParseConfig(invalidApn));
}

TEST_CASE("lte/ue/config: LTE TUN defaults install no route and explicit routes reject a default route")
{
    auto defaults = lte::ue::ParseConfig(ConfigText);
    CHECK(defaults.tun.namePrefix == "uniransim-lte");
    CHECK(defaults.tun.required);
    CHECK(defaults.tun.mtu == 1400);
    CHECK(defaults.tun.routes.empty());

    std::string selected = ConfigText;
    selected += "\ntun:\n  required: false\n  namePrefix: lte-test\n  mtu: 1300\n  routes: ['10.45.0.1/32']\n";
    auto configured = lte::ue::ParseConfig(selected);
    CHECK(configured.tun.namePrefix == "lte-test");
    CHECK_FALSE(configured.tun.required);
    CHECK(configured.tun.mtu == 1300);
    CHECK(configured.tun.routes == std::vector<std::string>{"10.45.0.1/32"});

    std::string unsafe = ConfigText;
    unsafe += "\ntun:\n  routes: ['0.0.0.0/0']\n";
    CHECK_THROWS(lte::ue::ParseConfig(unsafe));
}

TEST_CASE("lte/ue/config: lifecycle scenarios and bounded procedure controls are validated")
{
    auto defaults = lte::ue::ParseConfig(ConfigText);
    CHECK(defaults.lifecycle.scenario == lte::ue::LifecycleScenario::ATTACH_ONLY);
    std::string configured = ConfigText;
    configured += "\nlifecycle:\n  scenario: service-request\n  triggerAfterMs: 250\n"
                  "  procedureTimeoutMs: 750\n  maxRetries: 2\n";
    auto value = lte::ue::ParseConfig(configured);
    CHECK(value.lifecycle.scenario == lte::ue::LifecycleScenario::SERVICE_REQUEST);
    CHECK(value.lifecycle.triggerAfterMs == 250);
    CHECK(value.lifecycle.procedureTimeoutMs == 750);
    CHECK(value.lifecycle.maxRetries == 2);

    std::string invalid = ConfigText;
    invalid += "\nlifecycle:\n  scenario: arbitrary\n";
    CHECK_THROWS(lte::ue::ParseConfig(invalid));
    std::string invalidSwitchOff = ConfigText;
    invalidSwitchOff += "\nlifecycle:\n  scenario: tau-periodic\n  switchOff: true\n";
    CHECK_THROWS(lte::ue::ParseConfig(invalidSwitchOff));

    // The network-triggered paging window is bounded like the other deadline
    // controls: an absent field keeps the default, and a value outside the
    // supported range is rejected rather than silently clamped.
    CHECK(defaults.lifecycle.pagingWaitMs == 60000);
    std::string paging = ConfigText;
    paging += "\nlifecycle:\n  scenario: paging\n  pagingWaitMs: 1200\n";
    CHECK(lte::ue::ParseConfig(paging).lifecycle.pagingWaitMs == 1200);
    for (const char *bound : {"99", "600001"})
    {
        std::string outOfRange = ConfigText;
        outOfRange += "\nlifecycle:\n  scenario: paging\n  pagingWaitMs: ";
        outOfRange += bound;
        outOfRange += "\n";
        CHECK_THROWS(lte::ue::ParseConfig(outOfRange));
    }
}

TEST_CASE("lte/ue/nas: OP derivation and stale SQN handling fail or succeed independently")
{
    std::string withOp = ConfigText;
    withOp.replace(withOp.find("opc:"), 4, "op:");
    withOp.replace(withOp.find("CD63CB71954A9F4E48A5994E37A02BAF"), 32,
                   "CDC202D5123E20F62B6D676AC72CB318");
    auto challenge = AuthRequest();
    auto decoded = lte::ue::nas::DecodeAuthenticationRequest(challenge.data(), challenge.size());
    CHECK(lte::ue::nas::Authenticate(lte::ue::ParseConfig(withOp), decoded).failure ==
          lte::ue::nas::AkaFailure::NONE);

    std::string stale = ConfigText;
    stale.replace(stale.find("FF9BB4D0B607"), 12, "FF9BB4D0B608");
    CHECK(lte::ue::nas::Authenticate(lte::ue::ParseConfig(stale), decoded).failure ==
          lte::ue::nas::AkaFailure::SYNCHRONIZATION_FAILURE);
}

TEST_CASE("lte/ue/nas: invalid AUTN and malformed NAS fail closed")
{
    auto config = lte::ue::ParseConfig(ConfigText);
    auto challenge = AuthRequest();
    challenge.back() ^= 1;
    auto decoded = lte::ue::nas::DecodeAuthenticationRequest(challenge.data(), challenge.size());
    CHECK(lte::ue::nas::Authenticate(config, decoded).failure == lte::ue::nas::AkaFailure::MAC_FAILURE);
    const auto valid = AuthRequest();
    for (size_t size = 0; size < valid.size(); ++size)
        CHECK_THROWS(lte::ue::nas::DecodeAuthenticationRequest(valid.data(), size));
}

TEST_CASE("lte/ue/nas: Security Mode Command is recognized in plain and protected EPS NAS")
{
    const std::vector<uint8_t> plain{0x07, 0x5D, 0x00};
    const std::vector<uint8_t> protectedNewContext{0x37, 0x01, 0x02, 0x03, 0x04, 0x00, 0x07, 0x5D, 0x00};
    const std::vector<uint8_t> protectedWrongMessage{0x37, 0x01, 0x02, 0x03, 0x04, 0x00, 0x07, 0x54};
    CHECK(lte::ue::nas::IsSecurityModeCommand(plain.data(), plain.size()));
    CHECK(lte::ue::nas::IsSecurityModeCommand(protectedNewContext.data(), protectedNewContext.size()));
    CHECK_FALSE(lte::ue::nas::IsSecurityModeCommand(protectedWrongMessage.data(), protectedWrongMessage.size()));
    CHECK_FALSE(lte::ue::nas::IsSecurityModeCommand(protectedNewContext.data(), 7));
}

TEST_CASE("lte/ue/radio-link: rejects malformed frames and preserves NAS payload")
{
    lte::ue::link::Message input{lte::ue::link::MessageType::NAS_UPLINK, 1, {0x07, 0x53, 0x08}};
    auto encoded = lte::ue::link::Encode(input);
    auto decoded = lte::ue::link::Decode(encoded.data(), encoded.size());
    CHECK(decoded.ueId == 1);
    CHECK(decoded.payload == input.payload);
    encoded[7] = static_cast<uint8_t>(encoded[7] + 1U);
    CHECK_THROWS(lte::ue::link::Decode(encoded.data(), encoded.size()));
}
