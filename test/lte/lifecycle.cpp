//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALI GUNGOR.
//
// LTE EPS lifecycle, Detach, Service Request and TAU tests.

#include <ext/doctest/doctest.h>

#include <lte/ue/lifecycle.hpp>
#include <lte/ue/nas.hpp>
#include <lte/ue/security.hpp>

namespace
{
std::array<uint8_t, 11> Guti()
{
    return {0xF6, 0x64, 0xF0, 0x20, 0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78};
}

lte::ue::MobilityContext Registered()
{
    lte::ue::MobilityContext context;
    context.ecm = lte::ue::EcmState::CONNECTED;
    context.securityContextValid = true;
    context.onAttachComplete(5, {10, 45, 0, 5}, Guti(), {0, 1}, 0x30);
    context.onUserPlaneReady();
    return context;
}
} // namespace

TEST_CASE("lte/lifecycle: S1 release retains registration and logical bearer but blocks data")
{
    auto context = Registered();
    context.enbTeid = 0x11111111;
    context.sgwTeid = 0x22222222;
    REQUIRE(context.canForwardUserPlane());
    context.onS1ContextReleased();
    CHECK(context.emm == lte::ue::EmmState::REGISTERED);
    CHECK(context.ecm == lte::ue::EcmState::IDLE);
    CHECK(context.bearer == lte::ue::EpsBearerState::SIGNALING_ESTABLISHED);
    CHECK_FALSE(context.canForwardUserPlane());
    CHECK_FALSE(context.enbTeid.has_value());
    CHECK_FALSE(context.sgwTeid.has_value());
    CHECK_NOTHROW(context.onS1ContextReleased());
}

TEST_CASE("lte/lifecycle: Service Request restores once and Detach clears all context")
{
    auto context = Registered();
    context.onS1ContextReleased();
    context.startServiceRequest();
    CHECK_THROWS(context.startServiceRequest());
    context.onServiceRestored();
    CHECK(context.canForwardUserPlane());
    CHECK_THROWS(context.onServiceRestored());
    context.startDetach();
    CHECK_FALSE(context.canForwardUserPlane());
    context.onDetachAccepted();
    CHECK(context.emm == lte::ue::EmmState::DEREGISTERED);
    CHECK(context.bearer == lte::ue::EpsBearerState::INACTIVE);
    CHECK_FALSE(context.guti.has_value());
    CHECK_THROWS(context.startDetach());
}

TEST_CASE("lte/lifecycle: normal and periodic TAU preserve bearer and update assigned context")
{
    auto context = Registered();
    context.startTau(false);
    context.onTauAccepted(std::nullopt, std::vector<uint8_t>{2, 3}, 0x21);
    CHECK(context.taiList == std::vector<uint8_t>{2, 3});
    CHECK(context.t3412 == 0x21);
    CHECK(context.canForwardUserPlane());
    context.startTau(true);
    context.onTauAccepted(Guti(), std::nullopt, std::nullopt);
    CHECK(context.pending == lte::ue::PendingProcedure::NONE);
}

TEST_CASE("lte/nas: Detach and TAU use GUTI, native KSI and exact EPS wire fields")
{
    CHECK(lte::ue::nas::EncodeDetachRequest(3, Guti(), false) ==
          std::vector<uint8_t>{0x07, 0x45, 0x31, 0x0B, 0xF6, 0x64, 0xF0, 0x20,
                               0x00, 0x01, 0x01, 0x12, 0x34, 0x56, 0x78});
    auto switchOff = lte::ue::nas::EncodeDetachRequest(3, Guti(), true);
    CHECK(switchOff[2] == 0x39);
    auto normal = lte::ue::nas::EncodeTauRequest(3, Guti(), 5, false);
    auto periodic = lte::ue::nas::EncodeTauRequest(3, Guti(), 5, true);
    CHECK(normal[0] == 0x07);
    CHECK(normal[1] == 0x48);
    CHECK(normal[2] == 0x30);
    CHECK(periodic[2] == 0x33);
    CHECK(std::vector<uint8_t>(normal.end() - 4, normal.end()) ==
          std::vector<uint8_t>{0x57, 0x02, 0x20, 0x00});
    auto ebiEight = lte::ue::nas::EncodeTauRequest(3, Guti(), 8, false);
    CHECK(std::vector<uint8_t>(ebiEight.end() - 4, ebiEight.end()) ==
          std::vector<uint8_t>{0x57, 0x02, 0x00, 0x01});
    CHECK(lte::ue::nas::EncodeTauComplete() == std::vector<uint8_t>{0x07, 0x4A});
}

TEST_CASE("lte/nas: Detach Accept, TAU Accept and rejects are decoded defensively")
{
    const std::vector<uint8_t> detach{0x07, 0x46};
    CHECK(lte::ue::nas::DecodeDownlink(detach.data(), detach.size()).type ==
          lte::ue::nas::DownlinkEmm::DETACH_ACCEPT);
    std::vector<uint8_t> tau{0x07, 0x49, 0x00, 0x5A, 0x31, 0x54, 0x02, 0x00, 0x02,
                             0x50, 0x0B};
    const auto guti = Guti();
    tau.insert(tau.end(), guti.begin(), guti.end());
    tau.insert(tau.end(), {0x57, 0x02, 0x20, 0x00});
    auto accepted = lte::ue::nas::DecodeDownlink(tau.data(), tau.size());
    CHECK(accepted.type == lte::ue::nas::DownlinkEmm::TAU_ACCEPT);
    CHECK(accepted.tauAccept.t3412 == 0x31);
    CHECK(accepted.tauAccept.taiList == std::vector<uint8_t>{0, 2});
    CHECK(accepted.tauAccept.guti == guti);
    CHECK(accepted.tauAccept.bearerContextStatus == 0x20);
    const std::vector<uint8_t> rejected{0x07, 0x4B, 0x0B};
    CHECK(lte::ue::nas::DecodeDownlink(rejected.data(), rejected.size()).emmCause == 0x0B);
    CHECK_THROWS(lte::ue::nas::DecodeDownlink(detach.data(), 1));
}

TEST_CASE("lte/security: compact Service Request matches independent AES-CMAC fixture")
{
    lte::ue::SecurityContext context{};
    context.valid = context.keysDerived = context.securityActive = true;
    context.ksi = 3;
    context.integrity = lte::ue::IntegrityAlgorithm::EIA2;
    context.kNasInt = {0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
                       0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48};
    context.ulNasCount = 0x0059B4;
    // Independently derived with AES-CMAC over
    // COUNT||BEARER/DIRECTION||0^24||{C7,74}: 6A9FD3BD...; short MAC=D3BD.
    const std::vector<uint8_t> expected{0xC7, 0x74, 0xD3, 0xBD};
    CHECK(lte::ue::nas::EncodeServiceRequest(context) == expected);
    CHECK_NOTHROW(lte::ue::nas::VerifyServiceRequest(context, expected.data(), expected.size(), 0x0059A0));
    auto corrupt = expected;
    corrupt.back() ^= 1;
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, corrupt.data(), corrupt.size(), 0x0059A0));
    auto wrongKsi = expected;
    wrongKsi[1] ^= 0x20;
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, wrongKsi.data(), wrongKsi.size(), 0x0059A0));
    CHECK_THROWS(lte::ue::nas::VerifyServiceRequest(context, expected.data(), expected.size(), 0x0059B5));
    context.securityActive = false;
    CHECK_THROWS(lte::ue::nas::EncodeServiceRequest(context));
}
