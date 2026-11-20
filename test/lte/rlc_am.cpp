//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-B1: LTE RLC AM wire codec.
//
// The golden bytes below were derived by hand from the field tables of
// TS 36.322 6.2.1.4 and 6.2.1.6, not from the encoder under test.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/rlc_am.hpp>

#include <string>
#include <vector>

using namespace lte::rlc::am;

TEST_CASE("lte/rlc-am/amd header without LI")
{
    AmdPdu pdu;
    pdu.sn = 0;
    pdu.poll = false;
    pdu.fi = FramingInfo::COMPLETE;
    pdu.data = {0x2A, 0x2B};

    // D/C=1 RF=0 P=0 FI=00 E=0 SN[9:8]=00 -> 1000 0000; SN=0x00; data.
    const std::vector<uint8_t> expected = {0x80, 0x00, 0x2A, 0x2B};
    CHECK(EncodeAmd(pdu) == expected);

    AmdPdu decoded;
    std::string why;
    REQUIRE(DecodeAmd(expected.data(), expected.size(), decoded, &why));
    CHECK(decoded.sn == 0);
    CHECK_FALSE(decoded.poll);
    CHECK(decoded.fi == FramingInfo::COMPLETE);
    CHECK(decoded.data == pdu.data);
    CHECK(decoded.li.empty());
}

TEST_CASE("lte/rlc-am/amd header with one LI and its padding")
{
    AmdPdu pdu;
    pdu.sn = 1;
    pdu.poll = false;
    pdu.fi = FramingInfo::FIRST_SEGMENT;
    pdu.li = {3};
    pdu.data = {0x01, 0x02, 0x03, 0x04, 0x05};

    // Octet1: 1 0 0 01 1 00 = 0x8C; octet2 = 0x01.
    // One E/LI: E=0, LI=3 -> 0 00000000011, then four padding bits -> 00 30.
    const std::vector<uint8_t> expected = {0x8C, 0x01, 0x00, 0x30, 0x01, 0x02, 0x03, 0x04, 0x05};
    CHECK(EncodeAmd(pdu) == expected);

    AmdPdu decoded;
    std::string why;
    REQUIRE(DecodeAmd(expected.data(), expected.size(), decoded, &why));
    CHECK(decoded.sn == 1);
    CHECK(decoded.fi == FramingInfo::FIRST_SEGMENT);
    REQUIRE(decoded.li.size() == 1);
    CHECK(decoded.li[0] == 3);
    CHECK(decoded.data == pdu.data);
}

TEST_CASE("lte/rlc-am/amd segment carries RF, SO and LSF")
{
    AmdPdu pdu;
    pdu.sn = 0x2AB;
    pdu.poll = true;
    pdu.fi = FramingInfo::MIDDLE_SEGMENT;
    pdu.segment = true;
    pdu.so = 0x0123;
    pdu.lsf = true;
    pdu.data = {0xAA};

    const auto bytes = EncodeAmd(pdu);
    // Octet1: 1 1 1 11 0 10 = 0xFA; octet2 = 0xAB; octet3: LSF=1, SO[14:8]=0x01 -> 0x81; octet4 = 0x23.
    CHECK(bytes.size() == 2 + 2 + 1);
    CHECK(bytes[0] == 0xFA);
    CHECK(bytes[1] == 0xAB);
    CHECK(bytes[2] == 0x81);
    CHECK(bytes[3] == 0x23);

    AmdPdu decoded;
    std::string why;
    REQUIRE(DecodeAmd(bytes.data(), bytes.size(), decoded, &why));
    CHECK(decoded.segment);
    CHECK(decoded.so == 0x0123);
    CHECK(decoded.lsf);
    CHECK(decoded.poll);
    CHECK(decoded.sn == 0x2AB);
    CHECK(decoded.data == pdu.data);
}

TEST_CASE("lte/rlc-am/status with and without NACK")
{
    StatusPdu pdu;
    pdu.ackSn = 5;
    // 0000 | 0000000101 | 0  + one padding bit -> 0x00 0x14
    const std::vector<uint8_t> expected = {0x00, 0x14};
    CHECK(EncodeStatus(pdu) == expected);

    StatusPdu decoded;
    std::string why;
    REQUIRE(DecodeStatus(expected.data(), expected.size(), decoded, &why));
    CHECK(decoded.ackSn == 5);
    CHECK(decoded.nacks.empty());

    StatusPdu withNack;
    withNack.ackSn = 7;
    StatusNack nack;
    nack.sn = 4;
    withNack.nacks.push_back(nack);
    const auto bytes = EncodeStatus(withNack);

    StatusPdu roundTrip;
    REQUIRE(DecodeStatus(bytes.data(), bytes.size(), roundTrip, &why));
    CHECK(roundTrip.ackSn == 7);
    REQUIRE(roundTrip.nacks.size() == 1);
    CHECK(roundTrip.nacks[0].sn == 4);
    CHECK_FALSE(roundTrip.nacks[0].soRange.has_value());

    StatusPdu withRange;
    withRange.ackSn = 8;
    StatusNack ranged;
    ranged.sn = 6;
    ranged.soRange = std::pair<uint16_t, uint16_t>(10, SoMax);
    withRange.nacks.push_back(ranged);
    const auto rangeBytes = EncodeStatus(withRange);
    StatusPdu rangeRoundTrip;
    REQUIRE(DecodeStatus(rangeBytes.data(), rangeBytes.size(), rangeRoundTrip, &why));
    REQUIRE(rangeRoundTrip.nacks.size() == 1);
    REQUIRE(rangeRoundTrip.nacks[0].soRange.has_value());
    CHECK(rangeRoundTrip.nacks[0].soRange->first == 10);
    CHECK(rangeRoundTrip.nacks[0].soRange->second == SoMax);
}

TEST_CASE("lte/rlc-am/malformed pdus are refused")
{
    AmdPdu decoded;
    std::string why;

    // D/C = 0 is a control PDU, not an AMD PDU.
    const std::vector<uint8_t> control = {0x00, 0x00};
    CHECK_FALSE(DecodeAmd(control.data(), control.size(), decoded, &why));

    // Truncated header.
    const std::vector<uint8_t> oneByte = {0x80};
    CHECK_FALSE(DecodeAmd(oneByte.data(), oneByte.size(), decoded, &why));

    // A non-zero LI padding nibble is refused rather than ignored.
    const std::vector<uint8_t> badPadding = {0x8C, 0x01, 0x00, 0x3F, 0x01, 0x02, 0x03, 0x04, 0x05};
    CHECK_FALSE(DecodeAmd(badPadding.data(), badPadding.size(), decoded, &why));

    StatusPdu status;
    const std::vector<uint8_t> dataPdu = {0x80, 0x00};
    CHECK_FALSE(DecodeStatus(dataPdu.data(), dataPdu.size(), status, &why));
}
