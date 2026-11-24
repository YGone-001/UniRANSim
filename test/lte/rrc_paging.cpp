//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D5: PCCH Paging and RRCConnectionRelease codecs, and the PCCH
// logical channel of the simulated Uu envelope.
#include <ext/doctest/doctest.h>

#include <lte/rrc-runtime/rrc_connection_release.hpp>
#include <lte/rrc-runtime/rrc_information_transfer.hpp>
#include <lte/rrc-runtime/rrc_paging.hpp>
#include <lte/rrc-runtime/uu_transport.hpp>

TEST_CASE("lte/rrc: a Paging message round trips with the S-TMSI of each record")
{
    lte::rrc::PagingMessage message;
    message.records.push_back({1, 0x12345678U, false});
    message.records.push_back({7, 0xDEADBEEFU, true});

    const auto wire = lte::rrc::EncodePaging(message);
    REQUIRE_FALSE(wire.empty());

    lte::rrc::PagingMessage decoded;
    REQUIRE(lte::rrc::DecodePaging(wire.data(), wire.size(), decoded));
    REQUIRE(decoded.records.size() == 2);
    CHECK(decoded.records[0].mmec == 1);
    CHECK(decoded.records[0].mTmsi == 0x12345678U);
    CHECK_FALSE(decoded.records[0].csDomain);
    CHECK(decoded.records[1].mmec == 7);
    CHECK(decoded.records[1].mTmsi == 0xDEADBEEFU);
    CHECK(decoded.records[1].csDomain);
}

TEST_CASE("lte/rrc: Paging refuses an empty record set and a malformed PDU")
{
    lte::rrc::PagingMessage empty;
    CHECK(lte::rrc::EncodePaging(empty).empty());

    lte::rrc::PagingMessage tooMany;
    for (size_t i = 0; i < lte::rrc::MaxPagingRecords + 1; i++)
        tooMany.records.push_back({1, static_cast<uint32_t>(i + 1), false});
    CHECK(lte::rrc::EncodePaging(tooMany).empty());

    lte::rrc::PagingMessage decoded;
    const std::vector<uint8_t> garbage{0xFF, 0x00, 0x13};
    CHECK_FALSE(lte::rrc::DecodePaging(garbage.data(), garbage.size(), decoded));
    CHECK_FALSE(lte::rrc::DecodePaging(nullptr, 0, decoded));
}

TEST_CASE("lte/rrc: RRCConnectionRelease round trips and is not confused with NAS transfer")
{
    lte::rrc::RrcConnectionReleaseMessage message;
    message.transactionId = 2;
    const auto wire = lte::rrc::EncodeRrcConnectionRelease(message);
    REQUIRE_FALSE(wire.empty());

    lte::rrc::RrcConnectionReleaseMessage decoded;
    REQUIRE(lte::rrc::DecodeRrcConnectionRelease(wire.data(), wire.size(), decoded));
    CHECK(decoded.transactionId == 2);

    // A DLInformationTransfer is a different DL-DCCH message and must not be
    // accepted as a release.
    lte::rrc::InformationTransferMessage information;
    information.dedicatedInfoNas = {0xC7, 0x02, 0x11, 0x22};
    const auto transfer = lte::rrc::EncodeDlInformationTransfer(information);
    REQUIRE_FALSE(transfer.empty());
    CHECK_FALSE(lte::rrc::DecodeRrcConnectionRelease(transfer.data(), transfer.size(), decoded));

    // And a release carries no NAS.
    lte::rrc::InformationTransferMessage nas;
    CHECK_FALSE(lte::rrc::DecodeDlInformationTransfer(wire.data(), wire.size(), nas));

    // The transaction identifier is two bits.
    message.transactionId = 4;
    CHECK(lte::rrc::EncodeRrcConnectionRelease(message).empty());
}

TEST_CASE("lte/uu: the PCCH logical channel carries a Paging frame byte for byte")
{
    lte::rrc::PagingMessage message;
    message.records.push_back({1, 0x12345678U, false});
    const auto paging = lte::rrc::EncodePaging(message);
    REQUIRE_FALSE(paging.empty());

    lte::uu::Frame frame;
    frame.association = 46001;
    frame.direction = lte::uu::Direction::DOWNLINK;
    frame.channel = lte::uu::LogicalChannel::PCCH;
    frame.payload = paging;

    const auto encoded = lte::uu::EncodeFrame(frame);
    lte::uu::Frame decoded;
    std::string why;
    REQUIRE(lte::uu::DecodeFrame(encoded.data(), encoded.size(), decoded, &why));
    CHECK(decoded.channel == lte::uu::LogicalChannel::PCCH);
    CHECK(decoded.association == 46001);
    CHECK(decoded.payload == paging);

    // An unknown channel value is still refused.
    auto corrupted = encoded;
    corrupted[9] = 3;
    CHECK_FALSE(lte::uu::DecodeFrame(corrupted.data(), corrupted.size(), decoded, &why));
}
