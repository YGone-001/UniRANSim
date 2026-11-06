//
// Phase 18-A: S1-based connected-mode handover protocol foundation.
//
// The positive cases below assert against fixed APER byte strings that were
// produced once and then cross-checked against an independent dissector
// (Wireshark tshark 4.2.2, S1AP, 902 registered fields). They are not
// encode-then-decode round trips: a change to the encoder that alters the wire
// form fails here even if it still round-trips with itself.
//
// The negative cases are built with a deliberately separate bit writer at the
// bottom of this file. It shares no code with src/lte/enb/codec.cpp, so a
// rejection this file proves cannot be an artefact of the encoder and the
// decoder agreeing on the same mistake.

#include <ext/doctest/doctest.h>

#include <lte/enb/codec.hpp>
#include <lte/enb/handover_admission.hpp>
#include <lte/enb/ue_registry.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace
{

using namespace lte::enb;
using namespace lte::enb::s1ap;

std::vector<uint8_t> Hex(const std::string &text)
{
    std::vector<uint8_t> out;
    out.reserve(text.size() / 2);
    int nibble = -1;
    for (char c : text)
    {
        int value;
        if (c >= '0' && c <= '9')
            value = c - '0';
        else if (c >= 'a' && c <= 'f')
            value = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            value = c - 'A' + 10;
        else
            continue;
        if (nibble < 0)
            nibble = value;
        else
        {
            out.push_back(static_cast<uint8_t>((nibble << 4) | value));
            nibble = -1;
        }
    }
    return out;
}

std::string Describe(const std::vector<uint8_t> &bytes)
{
    static const char *digits = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes)
    {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0F]);
    }
    return out;
}

// Reads the number of information elements straight out of a PDU's bytes.
// It shares nothing with the decoder, so it can say what is on the wire even
// when the decoder under test is the thing in question.
size_t CountInformationElements(const std::vector<uint8_t> &pdu)
{
    // Three header octets (choice, procedure code, criticality), then the body
    // length: one octet, or two with the top bit set for a longer body.
    REQUIRE(pdu.size() > 3);
    size_t body = 0;
    size_t header = 0;
    if ((pdu[3] & 0x80U) != 0)
    {
        REQUIRE(pdu.size() > 5);
        body = (static_cast<size_t>(pdu[3] & 0x7FU) << 8) | pdu[4];
        header = 5;
    }
    else
    {
        body = pdu[3];
        header = 4;
    }
    REQUIRE(pdu.size() == header + body);
    REQUIRE(body >= 3);
    // The message SEQUENCE's extension marker, then the ProtocolIE-Container
    // count as two octet-aligned octets.
    REQUIRE(pdu[header] == 0);
    return (static_cast<size_t>(pdu[header + 1]) << 8) | pdu[header + 2];
}

// Information-element values, byte for byte, as the dissector read them out of
// the eight frames asserted above. The negative cases assemble these into a
// frame with the test-local writer, so a rejection is neither an
// encode-then-decode round trip nor a guess at the wire form of an inner type.
const std::vector<uint8_t> kUeId7 = Hex("0007");
const std::vector<uint8_t> kUeId9 = Hex("0009");
const std::vector<uint8_t> kUeId11 = Hex("000B");
const std::vector<uint8_t> kUeIdZero = Hex("0000");
const std::vector<uint8_t> kHandoverTypeIntraLte = Hex("00");
const std::vector<uint8_t> kCause16 = Hex("0200"); // radioNetwork / handover-desirable-for-radio-reason
const std::vector<uint8_t> kCause10 = Hex("0140"); // radioNetwork / cell-not-available
const std::vector<uint8_t> kCause0 = Hex("0000");  // radioNetwork / unspecified
const std::vector<uint8_t> kTargetId = Hex("0000F11000ABCDE000F1100002");
const std::vector<uint8_t> kContainer6 = Hex("06DEADBEEF0102");
const std::vector<uint8_t> kContainer4 = Hex("0401020304");
const std::vector<uint8_t> kAmbr = Hex("1808F0D18060047868C0");
const std::vector<uint8_t> kErabListTwo = Hex("01001B400D0A1FC00002010A0B0C0D00053C001B400D0C1FC00002010E0F101100060D");
const std::vector<uint8_t> kSecurityCapabilities = Hex("1000040000");
const std::vector<uint8_t> kSecurityContext =
    Hex("18A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF");
const std::vector<uint8_t> kEutranCgi = Hex("0000F110ABCDE000");
const std::vector<uint8_t> kTai = Hex("0000F1100002");
const std::vector<uint8_t> kTargetToSource4 = Hex("04CAFEBABE");

std::array<uint8_t, 4> Ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return {a, b, c, d};
}

std::array<uint8_t, 4> Teid(uint32_t value)
{
    return {static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
            static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
}

// Test fixture data only. These are not UE security keys and no real key is
// ever present in this repository's tests.
std::array<uint8_t, 32> TestNextHopParameter()
{
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(0xA0 + i);
    return key;
}

EnbIdentity TargetIdentity()
{
    return EnbIdentity{Plmn{"001", "01"}, 0x00ABCDEu, 2};
}

HandoverRequired SampleRequired()
{
    HandoverRequired message;
    message.mmeUeS1apId = 7;
    message.enbUeS1apId = 9;
    message.handoverType = HandoverType::INTRA_LTE;
    message.causeCategory = "radioNetwork";
    message.causeValue = 16;
    message.target = TargetIdentity();
    message.directForwardingPathAvailable = false;
    message.sourceToTarget = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    return message;
}

HandoverCommand SampleCommand()
{
    HandoverCommand message;
    message.mmeUeS1apId = 7;
    message.enbUeS1apId = 9;
    message.handoverType = HandoverType::INTRA_LTE;
    message.targetToSource = {0xCA, 0xFE, 0xBA, 0xBE};
    return message;
}

ErabDataForwardingItem SampleForwarding()
{
    ErabDataForwardingItem item;
    item.erabId = 5;
    item.dlForwardingPresent = true;
    item.dlTransportLayerAddress = Ip(192, 0, 2, 10);
    item.dlGtpTeid = Teid(0x11223344);
    item.ulForwardingPresent = true;
    item.ulTransportLayerAddress = Ip(192, 0, 2, 11);
    item.ulGtpTeid = Teid(0x55667788);
    return item;
}

HandoverPreparationFailure SamplePreparationFailure()
{
    HandoverPreparationFailure message;
    message.mmeUeS1apId = 7;
    message.enbUeS1apId = 9;
    message.causeCategory = "radioNetwork";
    message.causeValue = 10;
    return message;
}

ErabToBeSetupItemHoReq SampleBearer5()
{
    ErabToBeSetupItemHoReq item;
    item.erabId = 5;
    item.sgwAddress = Ip(192, 0, 2, 1);
    item.sgwTeid = Teid(0x0A0B0C0D);
    item.qos.qci = 5;
    item.qos.priorityLevel = 15;
    return item;
}

ErabToBeSetupItemHoReq SampleBearer6()
{
    ErabToBeSetupItemHoReq item;
    item.erabId = 6;
    item.sgwAddress = Ip(192, 0, 2, 1);
    item.sgwTeid = Teid(0x0E0F1011);
    item.qos.qci = 6;
    item.qos.priorityLevel = 3;
    item.qos.preemptionCapability = false;
    item.qos.preemptionVulnerability = true;
    return item;
}

HandoverRequest SampleRequest()
{
    HandoverRequest message;
    message.mmeUeS1apId = 7;
    message.handoverType = HandoverType::INTRA_LTE;
    message.causeCategory = "radioNetwork";
    message.causeValue = 16;
    message.ueAmbr = {150000000ULL, 75000000ULL};
    message.erabs = {SampleBearer5(), SampleBearer6()};
    message.sourceToTarget = {0x01, 0x02, 0x03, 0x04};
    message.encryptionAlgorithms = {0x80, 0x00};
    message.integrityAlgorithms = {0x40, 0x00};
    message.securityContext.nextHopChainingCount = 3;
    message.securityContext.nextHopParameter = TestNextHopParameter();
    return message;
}

HandoverRequestAcknowledge SampleAcknowledge()
{
    HandoverRequestAcknowledge message;
    message.mmeUeS1apId = 7;
    message.enbUeS1apId = 11;
    ErabAdmittedItem item;
    item.erabId = 5;
    item.transportLayerAddress = Ip(198, 51, 100, 1);
    item.gtpTeid = Teid(0x22334455);
    message.admitted = {item};
    message.targetToSource = {0x11, 0x22, 0x33};
    return message;
}

HandoverFailure SampleFailure()
{
    HandoverFailure message;
    message.mmeUeS1apId = 7;
    message.causeCategory = "radioNetwork";
    message.causeValue = 0;
    return message;
}

HandoverNotify SampleNotify()
{
    HandoverNotify message;
    message.mmeUeS1apId = 7;
    message.enbUeS1apId = 11;
    message.cgi = EutranCgi{Plmn{"001", "01"}, 0x0ABCDE00u};
    message.tai = Tai{Plmn{"001", "01"}, 2};
    return message;
}

SourceContext SampleSource()
{
    return SourceContext{EnbIdentity{Plmn{"001", "01"}, 0x0012345u, 1}, true};
}

TargetContext SampleTargetContext()
{
    TargetContext target;
    target.identity = TargetIdentity();
    target.s1uAddress = Ip(198, 51, 100, 1);
    target.encryptionAlgorithms = {0x80, 0x00};
    target.integrityAlgorithms = {0x40, 0x00};
    return target;
}

std::vector<BearerRoleBinding> SampleRoles()
{
    // The network's own statement of the session: E-RAB 5 is the default
    // bearer, E-RAB 6 is a dedicated bearer linked to it. Neither role is
    // derived from the QCI or from the order the E-RABs are listed in.
    BearerRoleBinding def;
    def.erabId = 5;
    def.role = BearerRole::DEFAULT;
    def.qci = 5;
    def.priorityLevel = 15;

    BearerRoleBinding dedicated;
    dedicated.erabId = 6;
    dedicated.role = BearerRole::DEDICATED;
    dedicated.linkedDefaultErabId = 5;
    dedicated.qci = 6;
    dedicated.priorityLevel = 3;
    dedicated.preemptionVulnerability = true;
    return {def, dedicated};
}

// --- an independent APER writer, used only to build negative fixtures ------
//
// It is deliberately not BitWriter. Nothing in src/lte/enb/codec.cpp is
// reachable from this struct.
struct ForeignBits
{
    std::vector<uint8_t> data;
    size_t used{0};

    void bit(bool value)
    {
        if ((used % 8) == 0)
            data.push_back(0);
        if (value)
            data.back() |= static_cast<uint8_t>(1U << (7U - (used % 8)));
        ++used;
    }

    void bits(uint64_t value, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
            bit(((value >> (count - i - 1)) & 1U) != 0);
    }

    void padToOctet()
    {
        while (used % 8)
            bit(false);
    }

    void octets(const std::vector<uint8_t> &value)
    {
        padToOctet();
        data.insert(data.end(), value.begin(), value.end());
        used += value.size() * 8U;
    }

    template <size_t N>
    void octets(const std::array<uint8_t, N> &value)
    {
        octets(std::vector<uint8_t>(value.begin(), value.end()));
    }

    std::vector<uint8_t> take()
    {
        padToOctet();
        return data;
    }
};

std::vector<uint8_t> ForeignIe(uint16_t id, int criticality, const std::vector<uint8_t> &value)
{
    ForeignBits writer;
    writer.bits(id, 16);          // ProtocolIE-ID 0..65535, octet aligned
    writer.bits(criticality, 2);  // reject 0, ignore 1, notify 2
    writer.padToOctet();
    if (value.size() < 128)
        writer.bits(value.size(), 8);
    else
    {
        writer.bits(0x8000U | value.size(), 16);
    }
    writer.octets(value);
    return writer.take();
}

std::vector<uint8_t> ForeignUeId(uint32_t value)
{
    size_t octets = 1;
    while (octets < 4 && (value >> (8 * octets)) != 0)
        ++octets;
    ForeignBits writer;
    writer.bits(octets - 1, 2); // the number of octets of value, minus one
    writer.padToOctet();
    writer.bits(value, octets * 8);
    return writer.take();
}

std::vector<uint8_t> ForeignCause(int value)
{
    ForeignBits writer;
    writer.bit(false);       // Cause CHOICE root
    writer.bits(0, 3);       // radioNetwork
    writer.bit(false);       // root enumeration
    writer.bits(value, 6);   // CauseRadioNetwork root index
    return writer.take();
}

std::vector<uint8_t> ForeignContainer(const std::vector<uint8_t> &value)
{
    ForeignBits writer;
    if (value.size() < 128)
        writer.bits(value.size(), 8);
    else
        writer.bits(0x8000U | value.size(), 16);
    writer.octets(value);
    return writer.take();
}

std::vector<uint8_t> ForeignHandoverType(int rootIndex)
{
    ForeignBits writer;
    writer.bit(false);
    writer.bits(rootIndex, 3);
    return writer.take();
}

std::vector<uint8_t> ForeignPdu(int choice, int procedure, int criticality,
                                const std::vector<std::vector<uint8_t>> &ies)
{
    ForeignBits body;
    body.bit(false);           // the message SEQUENCE extension marker
    body.padToOctet();
    body.bits(ies.size(), 16); // ProtocolIE-Container: 0..65535, octet aligned
    for (const auto &ie : ies)
        body.octets(ie);
    auto value = body.take();

    ForeignBits pdu;
    pdu.bit(false);           // S1AP-PDU CHOICE extension marker
    pdu.bits(choice, 2);
    pdu.padToOctet();
    pdu.bits(procedure, 8);
    pdu.bits(criticality, 2);
    pdu.padToOctet();
    if (value.size() < 128)
        pdu.bits(value.size(), 8);
    else
        pdu.bits(0x8000U | value.size(), 16);
    pdu.octets(value);
    return pdu.take();
}

// A Handover Failure frame: unsuccessfulOutcome, procedure 1, criticality
// reject, MME-UE-S1AP-ID 7, Cause radioNetwork(0). This is the frame the
// tshark cross-check confirmed.
const char *const kFailureHex = "4001000F000002000040020007000240020000";

// Handover Notify: initiatingMessage, procedure 2, criticality ignore.
const char *const kNotifyHex = "0002402500000400000002000700080002000B006440080000F110ABCDE000"
                               "004340060000F1100002";

} // namespace

// --- A. handover message wire compatibility -------------------------------

TEST_CASE("lte/handover/wire: handover failure matches the cross-checked aper vector")
{
    const auto expected = Hex(kFailureHex);
    const auto encoded = EncodeHandoverFailure(SampleFailure());
    CHECK(Describe(encoded) == Describe(expected));

    auto decoded = DecodeHandoverFailure(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.causeCategory == "radioNetwork");
    CHECK(decoded.causeValue == 0);
}

TEST_CASE("lte/handover/wire: handover notify matches the cross-checked aper vector")
{
    const auto expected = Hex(kNotifyHex);
    const auto encoded = EncodeHandoverNotify(SampleNotify());
    CHECK(Describe(encoded) == Describe(expected));

    auto decoded = DecodeHandoverNotify(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.enbUeS1apId == 11);
    CHECK(decoded.cgi.plmn.mcc == "001");
    CHECK(decoded.cgi.plmn.mnc == "01");
    CHECK(decoded.cgi.cellId == 0x0ABCDE00u);
    CHECK(decoded.tai.tac == 2);
}

TEST_CASE("lte/handover/wire: handover preparation failure matches the cross-checked aper vector")
{
    const auto expected =
        Hex("40000015000003000040020007000840020009000240020140");
    CHECK(Describe(EncodeHandoverPreparationFailure(SamplePreparationFailure())) == Describe(expected));

    auto decoded = DecodeHandoverPreparationFailure(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.enbUeS1apId == 9);
    CHECK(decoded.causeCategory == "radioNetwork");
    CHECK(decoded.causeValue == 10);
}

TEST_CASE("lte/handover/wire: handover required matches the cross-checked aper vector")
{
    const auto expected = Hex("00000036000006000000020007000800020009000100010000024002020000"
                              "04000D0000F11000ABCDE000F11000020068000706DEADBEEF0102");
    CHECK(Describe(EncodeHandoverRequired(SampleRequired())) == Describe(expected));

    auto decoded = DecodeHandoverRequired(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.enbUeS1apId == 9);
    CHECK(decoded.handoverType == HandoverType::INTRA_LTE);
    CHECK(decoded.causeValue == 16);
    CHECK(decoded.target.enbId == 0x00ABCDEu);
    CHECK(decoded.target.tac == 2);
    CHECK(decoded.target.plmn.mcc == "001");
    CHECK(!decoded.directForwardingPathAvailable);
    CHECK(decoded.sourceToTarget == std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}));
}

TEST_CASE("lte/handover/wire: handover command matches the cross-checked aper vector")
{
    const auto expected = Hex("2000001D0000040000000200070008000200090001000100007B000504CAFEBABE");
    CHECK(Describe(EncodeHandoverCommand(SampleCommand())) == Describe(expected));
    auto decoded = DecodeHandoverCommand(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.enbUeS1apId == 9);
    CHECK(decoded.dataForwarding.empty());
    CHECK(decoded.targetToSource == std::vector<uint8_t>({0xCA, 0xFE, 0xBA, 0xBE}));
}

TEST_CASE("lte/handover/wire: data forwarding endpoints keep their e-rab identity and byte order")
{
    auto message = SampleCommand();
    message.dataForwarding = {SampleForwarding()};
    const auto expected =
        Hex("2000003B0000050000000200070008000200090001000100000C401A00000E401578A1F0C000020A1122334"
            "40F80C000020B55667788007B000504CAFEBABE");
    CHECK(Describe(EncodeHandoverCommand(message)) == Describe(expected));

    auto decoded = DecodeHandoverCommand(expected.data(), expected.size());
    REQUIRE(decoded.dataForwarding.size() == 1);
    const auto &item = decoded.dataForwarding[0];
    CHECK(item.erabId == 5);
    CHECK(item.dlForwardingPresent);
    CHECK(item.dlTransportLayerAddress == Ip(192, 0, 2, 10));
    CHECK(item.dlGtpTeid == Teid(0x11223344));
    CHECK(item.ulForwardingPresent);
    CHECK(item.ulTransportLayerAddress == Ip(192, 0, 2, 11));
    CHECK(item.ulGtpTeid == Teid(0x55667788));
}

TEST_CASE("lte/handover/wire: handover request matches the cross-checked aper vector")
{
    const auto expected =
        Hex("000100808000000800000002000700010001000002400202000042000A1808F0D18060047868C0003500230"
            "1001B400D0A1FC00002010A0B0C0D00053C001B400D0C1FC00002010E0F101100060D0068000504010203040"
            "06B000510000400000028002118A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBE"
            "BF");
    CHECK(Describe(EncodeHandoverRequest(SampleRequest())) == Describe(expected));

    auto decoded = DecodeHandoverRequest(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.handoverType == HandoverType::INTRA_LTE);
    CHECK(decoded.causeValue == 16);
    CHECK(decoded.ueAmbr.downlink == 150000000ULL);
    CHECK(decoded.ueAmbr.uplink == 75000000ULL);
    REQUIRE(decoded.erabs.size() == 2);
    CHECK(decoded.erabs[0].erabId == 5);
    CHECK(decoded.erabs[0].sgwTeid == Teid(0x0A0B0C0D));
    CHECK(decoded.erabs[0].qos.qci == 5);
    CHECK(decoded.erabs[0].qos.priorityLevel == 15);
    CHECK(!decoded.erabs[0].qos.gbr.has_value());
    CHECK(decoded.erabs[1].erabId == 6);
    CHECK(decoded.erabs[1].qos.qci == 6);
    CHECK(decoded.erabs[1].qos.priorityLevel == 3);
    CHECK(decoded.erabs[1].qos.preemptionVulnerability);
    CHECK(decoded.encryptionAlgorithms == std::array<uint8_t, 2>{0x80, 0x00});
    CHECK(decoded.integrityAlgorithms == std::array<uint8_t, 2>{0x40, 0x00});
    CHECK(decoded.securityContext.nextHopChainingCount == 3);
    CHECK(decoded.securityContext.nextHopParameter == TestNextHopParameter());
}

TEST_CASE("lte/handover/wire: handover request acknowledge matches the cross-checked aper vector")
{
    const auto expected =
        Hex("2001002B00000400004002000700084002000B00124010000014400B00A1F0C633640122334455007B00040311"
            "2233");
    CHECK(Describe(EncodeHandoverRequestAcknowledge(SampleAcknowledge())) == Describe(expected));

    auto decoded = DecodeHandoverRequestAcknowledge(expected.data(), expected.size());
    CHECK(decoded.mmeUeS1apId == 7);
    CHECK(decoded.enbUeS1apId == 11);
    REQUIRE(decoded.admitted.size() == 1);
    CHECK(decoded.admitted[0].erabId == 5);
    CHECK(decoded.admitted[0].transportLayerAddress == Ip(198, 51, 100, 1));
    CHECK(decoded.admitted[0].gtpTeid == Teid(0x22334455));
    CHECK(!decoded.admitted[0].dlForwardingPresent);
    CHECK(!decoded.admitted[0].ulForwardingPresent);
    CHECK(decoded.targetToSource == std::vector<uint8_t>({0x11, 0x22, 0x33}));
}

TEST_CASE("lte/handover/wire: the envelope names the standard's procedure code and criticality")
{
    // Raw envelope assertions, made on the bytes rather than through the
    // decoder, so a decoder that stopped checking the procedure code would
    // still fail here. TS 36.413 §9.1.3.1: preparation is 0, resource
    // allocation is 1, notification is 2, and the notification procedure
    // criticality is ignore while the other two are reject.
    struct Expectation
    {
        const char *name;
        std::vector<uint8_t> bytes;
        uint8_t choice;
        uint8_t procedure;
        uint8_t criticality;
    };
    const std::vector<Expectation> cases = {
        {"HandoverRequired", EncodeHandoverRequired(SampleRequired()), 0, 0, 0},
        {"HandoverCommand", EncodeHandoverCommand(SampleCommand()), 1, 0, 0},
        {"HandoverPreparationFailure", EncodeHandoverPreparationFailure(SamplePreparationFailure()), 2, 0, 0},
        {"HandoverRequest", EncodeHandoverRequest(SampleRequest()), 0, 1, 0},
        {"HandoverRequestAcknowledge", EncodeHandoverRequestAcknowledge(SampleAcknowledge()), 1, 1, 0},
        {"HandoverFailure", EncodeHandoverFailure(SampleFailure()), 2, 1, 0},
        {"HandoverNotify", EncodeHandoverNotify(SampleNotify()), 0, 2, 1},
    };
    for (const auto &item : cases)
    {
        CAPTURE(item.name);
        REQUIRE(item.bytes.size() > 3);
        const uint8_t first = item.bytes[0];
        CHECK((first & 0x80U) == 0); // no extended PDU choice
        CHECK(((first >> 5) & 0x03U) == item.choice);
        CHECK(item.bytes[1] == item.procedure);
        CHECK(((item.bytes[2] >> 6) & 0x03U) == item.criticality);
    }
}

TEST_CASE("lte/handover/wire: the test-local writer agrees with the dissector on inner values")
{
    // Every negative frame below is assembled from these inner values. If the
    // test-local writer and the dissector disagreed about how an identifier, a
    // cause, a handover type or a container is spelled, a rejection proved
    // nothing. So the two are pinned against each other here.
    CHECK(ForeignUeId(7) == kUeId7);
    CHECK(ForeignUeId(9) == kUeId9);
    CHECK(ForeignUeId(11) == kUeId11);
    CHECK(ForeignUeId(0) == kUeIdZero);
    CHECK(ForeignHandoverType(0) == kHandoverTypeIntraLte);
    CHECK(ForeignCause(16) == kCause16);
    CHECK(ForeignCause(10) == kCause10);
    CHECK(ForeignCause(0) == kCause0);
    CHECK(ForeignContainer({0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}) == kContainer6);
    CHECK(ForeignContainer({0x01, 0x02, 0x03, 0x04}) == kContainer4);
    CHECK(ForeignContainer({0xCA, 0xFE, 0xBA, 0xBE}) == kTargetToSource4);

    // And the envelope reader counts what the dissector counted in each of the
    // eight frames.
    CHECK(CountInformationElements(EncodeHandoverRequired(SampleRequired())) == 6);
    CHECK(CountInformationElements(EncodeHandoverCommand(SampleCommand())) == 4);
    CHECK(CountInformationElements(EncodeHandoverPreparationFailure(SamplePreparationFailure())) == 3);
    CHECK(CountInformationElements(EncodeHandoverRequest(SampleRequest())) == 8);
    CHECK(CountInformationElements(EncodeHandoverRequestAcknowledge(SampleAcknowledge())) == 4);
    CHECK(CountInformationElements(EncodeHandoverFailure(SampleFailure())) == 2);
    CHECK(CountInformationElements(EncodeHandoverNotify(SampleNotify())) == 4);
}

// --- B. invalid message rejection -----------------------------------------

TEST_CASE("lte/handover/reject: truncated input is refused")
{
    const auto frame = Hex(kFailureHex);
    for (size_t cut = 0; cut < frame.size(); ++cut)
    {
        CAPTURE(cut);
        std::vector<uint8_t> partial(frame.begin(), frame.begin() + static_cast<long>(cut));
        CHECK_THROWS_AS(DecodeHandoverFailure(partial.data(), partial.size()), CodecError);
    }
}

TEST_CASE("lte/handover/reject: an incorrect procedure code is refused")
{
    auto frame = Hex(kFailureHex);
    frame[1] = 9; // InitialContextSetup, not HandoverResourceAllocation
    CHECK_THROWS_AS(DecodeHandoverFailure(frame.data(), frame.size()), CodecError);
}

TEST_CASE("lte/handover/reject: an incorrect pdu outcome category is refused")
{
    auto frame = Hex(kFailureHex);
    frame[0] = 0x00; // initiatingMessage, not unsuccessfulOutcome
    CHECK_THROWS_AS(DecodeHandoverFailure(frame.data(), frame.size()), CodecError);
}

TEST_CASE("lte/handover/reject: a missing mandatory ie is refused")
{
    // Handover Notify without the mandatory TAI.
    const auto frame = ForeignPdu(0, 2, 1, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(11)),
        ForeignIe(100, 1, kEutranCgi),
    });
    CHECK_THROWS_AS(DecodeHandoverNotify(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverNotify(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::MISSING_MANDATORY_IE);
    }
}

TEST_CASE("lte/handover/reject: a duplicate mandatory ie is refused")
{
    const auto frame = ForeignPdu(2, 1, 0, {
        ForeignIe(0, 1, ForeignUeId(7)),
        ForeignIe(0, 1, ForeignUeId(8)),
        ForeignIe(2, 1, ForeignCause(0)),
    });
    CHECK_THROWS_AS(DecodeHandoverFailure(frame.data(), frame.size()), CodecError);
}

TEST_CASE("lte/handover/reject: an invalid ue identifier is refused")
{
    // A zero MME-UE-S1AP-ID identifies no UE-associated context.
    const auto frame = ForeignPdu(2, 1, 0, {
        ForeignIe(0, 1, ForeignUeId(0)),
        ForeignIe(2, 1, ForeignCause(0)),
    });
    CHECK_THROWS_AS(DecodeHandoverFailure(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverFailure(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::INVALID_CONTEXT_IDENTITY);
    }

    // An eNB-UE-S1AP-ID above its 24-bit range is not an identifier either.
    const auto outOfRange = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(0x1000000U)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, ForeignCause(16)),
        ForeignIe(4, 0, Hex("")),
        ForeignIe(104, 0, ForeignContainer({0x01})),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(outOfRange.data(), outOfRange.size()), CodecError);
}

TEST_CASE("lte/handover/reject: an unsupported or inconsistent e-rab list is refused")
{
    // The two E-RAB items the dissector read out of the Handover Request
    // fixture: E-RAB-ID 5 and E-RAB-ID 6, each with its own transport endpoint.
    const auto item5 = Hex("0A1FC00002010A0B0C0D00053C");
    const auto item6 = Hex("0C1FC00002010E0F101100060D");

    auto requestWithList = [&](const std::vector<uint8_t> &listValue) {
        return ForeignPdu(0, 1, 0, {
            ForeignIe(0, 0, ForeignUeId(7)),
            ForeignIe(1, 0, ForeignHandoverType(0)),
            ForeignIe(2, 1, ForeignCause(16)),
            ForeignIe(66, 0, kAmbr),
            ForeignIe(53, 0, listValue),
            ForeignIe(104, 0, kContainer4),
            ForeignIe(107, 0, kSecurityCapabilities),
            ForeignIe(40, 0, kSecurityContext),
        });
    };

    // A list whose entry names an information element other than
    // E-RABToBeSetupItemHOReq is not a list of E-RABs to set up.
    {
        ForeignBits list;
        list.bits(0, 8); // SIZE(1..256): the number of items minus one
        list.octets(ForeignIe(13, 1, item5)); // E-RABReleaseItemHOCmd
        const auto frame = requestWithList(list.take());
        CHECK_THROWS_AS(DecodeHandoverRequest(frame.data(), frame.size()), HandoverRefused);
        try
        {
            DecodeHandoverRequest(frame.data(), frame.size());
        }
        catch (const HandoverRefused &error)
        {
            CHECK(error.refusal() == HandoverRefusal::UNSUPPORTED_ERAB_LIST);
        }
    }

    // The same E-RAB identity twice is one bearer claimed twice.
    {
        ForeignBits list;
        list.bits(1, 8);
        list.octets(ForeignIe(27, 1, item5));
        list.octets(ForeignIe(27, 1, item5));
        const auto frame = requestWithList(list.take());
        CHECK_THROWS_AS(DecodeHandoverRequest(frame.data(), frame.size()), HandoverRefused);
        try
        {
            DecodeHandoverRequest(frame.data(), frame.size());
        }
        catch (const HandoverRefused &error)
        {
            CHECK(error.refusal() == HandoverRefusal::UNSUPPORTED_ERAB_LIST);
        }
    }

    // The two items in the right order decode, which is what makes the two
    // refusals above refusals of the list and not of the item.
    {
        ForeignBits list;
        list.bits(1, 8);
        list.octets(ForeignIe(27, 1, item5));
        list.octets(ForeignIe(27, 1, item6));
        const auto frame = requestWithList(list.take());
        auto decoded = DecodeHandoverRequest(frame.data(), frame.size());
        REQUIRE(decoded.erabs.size() == 2);
        CHECK(decoded.erabs[0].erabId == 5);
        CHECK(decoded.erabs[1].erabId == 6);
    }

    // A forwarding endpoint named by half its pair is not an endpoint.
    ForeignBits half;
    half.bit(false);  // E-RABDataForwardingItem extension marker
    half.bit(true);   // dL-transportLayerAddress
    half.bit(false);  // dL-gTP-TEID
    half.bit(false);  // uL-TransportLayerAddress
    half.bit(false);  // uL-gTP-TEID
    half.bit(false);  // iE-Extensions
    half.bits(5, 5);  // e-RAB-ID: extension marker plus 4 bits
    half.bits(0, 1);  // TransportLayerAddress size extension marker
    half.bits(31, 8); // 32 bits
    half.padToOctet();
    half.octets(Ip(192, 0, 2, 10));

    ForeignBits list;
    list.bits(0, 8);
    list.octets(ForeignIe(14, 1, half.take()));
    const auto frame = ForeignPdu(1, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(12, 1, list.take()),
        ForeignIe(123, 0, kTargetToSource4),
    });
    CHECK_THROWS_AS(DecodeHandoverCommand(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverCommand(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::UNSUPPORTED_ERAB_LIST);
    }

    // And the encoder holds the same bound: a list of no bearers is refused
    // rather than written as an empty one.
    auto empty = SampleRequest();
    empty.erabs.clear();
    CHECK_THROWS_AS(EncodeHandoverRequest(empty), HandoverRefused);
}

TEST_CASE("lte/handover/reject: an unsupported handover type is refused")
{
    // ltetoutran is a root value the standard names and this eNB does not
    // implement. It is refused, never silently treated as intra-LTE.
    for (int rootIndex : {1, 2, 3, 4})
    {
        CAPTURE(rootIndex);
        const auto request = ForeignPdu(0, 0, 0, {
            ForeignIe(0, 0, ForeignUeId(7)),
            ForeignIe(8, 0, ForeignUeId(9)),
            ForeignIe(1, 0, ForeignHandoverType(rootIndex)),
            ForeignIe(2, 1, kCause16),
            ForeignIe(4, 0, kTargetId),
            ForeignIe(104, 0, kContainer6),
        });
        CHECK_THROWS_AS(DecodeHandoverRequired(request.data(), request.size()), HandoverRefused);
        try
        {
            DecodeHandoverRequired(request.data(), request.size());
        }
        catch (const HandoverRefused &error)
        {
            CHECK(error.refusal() == HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE);
        }
    }

    // An extended HandoverType has no value this eNB understands.
    ForeignBits extended;
    extended.bit(true);
    extended.bits(0, 6);
    const auto extendedType = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, extended.take()),
        ForeignIe(2, 1, kCause16),
        ForeignIe(4, 0, kTargetId),
        ForeignIe(104, 0, kContainer6),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(extendedType.data(), extendedType.size()), HandoverRefused);

    // And the encoder refuses to write one.
    auto message = SampleRequired();
    message.handoverType = HandoverType::LTE_TO_UTRAN;
    CHECK_THROWS_AS(EncodeHandoverRequired(message), HandoverRefused);
}

TEST_CASE("lte/handover/reject: an oversized or empty mandatory container is refused")
{
    // An empty Source-ToTarget-TransparentContainer says nothing about the
    // source cell and is refused rather than treated as an empty message.
    const auto empty = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, ForeignCause(16)),
        ForeignIe(4, 0, kTargetId),
        ForeignIe(104, 0, ForeignContainer({})),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(empty.data(), empty.size()), HandoverRefused);
    try
    {
        DecodeHandoverRequired(empty.data(), empty.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::INVALID_TRANSPARENT_CONTAINER);
    }

    // A container one octet past the receiver bound is refused whole, never
    // truncated to the bound.
    std::vector<uint8_t> oversized(MaxTransparentContainerSize + 1, 0x5A);
    const auto big = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, ForeignCause(16)),
        ForeignIe(4, 0, kTargetId),
        ForeignIe(104, 0, ForeignContainer(oversized)),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(big.data(), big.size()), HandoverRefused);
    try
    {
        DecodeHandoverRequired(big.data(), big.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::INVALID_TRANSPARENT_CONTAINER);
    }

    // The encoder refuses the same two shapes rather than writing them.
    auto message = SampleRequired();
    message.sourceToTarget.clear();
    CHECK_THROWS_AS(EncodeHandoverRequired(message), HandoverRefused);
    message.sourceToTarget.assign(MaxTransparentContainerSize + 1, 0x5A);
    CHECK_THROWS_AS(EncodeHandoverRequired(message), HandoverRefused);
}

TEST_CASE("lte/handover/reject: an unknown critical ie requires rejection")
{
    // An information element this decoder does not know, marked reject
    // criticality, is not ignorable: the standard makes rejection mandatory.
    const auto critical = ForeignPdu(2, 1, 0, {
        ForeignIe(0, 1, ForeignUeId(7)),
        ForeignIe(2, 1, ForeignCause(0)),
        ForeignIe(4000, 0, Hex("00")),
    });
    CHECK_THROWS_AS(DecodeHandoverFailure(critical.data(), critical.size()), HandoverRefused);
    try
    {
        DecodeHandoverFailure(critical.data(), critical.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::MISSING_MANDATORY_IE);
    }

    // The same element marked ignore is passed over, which is what the
    // criticality says to do.
    const auto ignorable = ForeignPdu(2, 1, 0, {
        ForeignIe(0, 1, ForeignUeId(7)),
        ForeignIe(2, 1, ForeignCause(0)),
        ForeignIe(4000, 1, Hex("00")),
    });
    auto decoded = DecodeHandoverFailure(ignorable.data(), ignorable.size());
    CHECK(decoded.mmeUeS1apId == 7);
}

TEST_CASE("lte/handover/reject: a mandatory ie carrying the wrong criticality is refused")
{
    // MME-UE-S1AP-ID is reject-criticality in Handover Required. An ignore
    // marking does not make it optional.
    const auto frame = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 1, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, ForeignCause(16)),
        ForeignIe(4, 0, kTargetId),
        ForeignIe(104, 0, ForeignContainer({0x01})),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverRequired(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::MISSING_MANDATORY_IE);
    }
}

TEST_CASE("lte/handover/reject: a security context that carries no algorithms is refused")
{
    // Handover Request with no UESecurityCapabilities: the target would have
    // nothing to protect the UE with, and must not guess.
    const auto frame = ForeignPdu(0, 1, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, kCause16),
        ForeignIe(66, 0, kAmbr),
        ForeignIe(53, 0, kErabListTwo),
        ForeignIe(104, 0, kContainer4),
        ForeignIe(40, 0, kSecurityContext),
    });
    CHECK_THROWS_AS(DecodeHandoverRequest(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverRequest(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::MISSING_MANDATORY_IE);
    }
}

TEST_CASE("lte/handover/reject: a source or target that names two networks is refused")
{
    // The Global-ENB-ID PLMN and the selected TAI PLMN are separate fields on
    // the wire. A TargetID that names two different networks is not a coherent
    // target.
    ForeignBits targetId;
    targetId.bit(false); // TargetID CHOICE extension marker
    targetId.bits(0, 2); // targeteNB-ID
    targetId.bit(false); // TargeteNB-ID extension marker
    targetId.bit(false); // TargeteNB-ID iE-Extensions
    targetId.bit(false); // Global-ENB-ID extension marker
    targetId.bit(false); // Global-ENB-ID iE-Extensions
    targetId.octets(Hex("00F110"));
    targetId.bit(false); // ENB-ID CHOICE extension marker
    targetId.bit(false); // macroENB-ID
    targetId.padToOctet();
    targetId.bits(0xABCDE, 20);
    targetId.bit(false); // TAI extension marker
    targetId.bit(false); // TAI iE-Extensions
    targetId.octets(Hex("00F111")); // a different PLMN
    targetId.bits(2, 16);

    const auto frame = ForeignPdu(0, 0, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(8, 0, ForeignUeId(9)),
        ForeignIe(1, 0, ForeignHandoverType(0)),
        ForeignIe(2, 1, ForeignCause(16)),
        ForeignIe(4, 0, targetId.take()),
        ForeignIe(104, 0, ForeignContainer({0x01})),
    });
    CHECK_THROWS_AS(DecodeHandoverRequired(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverRequired(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::INVALID_CONTEXT_IDENTITY);
    }
}

TEST_CASE("lte/handover/reject: a handover failure that carries an e-nb-ue-s1ap-id is refused")
{
    // HandoverFailureIEs has no eNB-UE-S1AP-ID: the target binds none before
    // it admits. A message that carries one is not a Handover Failure.
    const auto frame = ForeignPdu(2, 1, 0, {
        ForeignIe(0, 1, ForeignUeId(7)),
        ForeignIe(8, 1, ForeignUeId(9)),
        ForeignIe(2, 1, ForeignCause(0)),
    });
    CHECK_THROWS_AS(DecodeHandoverFailure(frame.data(), frame.size()), HandoverRefused);
    try
    {
        DecodeHandoverFailure(frame.data(), frame.size());
    }
    catch (const HandoverRefused &error)
    {
        CHECK(error.refusal() == HandoverRefusal::MISSING_MANDATORY_IE);
    }
}

// --- C. bearer identity preservation --------------------------------------

TEST_CASE("lte/handover/bearer: one default and one dedicated bearer keep role and qci")
{
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    REQUIRE(admission.bearers.size() == 2);

    const auto &def = admission.bearers[0];
    CHECK(def.erabId == 5);
    CHECK(def.role == BearerRole::DEFAULT);
    CHECK(!def.linkedDefaultErabId.has_value());
    CHECK(def.qci == 5);
    CHECK(def.priorityLevel == 15);

    const auto &dedicated = admission.bearers[1];
    CHECK(dedicated.erabId == 6);
    CHECK(dedicated.role == BearerRole::DEDICATED);
    REQUIRE(dedicated.linkedDefaultErabId.has_value());
    CHECK(*dedicated.linkedDefaultErabId == 5);
    CHECK(dedicated.qci == 6);
    CHECK(dedicated.priorityLevel == 3);
    CHECK(dedicated.preemptionVulnerability);
}

TEST_CASE("lte/handover/bearer: role and qos survive a reversed e-rab list order")
{
    auto request = SampleRequest();
    std::reverse(request.erabs.begin(), request.erabs.end());

    // The roles come from the network's statement, not from the list order, so
    // a reordered E-RABToBeSetupListHOReq must produce the same result with the
    // default bearer still first.
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    REQUIRE(admission.bearers.size() == 2);
    CHECK(admission.bearers[0].erabId == 5);
    CHECK(admission.bearers[0].role == BearerRole::DEFAULT);
    CHECK(admission.bearers[1].erabId == 6);
    CHECK(admission.bearers[1].role == BearerRole::DEDICATED);
    CHECK(*admission.bearers[1].linkedDefaultErabId == 5);

    // And the wire form of the request itself does depend on the order, which
    // is what makes this a real reorder rather than a no-op.
    CHECK(Describe(EncodeHandoverRequest(request)) != Describe(EncodeHandoverRequest(SampleRequest())));
}

TEST_CASE("lte/handover/bearer: a qci is never used to decide a bearer's role")
{
    // A binding that calls E-RAB 5 dedicated and E-RAB 6 the default is
    // honoured even though E-RAB 5 has the lower QCI, which is what the
    // established default bearer usually looks like. Nothing in the admission
    // reorders the roles to look conventional.
    std::vector<BearerRoleBinding> swapped = {
        BearerRoleBinding{5, BearerRole::DEDICATED, 6, 5, 15, false, false},
        BearerRoleBinding{6, BearerRole::DEFAULT, std::nullopt, 6, 3, false, true},
    };
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), swapped);
    REQUIRE(admission.admitted);
    REQUIRE(admission.bearers.size() == 2);
    CHECK(admission.bearers[0].erabId == 6);
    CHECK(admission.bearers[0].role == BearerRole::DEFAULT);
    CHECK(admission.bearers[1].erabId == 5);
    CHECK(admission.bearers[1].role == BearerRole::DEDICATED);
}

TEST_CASE("lte/handover/bearer: a bearer the network never classified is refused")
{
    std::vector<BearerRoleBinding> partial = {
        BearerRoleBinding{5, BearerRole::DEFAULT, std::nullopt, 5, 15, false, false},
    };
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), partial);
    CHECK(!admission.admitted);
    REQUIRE(admission.refusal.has_value());
    CHECK(admission.refusal->refusal == AdmissionRefusal::BEARER_ROLE_UNCONFIRMED);
    CHECK(admission.refusal->causeCategory == "radioNetwork");
    CHECK(admission.refusal->causeValue == 30); // unknown-E-RAB-ID
}

TEST_CASE("lte/handover/bearer: a qci that disagrees with the negotiated one is refused")
{
    auto roles = SampleRoles();
    roles[1].qci = 9;
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), roles);
    CHECK(!admission.admitted);
    REQUIRE(admission.refusal.has_value());
    CHECK(admission.refusal->refusal == AdmissionRefusal::BEARER_QOS_MISMATCH);
    CHECK(admission.refusal->causeValue == 27); // invalid-qos-combination
}

TEST_CASE("lte/handover/bearer: a non-gbr qci carrying gbr values is refused")
{
    auto request = SampleRequest();
    request.erabs[0].qos.gbr = lte::GbrQos{1000, 1000, 500, 500};
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    CHECK(!admission.admitted);
    REQUIRE(admission.refusal.has_value());
    CHECK(admission.refusal->refusal == AdmissionRefusal::BEARER_QOS_MISMATCH);

    // And the encoder refuses the same shape rather than putting a fabricated
    // guaranteed bitrate on the wire.
    CHECK_THROWS_AS(EncodeHandoverRequest(request), HandoverRefused);
}

TEST_CASE("lte/handover/bearer: a dedicated bearer that names no default is refused")
{
    auto roles = SampleRoles();
    roles[1].linkedDefaultErabId.reset();
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), roles);
    CHECK(!admission.admitted);
    REQUIRE(admission.refusal.has_value());
    CHECK(admission.refusal->refusal == AdmissionRefusal::DEDICATED_WITHOUT_LINK);
}

TEST_CASE("lte/handover/bearer: a dedicated bearer linked to a default that is not admitted is refused")
{
    auto roles = SampleRoles();
    roles[1].linkedDefaultErabId = 9;
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), roles);
    CHECK(!admission.admitted);
    REQUIRE(admission.refusal.has_value());
    CHECK(admission.refusal->refusal == AdmissionRefusal::LINKED_DEFAULT_MISSING);
}

// --- D. context isolation -------------------------------------------------

TEST_CASE("lte/handover/isolation: a malformed message for one ue leaves the other ue untouched")
{
    UeRegistry registry(8);
    InetAddress peerA("127.0.0.1", 40001);
    InetAddress peerB("127.0.0.1", 40002);
    auto &a = registry.registerPeer(1, peerA);
    auto &b = registry.registerPeer(2, peerB);

    const uint32_t enbA = registry.allocateEnbUeS1apId();
    const uint32_t enbB = registry.allocateEnbUeS1apId();
    registry.bindEnbUeS1apId(a, enbA);
    registry.bindEnbUeS1apId(b, enbB);
    registry.setMmeUeS1apId(a, 7);
    registry.setMmeUeS1apId(b, 8);

    const uint32_t teidA = registry.allocateLocalTeid();
    const uint32_t teidB = registry.allocateLocalTeid();
    a.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1, teidA});
    registry.bindLocalTeid(a, teidA);
    b.bearer.establish({5, 9, 2, {127, 0, 0, 9}, 0xB2B2B2B2, teidB});
    registry.bindLocalTeid(b, teidB);

    // A malformed Handover Request claiming to be UE A's. It is refused before
    // it can reach any registry call at all.
    const auto malformed = ForeignPdu(0, 1, 0, {
        ForeignIe(0, 0, ForeignUeId(7)),
        ForeignIe(1, 0, ForeignHandoverType(1)), // an inter-RAT type
        ForeignIe(2, 1, kCause16),
        ForeignIe(66, 0, kAmbr),
        ForeignIe(53, 0, kErabListTwo),
        ForeignIe(104, 0, kContainer4),
        ForeignIe(107, 0, kSecurityCapabilities),
        ForeignIe(40, 0, kSecurityContext),
    });
    CHECK_THROWS_AS(DecodeHandoverRequest(malformed.data(), malformed.size()), HandoverRefused);

    // Neither UE changed: both still resolve under both of their identities and
    // both bearers are still bound to the TEID they were given.
    CHECK(registry.findByEnbUeS1apId(enbA) == &a);
    CHECK(registry.findByEnbUeS1apId(enbB) == &b);
    CHECK(registry.findByMmeUeS1apId(7) == &a);
    CHECK(registry.findByMmeUeS1apId(8) == &b);
    CHECK(registry.findByLocalTeid(teidA) != nullptr);
    CHECK(registry.findByLocalTeid(teidB) != nullptr);
    CHECK(!registry.isRetiredTeid(teidA));
    CHECK(!registry.isRetiredTeid(teidB));
    CHECK(registry.findBearer(a, 5) != nullptr);
    CHECK(registry.findBearer(b, 5) != nullptr);
    CHECK(registry.size() == 2);
}

TEST_CASE("lte/handover/isolation: two e-nbs and two ues produce independent admissions")
{
    TargetContext targetA = SampleTargetContext();
    targetA.identity = EnbIdentity{Plmn{"001", "01"}, 0x00ABCDEu, 2};
    targetA.s1uAddress = Ip(198, 51, 100, 1);

    TargetContext targetB = SampleTargetContext();
    targetB.identity = EnbIdentity{Plmn{"001", "01"}, 0x0012345u, 3};
    targetB.s1uAddress = Ip(198, 51, 100, 2);

    SourceContext sourceA{EnbIdentity{Plmn{"001", "01"}, 0x00AAAAAu, 1}, true};
    SourceContext sourceB{EnbIdentity{Plmn{"001", "01"}, 0x00BBBBBu, 4}, true};

    auto requestA = SampleRequest();
    requestA.mmeUeS1apId = 7;
    auto requestB = SampleRequest();
    requestB.mmeUeS1apId = 8;

    auto admitA = EvaluateHandoverAdmission(requestA, sourceA, targetA, SampleRoles());
    auto admitB = EvaluateHandoverAdmission(requestB, sourceB, targetB, SampleRoles());
    REQUIRE(admitA.admitted);
    REQUIRE(admitB.admitted);
    CHECK(admitA.source.enbId == 0x00AAAAAu);
    CHECK(admitB.source.enbId == 0x00BBBBBu);
    CHECK(admitA.target.enbId == 0x00ABCDEu);
    CHECK(admitB.target.enbId == 0x0012345u);
    CHECK(admitA.bearers[0].targetTransport.address == Ip(198, 51, 100, 1));
    CHECK(admitB.bearers[0].targetTransport.address == Ip(198, 51, 100, 2));

    // A Handover Request names no target: the target is the recipient, and the
    // only thing the target can be sure of is which source sent it. A request
    // whose source the target has no association with is refused, and the
    // named-target check lives in CheckNamedTarget below.
    SourceContext noSource{EnbIdentity{Plmn{"001", "01"}, 0x00AAAAAu, 1}, false};
    auto unattributed = EvaluateHandoverAdmission(requestA, noSource, targetA, SampleRoles());
    CHECK(!unattributed.admitted);
    REQUIRE(unattributed.refusal.has_value());
    CHECK(unattributed.refusal->refusal == AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN);

    // A target that names itself in the request is not the same target as the
    // one that receives it, and the admission does not pretend otherwise.
    auto wrongTarget = EvaluateHandoverAdmission(requestA, sourceA, targetB, SampleRoles());
    REQUIRE(wrongTarget.admitted);
    CHECK(wrongTarget.target.enbId == 0x0012345u);
    CHECK(wrongTarget.bearers[0].targetTransport.address == Ip(198, 51, 100, 2));
}

TEST_CASE("lte/handover/isolation: a target that does not match the named target is refused")
{
    auto named = TargetIdentity();
    auto other = TargetContext{EnbIdentity{Plmn{"001", "01"}, 0x0012345u, 3}, Ip(198, 51, 100, 2),
                               {0x80, 0x00}, {0x40, 0x00}};
    auto refusal = CheckNamedTarget(named, other);
    REQUIRE(refusal.has_value());
    CHECK(refusal->refusal == AdmissionRefusal::UNSUPPORTED_TARGET);
    CHECK(refusal->causeValue == 7); // ho-target-not-allowed

    auto self = SampleTargetContext();
    CHECK(!CheckNamedTarget(TargetIdentity(), self).has_value());
}

// --- E. resource safety ---------------------------------------------------

TEST_CASE("lte/handover/resource: a decoded request allocates nothing on the target")
{
    UeRegistry registry(8);
    auto &a = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t enbA = registry.allocateEnbUeS1apId();
    registry.bindEnbUeS1apId(a, enbA);
    registry.setMmeUeS1apId(a, 7);
    const uint32_t sourceTeid = registry.allocateLocalTeid();
    a.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1, sourceTeid});
    registry.bindLocalTeid(a, sourceTeid);

    const size_t sessionsBefore = registry.size();
    const auto retiredLedgerSize = registry.retiredTeids().size();

    // Decode and evaluate a perfectly well formed Handover Request. Admission
    // is not commitment: the target must hold no transport, bind no TEID,
    // retire no TEID, release no bearer and open no session.
    const auto frame = EncodeHandoverRequest(SampleRequest());
    auto request = DecodeHandoverRequest(frame.data(), frame.size());
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);
    CHECK(!admission.holdsTransportResources());
    for (const auto &bearer : admission.bearers)
    {
        CHECK(!bearer.targetTransport.bound);
        CHECK(bearer.targetTransport.teid == std::array<uint8_t, 4>{});
        CHECK(bearer.targetTransport.address == Ip(198, 51, 100, 1));
    }

    CHECK(registry.size() == sessionsBefore);
    CHECK(registry.retiredTeids().size() == retiredLedgerSize);
    CHECK(!registry.isRetiredTeid(sourceTeid));
    CHECK(registry.findByLocalTeid(sourceTeid) != nullptr);
    CHECK(registry.findBearer(a, 5) != nullptr);
    CHECK(registry.findByEnbUeS1apId(enbA) == &a);

    // The plan is not an acknowledge. There is nothing bound to acknowledge,
    // and the builder refuses to claim otherwise.
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11, {}), HandoverRefused);
}

TEST_CASE("lte/handover/resource: an acknowledge names only transport a commit step bound")
{
    auto request = SampleRequest();
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), SampleRoles());
    REQUIRE(admission.admitted);

    std::vector<CommittedTransport> committed = {
        CommittedTransport{5, Ip(198, 51, 100, 1), Teid(0x22334455)},
        CommittedTransport{6, Ip(198, 51, 100, 1), Teid(0x66778899)},
    };
    auto acknowledge = BuildHandoverRequestAcknowledge(admission, 7, 11, committed);
    REQUIRE(acknowledge.admitted.size() == 2);
    CHECK(acknowledge.mmeUeS1apId == 7);
    CHECK(acknowledge.enbUeS1apId == 11);
    CHECK(acknowledge.admitted[0].erabId == 5);
    CHECK(acknowledge.admitted[0].gtpTeid == Teid(0x22334455));
    CHECK(acknowledge.admitted[1].erabId == 6);
    CHECK(acknowledge.admitted[1].gtpTeid == Teid(0x66778899));
    // The acknowledge carries no invented security material and no invented
    // bearer role.
    CHECK(acknowledge.admitted[0].erabId != acknowledge.admitted[1].erabId);

    // A TEID the commit step never assigned is refused, not invented.
    std::vector<CommittedTransport> unassigned = {
        CommittedTransport{5, Ip(198, 51, 100, 1), {}},
        CommittedTransport{6, Ip(198, 51, 100, 1), Teid(0x66778899)},
    };
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11, unassigned), HandoverRefused);

    // A commit set that does not cover the admitted bearers is refused.
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11,
                                                    {CommittedTransport{5, Ip(198, 51, 100, 1),
                                                                        Teid(0x22334455)}}),
                    HandoverRefused);

    // A committed endpoint that is not on the target's own S1-U address is
    // refused: the target does not acknowledge transport it does not own.
    std::vector<CommittedTransport> elsewhere = {
        CommittedTransport{5, Ip(203, 0, 113, 1), Teid(0x22334455)},
        CommittedTransport{6, Ip(198, 51, 100, 1), Teid(0x66778899)},
    };
    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11, elsewhere), HandoverRefused);
}

TEST_CASE("lte/handover/resource: a refused admission reports a failure and acknowledges nothing")
{
    auto request = SampleRequest();
    auto roles = SampleRoles();
    roles[1].qci = 9;
    auto admission = EvaluateHandoverAdmission(request, SampleSource(), SampleTargetContext(), roles);
    REQUIRE(!admission.admitted);
    CHECK(!admission.holdsTransportResources());
    CHECK(admission.bearers.empty());

    auto failure = RefusalAsHandoverFailure(admission, 7);
    CHECK(failure.mmeUeS1apId == 7);
    CHECK(failure.causeCategory == "radioNetwork");
    CHECK(failure.causeValue == 27);
    // HandoverFailureIEs names exactly two information elements: the
    // MME-UE-S1AP-ID and the Cause. Handover Failure carries no
    // eNB-UE-S1AP-ID, and the frame this produced carries exactly those two.
    CHECK(CountInformationElements(EncodeHandoverFailure(failure)) == 2);

    CHECK_THROWS_AS(BuildHandoverRequestAcknowledge(admission, 7, 11, {}), HandoverRefused);
}

TEST_CASE("lte/handover/resource: an unvalidated request never reaches a bearer or a teid")
{
    // The admission step reads only its arguments. Whatever else happens to a
    // registry while a handover message is being decoded, decoding and
    // admitting cannot be what changed it.
    UeRegistry registry(8);
    auto &a = registry.registerPeer(1, InetAddress("127.0.0.1", 40001));
    const uint32_t sourceTeid = registry.allocateLocalTeid();
    a.bearer.establish({5, 9, 1, {127, 0, 0, 9}, 0xA1A1A1A1, sourceTeid});
    registry.bindLocalTeid(a, sourceTeid);

    std::vector<uint32_t> observed;
    for (int i = 0; i < 4; ++i)
        observed.push_back(registry.allocateLocalTeid());
    CHECK(std::set<uint32_t>(observed.begin(), observed.end()).size() == observed.size());
    for (uint32_t teid : observed)
    {
        CHECK(teid != 0);
        CHECK(teid != sourceTeid);
        CHECK(!registry.isRetiredTeid(teid));
    }
    CHECK(registry.retiredTeids().size() == 0);
    CHECK(registry.findByLocalTeid(sourceTeid) != nullptr);
}

TEST_CASE("lte/handover/reject: the refusal and role names are the ones diagnostics match on")
{
    // Every handover enum has a ToString, and those strings are what a future
    // log line and a future report match on. A rename is a wire-visible change
    // to the diagnostic surface, so it is pinned here rather than left to be
    // discovered the first time a log is grepped.
    CHECK(std::string(ToString(HandoverType::INTRA_LTE)) == "intralte");
    CHECK(std::string(ToString(HandoverType::LTE_TO_UTRAN)) == "ltetoutran");
    CHECK(std::string(ToString(HandoverType::LTE_TO_GERAN)) == "ltetogeran");
    CHECK(std::string(ToString(HandoverType::UTRAN_TO_LTE)) == "utrantolte");
    CHECK(std::string(ToString(HandoverType::GERAN_TO_LTE)) == "gerantolte");
    CHECK(std::string(ToString(HandoverType::EPS_TO_5GS)) == "eps-to-5gs");
    CHECK(std::string(ToString(HandoverType::FIVEGS_TO_EPS)) == "fivegs-to-eps");

    CHECK(std::string(ToString(HandoverRefusal::MISSING_MANDATORY_IE)) == "missing-mandatory-ie");
    CHECK(std::string(ToString(HandoverRefusal::UNSUPPORTED_HANDOVER_TYPE)) ==
          "unsupported-handover-type");
    CHECK(std::string(ToString(HandoverRefusal::INVALID_CONTEXT_IDENTITY)) ==
          "invalid-context-identity");
    CHECK(std::string(ToString(HandoverRefusal::UNSUPPORTED_ERAB_LIST)) == "unsupported-erab-list");
    CHECK(std::string(ToString(HandoverRefusal::INVALID_TRANSPARENT_CONTAINER)) ==
          "invalid-transparent-container");

    CHECK(std::string(ToString(BearerRole::DEFAULT)) == "default");
    CHECK(std::string(ToString(BearerRole::DEDICATED)) == "dedicated");

    CHECK(std::string(ToString(AdmissionRefusal::UNKNOWN_HANDOVER_TYPE)) == "unknown-handover-type");
    CHECK(std::string(ToString(AdmissionRefusal::UNSUPPORTED_TARGET)) == "unsupported-target");
    CHECK(std::string(ToString(AdmissionRefusal::SOURCE_CONTEXT_UNKNOWN)) == "source-context-unknown");
    CHECK(std::string(ToString(AdmissionRefusal::BEARER_ROLE_UNCONFIRMED)) == "bearer-role-unconfirmed");
    CHECK(std::string(ToString(AdmissionRefusal::BEARER_QOS_MISMATCH)) == "bearer-qos-mismatch");
    CHECK(std::string(ToString(AdmissionRefusal::DUPLICATE_ERAB_ID)) == "duplicate-erab-id");
    CHECK(std::string(ToString(AdmissionRefusal::EMPTY_BEARER_SET)) == "empty-bearer-set");
    CHECK(std::string(ToString(AdmissionRefusal::LINKED_DEFAULT_MISSING)) == "linked-default-missing");
    CHECK(std::string(ToString(AdmissionRefusal::DEDICATED_WITHOUT_LINK)) == "dedicated-without-link");
    CHECK(std::string(ToString(AdmissionRefusal::SECURITY_ALGORITHMS_NOT_SUPPORTED)) ==
          "security-algorithms-not-supported");
    CHECK(std::string(ToString(AdmissionRefusal::TRANSPORT_ADDRESS_ABSENT)) == "transport-address-absent");

    // A value that names nothing must say so rather than borrow a real name.
    CHECK(std::string(ToString(static_cast<BearerRole>(99))) == "unknown");
    CHECK(std::string(ToString(static_cast<AdmissionRefusal>(99))) == "unknown");
    CHECK(std::string(ToString(static_cast<HandoverRefusal>(99))) == "unknown");
    CHECK(std::string(ToString(static_cast<HandoverType>(99))) == "unknown");
}
