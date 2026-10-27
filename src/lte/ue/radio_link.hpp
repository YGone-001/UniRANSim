//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Minimal, LTE-specific NAS and IPv4 transport between the software UE and eNB.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <utility>

namespace lte::ue::link
{

constexpr size_t MaxNasPduSize = 2048;
constexpr size_t MaxDataPduSize = 4096;
constexpr size_t HeaderSize = 8;

enum class MessageType : uint8_t
{
    NAS_UPLINK = 1,
    NAS_DOWNLINK = 2,
    DATA_UPLINK = 3,
    DATA_DOWNLINK = 4,
    BEARER_READY = 5,
    // Legacy bearer deletion indication. It remains decodable for wire
    // compatibility but is not used for an ordinary S1 context release.
    BEARER_RELEASED = 6,
    S1_CONTEXT_RELEASE_REQUEST = 7,
    S1_CONTEXT_RELEASED = 8,
    S1_CONTEXT_RESTORED = 9,
    // MMEC(1)||M-TMSI(4)||compact Service Request NAS(4).
    SERVICE_REQUEST = 10,
    // Bearer-aware user-plane frames. The payload starts with the EPS bearer
    // identity, so a packet can never be attributed to the wrong bearer and an
    // unknown EBI is rejected instead of falling back to the default bearer.
    DATA_UPLINK_BEARER = 12,
    DATA_DOWNLINK_BEARER = 13,
    // Uplink confirmation that the UE accepted a dedicated bearer activation.
    // Payload: EBI(1).
    BEARER_ACTIVATED = 14,
    // EBI(1) || access release generation(4), network byte order.
    DEDICATED_BEARER_RESTORED = 15,
    BEARER_TRANSPORT_READY = 16,
    EPS_SESSION_DELETED = 17,
    // Downlink-only INTERNAL simulator abstraction. Payload: EBI(1) || access
    // generation(4). It reports that the eNB lost its S1-MME association and
    // that this UE's access transport has been invalidated.
    //
    // It is NOT a 3GPP message. It is not a UE Context Release Command or
    // Complete, not a NAS message and not an RRC message: no such procedure was
    // executed on the network side. Only the simulated software-radio access
    // transport is affected; the EPS registration, security context, GUTI,
    // logical bearers, TFT and PDN address of the UE are retained.
    S1_ACCESS_LOST = 18,
    // Downlink-only simulation of an LTE paging occasion.
    // MMEC(1)||M-TMSI(4)||served TAC(2). It carries no IMSI and no NAS
    // material, so a UE can only match it against the S-TMSI of its own
    // valid GUTI. This is a laboratory abstraction, not an RRC Paging message.
    PAGING_INDICATION = 11
};

struct Message
{
    MessageType type{};
    uint32_t ueId{};
    std::vector<uint8_t> payload;
};

class DecodeError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

std::vector<uint8_t> Encode(const Message &message);
Message Decode(const uint8_t *data, size_t size);
std::vector<uint8_t> EncodeBearerRestoration(uint8_t ebi, uint32_t generation);
std::pair<uint8_t, uint32_t> DecodeBearerRestoration(const std::vector<uint8_t> &payload);
bool IsUplink(MessageType type);
bool IsDownlink(MessageType type);

// Payload of one simulated paging occasion: the S-TMSI being paged plus the
// served tracking area. Both the eNB fanout and the UE matching path share this
// encoding, so a notification cannot be reinterpreted on the way.
struct PagingNotification
{
    uint8_t mmeCode{};
    uint32_t mTmsi{};
    uint16_t tac{};
};

// Seven-octet MMEC || M-TMSI || TAC payload. Throws DecodeError on any length
// violation or zero M-TMSI.
std::vector<uint8_t> EncodePagingNotification(const PagingNotification &notification);
PagingNotification DecodePagingNotification(const uint8_t *data, size_t size);

} // namespace lte::ue::link
