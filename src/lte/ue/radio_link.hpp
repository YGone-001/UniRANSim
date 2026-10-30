//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Minimal, LTE-specific NAS and IPv4 transport between the software UE and eNB.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
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
    PAGING_INDICATION = 11,
    // Uplink NAS that continues an existing EPS session over a new S1
    // connection because the UE reselected a cell in ECM-IDLE. Payload:
    // MMEC(1)||M-TMSI(4)||protected NAS, the same identity prefix the compact
    // Service Request uses, and for the same reason: the eNB cannot read the
    // protected NAS, so the UE states which session this belongs to.
    //
    // It is deliberately distinct from NAS_UPLINK. NAS_UPLINK on an endpoint
    // with no S1 connection starts a fresh Attach, which is a new logical EPS
    // session; this one is not, so the eNB must build the Initial UE Message
    // without tearing down any EPS bearer context it still holds for the UE.
    NAS_UPLINK_MOBILITY = 19,
    // The same mobility uplink, additionally declaring the bearer inventory the
    // UE holds from its own NAS-confirmed contexts. Payload:
    // MMEC(1)||M-TMSI(4)||defaultEbi(1)||dedicatedCount(1)||dedicatedEbi[count]
    // ||protected NAS.
    //
    // A cell the UE reselected into has never seen the session's Attach, so it
    // holds no logical EPS bearer context of its own and cannot tell the
    // default bearer from the dedicated ones: the E-RAB list of an Initial
    // Context Setup Request names only E-RAB identifiers and QoS and marks no
    // roles, and inferring them from QCI or from the order of that list is
    // guessing. This declaration supplies the roles the UE's own NAS already
    // confirmed.
    //
    // It is a claim about the UE's session and it can only ever restrict what
    // the network authorized: an E-RAB the declaration does not name is not
    // established for this UE, and a declaration naming a bearer the network
    // did not put in its E-RAB list establishes nothing at all. It therefore
    // cannot make a network bearer true on its own, and it carries no
    // subscriber key and no authentication material.
    NAS_UPLINK_MOBILITY_CONTEXT = 20
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

// A UE accepting the fresh transport of one restored bearer. It names the
// bearer and the access epoch it confirms, and it restates the PDN address its
// own NAS already assigned. A cell that never saw the session's Attach cannot
// learn that address without decrypting NAS, and it is never invented here:
// the UE only restates what it holds, and a cell that already knows the
// address refuses any restatement that differs from it. No subscriber key and
// no authentication material travels with it.
struct BearerTransportReady
{
    uint8_t ebi{};
    uint32_t generation{};
    std::optional<std::array<uint8_t, 4>> ueIpv4;
};

std::vector<uint8_t> EncodeBearerTransportReady(uint8_t ebi, uint32_t generation,
                                                const std::array<uint8_t, 4> &ueIpv4);
// The two bounded forms: five octets naming only the bearer and the epoch, or
// nine also restating the PDN address. Nothing else is a confirmation.
BearerTransportReady DecodeBearerTransportReady(const uint8_t *data, size_t size);

bool IsUplink(MessageType type);
bool IsDownlink(MessageType type);

// The bounded bearer inventory a NAS_UPLINK_MOBILITY_CONTEXT payload declares
// alongside its NAS: the default EPS bearer identity the UE holds, plus the
// dedicated identities on top of it. Every identity comes from a context the
// UE's own NAS has already confirmed, so the set is known and finite.
struct BearerInventory
{
    uint8_t defaultEbi{};
    std::vector<uint8_t> dedicatedEbis;
};

// The declaration is a claim that travels over a simulated radio link, so its
// encoding is bounded to the same capacity one UE can hold rather than to
// whatever a datagram happens to carry.
constexpr size_t MaxDeclaredDedicatedBearers = 7;

// Encodes the inventory prefix of a NAS_UPLINK_MOBILITY_CONTEXT payload:
// defaultEbi(1) || dedicatedCount(1) || dedicatedEbi[dedicatedCount].
std::vector<uint8_t> EncodeBearerInventory(const BearerInventory &inventory);
// Decodes that prefix and reports how many octets it occupies, so the protected
// NAS that follows can be taken from the remainder. Throws DecodeError unless
// the claim is exactly the bounded, ordered and unambiguous form
// EncodeBearerInventory produces: an assignable default identity, at most
// MaxDeclaredDedicatedBearers dedicated identities, each assignable, strictly
// increasing and never the default one.
size_t DecodeBearerInventory(const uint8_t *data, size_t size, BearerInventory &inventory);

// Builds the complete NAS_UPLINK_MOBILITY_CONTEXT message a reselected cell
// receives: MMEC(1) || M-TMSI(4 BE) || bearer inventory || protected NAS.
//
// The identity prefix is derived from the UE's own valid GUTI, so the target
// eNB can address the Initial UE Message without the UE presenting any
// identifier the source cell allocated. The declaration is encoded before a
// frame exists, so an inventory the wire cannot express and a mobility uplink
// with no protected NAS are both refused here rather than transmitted as a
// claim a target would act on. The protected NAS bytes are carried verbatim:
// they are never rewritten or trimmed to make room for the declaration, and no
// subscriber key or authentication vector is ever placed beside them.
Message BuildMobilityContext(uint32_t ueId, const std::array<uint8_t, 11> &guti, const BearerInventory &inventory,
                             const std::vector<uint8_t> &protectedNas);

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
