//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

// Traffic Flow Template handling for the supported IPv4 EPS bearer subset.
//
// Wire format is TS 24.008 10.5.6.12 as applied by TS 24.301 9.9.4.11. The
// component type identifiers and the packet filter header layout used here were
// validated against a real Open5GS MME E-RAB Setup Request capture, not inferred
// from names alone. Only IPv4 is supported, matching the LTE user plane of this
// project.
namespace lte::tft
{

class TftError : public std::runtime_error
{
  public:
    explicit TftError(const std::string &message, uint8_t cause = 42) : std::runtime_error(message), esmCause(cause)
    {
    }
    uint8_t esmCause;
};

// A TFT cannot carry more than 15 filters (4-bit count field), and no single
// filter is allowed to exceed the component budget below.
constexpr size_t MaxPacketFilters = 15;
constexpr size_t MaxComponentsPerFilter = 8;
constexpr size_t MaxTftSize = 255;

// Packet filter direction, TS 24.008 10.5.6.12. Values are the on-wire codes.
enum class FilterDirection : uint8_t
{
    DOWNLINK_ONLY = 1,
    UPLINK_ONLY = 2,
    BIDIRECTIONAL = 3
};

// TFT operation code, TS 24.008 10.5.6.12. Values are the on-wire codes.
enum class OperationCode : uint8_t
{
    CREATE_NEW = 1,
    DELETE_EXISTING = 2,
    ADD_FILTERS = 3,
    REPLACE_FILTERS = 4,
    DELETE_FILTERS = 5,
    NO_TFT_OPERATION = 6
};

// Packet filter component type identifiers, TS 24.008 10.5.6.12.
constexpr uint8_t ComponentIpv4RemoteAddress = 0x10;
constexpr uint8_t ComponentIpv4LocalAddress = 0x11;
constexpr uint8_t ComponentProtocolOrNextHeader = 0x30;
constexpr uint8_t ComponentSingleLocalPort = 0x40;
constexpr uint8_t ComponentSingleRemotePort = 0x50;
constexpr uint8_t ComponentLocalPortRange = 0x41;
constexpr uint8_t ComponentRemotePortRange = 0x51;

// One decoded packet filter. A component that is absent never matches-tests
// against a value; it simply does not constrain that packet dimension.
struct PacketFilter
{
    uint8_t identifier{};
    uint8_t precedence{};
    FilterDirection direction{FilterDirection::BIDIRECTIONAL};

    bool hasProtocol{};
    uint8_t protocol{};

    bool hasRemoteAddress{};
    std::array<uint8_t, 4> remoteAddress{};
    std::array<uint8_t, 4> remoteMask{};

    bool hasLocalAddress{};
    std::array<uint8_t, 4> localAddress{};
    std::array<uint8_t, 4> localMask{};

    bool hasLocalPort{};
    uint16_t localPortLow{};
    uint16_t localPortHigh{};

    bool hasRemotePort{};
    uint16_t remotePortLow{};
    uint16_t remotePortHigh{};

    [[nodiscard]] bool appliesTo(bool uplink) const
    {
        if (direction == FilterDirection::BIDIRECTIONAL)
            return true;
        return uplink ? direction == FilterDirection::UPLINK_ONLY : direction == FilterDirection::DOWNLINK_ONLY;
    }
};

struct TrafficFlowTemplate
{
    OperationCode operation{OperationCode::NO_TFT_OPERATION};
    bool parametersPresent{};
    std::vector<PacketFilter> filters;
};

// Decodes the TFT value field. `data` points at the TFT operation header, so the
// caller has already consumed the IEI and the one-octet TLV length. Throws
// TftError on any malformed, truncated, duplicated or unsupported structure.
TrafficFlowTemplate Decode(const uint8_t *data, size_t size);

// Encodes a TFT value field (operation header + filters), excluding IEI and
// length. Used by fixtures and by the UE acceptance tests.
std::vector<uint8_t> Encode(const TrafficFlowTemplate &tft);

// Evaluates one IPv4 packet against a filter list. Filters are evaluated in
// ascending precedence order; the first matching filter that applies to the
// direction wins. Returns nullptr when no filter matches, which the caller maps
// to the default bearer.
const PacketFilter *Classify(const std::vector<PacketFilter> &filters, const uint8_t *ipPacket, size_t size,
                             bool uplink);

// Maintains the accumulated filter set of one dedicated bearer across TFT
// operations, because the network may add, replace or delete filters instead of
// always creating the TFT from scratch.
class TftState
{
  public:
    void apply(const TrafficFlowTemplate &tft);
    void clear();

    [[nodiscard]] bool empty() const { return m_filters.empty(); }
    [[nodiscard]] size_t size() const { return m_filters.size(); }
    [[nodiscard]] const std::vector<PacketFilter> &filters() const { return m_filters; }
    [[nodiscard]] const PacketFilter *classify(const uint8_t *ipPacket, size_t size, bool uplink) const;

  private:
    std::vector<PacketFilter> m_filters;
};

} // namespace lte::tft
