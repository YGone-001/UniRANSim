//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-A: the simulated Uu bearer transport.
//
// It carries opaque RLC PDUs between an independently running UE and eNB. The
// envelope below is simulator routing metadata, not an LTE header: it names the
// transport association, the direction and the logical channel, and carries the
// RLC PDU byte for byte. It never embeds an RRC message type, so an RRC message
// can only travel through RLC.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lte::uu
{

enum class Direction : uint8_t
{
    UPLINK = 0,
    DOWNLINK = 1,
};

enum class LogicalChannel : uint8_t
{
    CCCH = 0,
    DCCH = 1,
};

struct Frame
{
    uint32_t association{0};
    Direction direction{Direction::UPLINK};
    LogicalChannel channel{LogicalChannel::CCCH};
    std::vector<uint8_t> payload{};
};

constexpr uint8_t EnvelopeVersion = 1;
constexpr size_t MaxPayload = 2048;
constexpr size_t EnvelopeSize = 4 + 4 + 1 + 1 + 2;

[[nodiscard]] std::vector<uint8_t> EncodeFrame(const Frame &frame);
// Rejects a bad magic, a wrong version, an unknown direction or channel, a
// length that does not match the datagram, and an oversized payload.
[[nodiscard]] bool DecodeFrame(const uint8_t *data, size_t size, Frame &out, std::string *why);

// Deterministic, test-only link impairments. Zero disables a behaviour.
struct LinkModel
{
    uint32_t dropEveryNth{0};
    uint32_t duplicateEveryNth{0};
    uint32_t reorderEveryNth{0};
};

class Socket
{
  public:
    Socket() = default;
    ~Socket();
    Socket(const Socket &) = delete;
    Socket &operator=(const Socket &) = delete;
    Socket(Socket &&other) noexcept;
    Socket &operator=(Socket &&other) noexcept;

    static std::optional<Socket> BindLoopback(uint16_t port, std::string *why);
    [[nodiscard]] uint16_t Port() const noexcept
    {
        return port_;
    }
    [[nodiscard]] int Fd() const noexcept
    {
        return fd_;
    }
    void Close() noexcept;

    // Sends one frame to 127.0.0.1:port. A frame the link model drops is counted
    // and reported as sent-but-lost; the caller's RLC/RRC layer must notice the
    // absence, so nothing is retried here.
    bool Send(uint16_t port, const Frame &frame, std::string *why);
    // Waits up to timeoutMs for one frame. Returns false on timeout or error.
    bool Receive(Frame &out, int timeoutMs, std::string *why);

    [[nodiscard]] uint64_t Sent() const noexcept
    {
        return sent_;
    }
    [[nodiscard]] uint64_t Dropped() const noexcept
    {
        return dropped_;
    }
    [[nodiscard]] uint64_t Malformed() const noexcept
    {
        return malformed_;
    }
    void SetLinkModel(const LinkModel &model) noexcept
    {
        link_ = model;
    }

  private:
    int fd_{-1};
    uint16_t port_{0};
    uint64_t sent_{0};
    uint64_t dropped_{0};
    uint64_t malformed_{0};
    uint32_t sequence_{0};
    LinkModel link_{};
    std::optional<Frame> pending_{};
};

} // namespace lte::uu
