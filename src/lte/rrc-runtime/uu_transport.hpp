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
    // When sourcePort is not null it receives the sender's port, which lets a
    // multi-UE endpoint answer an association it has just learned about without
    // adding a field to the envelope.
    bool Receive(Frame &out, int timeoutMs, std::string *why, uint16_t *sourcePort = nullptr);

    // Releases a frame the reorder impairment is holding to its own destination.
    // A held frame is bounded: it leaves on the next send, on this call, or is
    // counted and discarded by Close(). It is never handed to Receive().
    bool FlushPending(std::string *why);
    [[nodiscard]] bool HasPending() const noexcept
    {
        return pending_.has_value();
    }

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
    [[nodiscard]] uint64_t Held() const noexcept
    {
        return held_;
    }
    [[nodiscard]] uint64_t Released() const noexcept
    {
        return released_;
    }
    [[nodiscard]] uint64_t PendingDropped() const noexcept
    {
        return pendingDropped_;
    }
    void SetLinkModel(const LinkModel &model) noexcept
    {
        link_ = model;
    }

  private:
    struct Pending
    {
        Frame frame{};
        uint16_t destination{0};
    };

    bool RawSend(uint16_t port, const Frame &frame, std::string *why);

    int fd_{-1};
    uint16_t port_{0};
    uint64_t sent_{0};
    uint64_t dropped_{0};
    uint64_t malformed_{0};
    uint64_t held_{0};
    uint64_t released_{0};
    uint64_t pendingDropped_{0};
    uint32_t sequence_{0};
    LinkModel link_{};
    std::optional<Pending> pending_{};
};

} // namespace lte::uu
