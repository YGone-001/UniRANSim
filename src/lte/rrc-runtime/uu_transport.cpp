//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

#include "uu_transport.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

namespace lte::uu
{
namespace
{

constexpr uint8_t Magic0 = 'U';
constexpr uint8_t Magic1 = 'U';

void PutU32(std::vector<uint8_t> &out, uint32_t value)
{
    out.push_back(static_cast<uint8_t>((value >> 24U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 16U) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
}

uint32_t GetU32(const uint8_t *data)
{
    return (static_cast<uint32_t>(data[0]) << 24U) | (static_cast<uint32_t>(data[1]) << 16U) |
           (static_cast<uint32_t>(data[2]) << 8U) | static_cast<uint32_t>(data[3]);
}

sockaddr_in Loopback(uint16_t port)
{
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
}

} // namespace

std::vector<uint8_t> EncodeFrame(const Frame &frame)
{
    std::vector<uint8_t> out;
    out.reserve(EnvelopeSize + frame.payload.size());
    out.push_back(Magic0);
    out.push_back(Magic1);
    out.push_back(EnvelopeVersion);
    out.push_back(0);  // reserved, must be zero
    PutU32(out, frame.association);
    out.push_back(static_cast<uint8_t>(frame.direction));
    out.push_back(static_cast<uint8_t>(frame.channel));
    out.push_back(static_cast<uint8_t>((frame.payload.size() >> 8U) & 0xFFU));
    out.push_back(static_cast<uint8_t>(frame.payload.size() & 0xFFU));
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
}

bool DecodeFrame(const uint8_t *data, size_t size, Frame &out, std::string *why)
{
    if (size < EnvelopeSize)
    {
        if (why)
            *why = "frame shorter than the envelope";
        return false;
    }
    if (data[0] != Magic0 || data[1] != Magic1)
    {
        if (why)
            *why = "bad magic";
        return false;
    }
    if (data[2] != EnvelopeVersion || data[3] != 0)
    {
        if (why)
            *why = "unsupported version";
        return false;
    }
    const uint8_t direction = data[8];
    const uint8_t channel = data[9];
    if (direction > static_cast<uint8_t>(Direction::DOWNLINK) || channel > static_cast<uint8_t>(LogicalChannel::PCCH))
    {
        if (why)
            *why = "unknown direction or logical channel";
        return false;
    }
    const size_t length = (static_cast<size_t>(data[10]) << 8U) | static_cast<size_t>(data[11]);
    if (length > MaxPayload)
    {
        if (why)
            *why = "payload exceeds the transport maximum";
        return false;
    }
    if (size != EnvelopeSize + length)
    {
        if (why)
            *why = "declared length does not match the datagram";
        return false;
    }
    out.association = GetU32(data + 4);
    out.direction = static_cast<Direction>(direction);
    out.channel = static_cast<LogicalChannel>(channel);
    out.payload.assign(data + EnvelopeSize, data + size);
    return true;
}

Socket::~Socket()
{
    Close();
}

Socket::Socket(Socket &&other) noexcept
{
    *this = std::move(other);
}

Socket &Socket::operator=(Socket &&other) noexcept
{
    if (this == &other)
        return *this;
    Close();
    fd_ = other.fd_;
    port_ = other.port_;
    sent_ = other.sent_;
    dropped_ = other.dropped_;
    malformed_ = other.malformed_;
    held_ = other.held_;
    released_ = other.released_;
    pendingDropped_ = other.pendingDropped_;
    sequence_ = other.sequence_;
    link_ = other.link_;
    pending_ = std::move(other.pending_);
    other.fd_ = -1;
    other.port_ = 0;
    other.pending_.reset();
    return *this;
}

void Socket::Close() noexcept
{
    // A pending frame has no receiver left. Dropping it is the cancellation
    // outcome: counted, never handed to a local Receive() and never leaked into
    // another socket.
    if (pending_)
    {
        pending_.reset();
        pendingDropped_++;
    }
    if (fd_ >= 0)
        ::close(fd_);
    fd_ = -1;
}

std::optional<Socket> Socket::Bind(const std::string &address, uint16_t port, std::string *why)
{
    in_addr parsed{};
    if (::inet_pton(AF_INET, address.c_str(), &parsed) != 1)
    {
        if (why)
            *why = "not a concrete IPv4 address";
        return std::nullopt;
    }
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        if (why)
            *why = "socket() failed";
        return std::nullopt;
    }
    sockaddr_in address4{};
    address4.sin_family = AF_INET;
    address4.sin_addr = parsed;
    address4.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address4), sizeof(address4)) != 0)
    {
        if (why)
            *why = "bind() failed";
        ::close(fd);
        return std::nullopt;
    }
    socklen_t length = sizeof(address4);
    sockaddr_in bound{};
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &length) != 0)
    {
        if (why)
            *why = "getsockname() failed";
        ::close(fd);
        return std::nullopt;
    }
    Socket socket;
    socket.fd_ = fd;
    socket.port_ = ntohs(bound.sin_port);
    return socket;
}

std::optional<Socket> Socket::BindLoopback(uint16_t port, std::string *why)
{
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        if (why)
            *why = "socket() failed";
        return std::nullopt;
    }
    const sockaddr_in address = Loopback(port);
    if (::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0)
    {
        if (why)
            *why = "bind() failed";
        ::close(fd);
        return std::nullopt;
    }
    socklen_t length = sizeof(address);
    sockaddr_in bound{};
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &length) != 0)
    {
        if (why)
            *why = "getsockname() failed";
        ::close(fd);
        return std::nullopt;
    }

    Socket socket;
    socket.fd_ = fd;
    socket.port_ = ntohs(bound.sin_port);
    return socket;
}

bool Socket::RawSend(uint16_t port, const Frame &frame, std::string *why)
{
    const auto bytes = EncodeFrame(frame);
    const sockaddr_in address = Loopback(port);
    const ssize_t written =
        ::sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr *>(&address), sizeof(address));
    if (written != static_cast<ssize_t>(bytes.size()))
    {
        if (why)
            *why = "sendto() failed";
        return false;
    }
    sent_++;
    return true;
}

bool Socket::FlushPending(std::string *why)
{
    if (!pending_)
        return true;
    const Pending held = std::move(*pending_);
    pending_.reset();
    released_++;
    return RawSend(held.destination, held.frame, why);
}

bool Socket::Send(uint16_t port, const Frame &frame, std::string *why)
{
    if (fd_ < 0)
    {
        if (why)
            *why = "socket is closed";
        return false;
    }
    if (frame.payload.size() > MaxPayload)
    {
        if (why)
            *why = "payload exceeds the transport maximum";
        return false;
    }

    sequence_++;
    if (link_.dropEveryNth != 0 && (sequence_ % link_.dropEveryNth) == 0)
    {
        dropped_++;
        sent_++;
        return true;  // accepted and lost: the upper layer must notice
    }

    if (link_.duplicateEveryNth != 0 && (sequence_ % link_.duplicateEveryNth) == 0)
        RawSend(port, frame, nullptr);

    if (link_.reorderEveryNth != 0 && (sequence_ % link_.reorderEveryNth) == 0)
    {
        if (pending_ && pending_->destination != port)
        {
            // A frame for another destination is held. Never swap across
            // destinations: release it to its own port first.
            if (!FlushPending(why))
                return false;
        }
        if (!pending_)
        {
            pending_ = Pending{frame, port};
            held_++;
            sent_++;
            return true;
        }
        // Same destination: send this frame now and release the held one after
        // it, so the peer sees the pair out of order.
        if (!RawSend(port, frame, why))
            return false;
        return FlushPending(why);
    }

    // Any other frame releases a held one first: the held frame was emitted
    // earlier, so it must not be overtaken indefinitely.
    if (pending_ && !FlushPending(why))
        return false;
    return RawSend(port, frame, why);
}

bool Socket::Receive(Frame &out, int timeoutMs, std::string *why, uint16_t *sourcePort)
{
    if (fd_ < 0)
    {
        if (why)
            *why = "socket is closed";
        return false;
    }

    pollfd entry{};
    entry.fd = fd_;
    entry.events = POLLIN;
    const int ready = ::poll(&entry, 1, timeoutMs);
    if (ready <= 0)
    {
        if (why && ready < 0)
            *why = "poll() failed";
        return false;
    }

    uint8_t buffer[EnvelopeSize + MaxPayload + 8];
    sockaddr_in source{};
    socklen_t sourceLength = sizeof(source);
    const ssize_t size = ::recvfrom(fd_, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr *>(&source), &sourceLength);
    if (size <= 0)
    {
        if (why)
            *why = "recvfrom() failed";
        return false;
    }
    if (!DecodeFrame(buffer, static_cast<size_t>(size), out, why))
    {
        malformed_++;
        return false;
    }
    if (sourcePort != nullptr)
        *sourcePort = ntohs(source.sin_port);
    return true;
}

} // namespace lte::uu
