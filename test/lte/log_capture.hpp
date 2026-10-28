//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// RAII capture of std::cout for LTE tests.
//
// Every production LTE component logs through a file-local Log() helper that
// writes to std::cout, so a test that wants to assert on a diagnostic has to
// capture the stream rather than a dedicated logger. The buffer is thread-safe
// because the paging-wait tests drive lte::ue::Run() on a worker thread and
// have to wait for a specific production line before acting; the same helper
// keeps the single-threaded privacy and observability tests from having their
// own variant. Restore happens in the destructor, so assertions run with
// doctest output back on the real stream.
#pragma once

#include <condition_variable>
#include <iostream>
#include <mutex>
#include <streambuf>
#include <string>

namespace lte::test
{

class LogCapture
{
  public:
    LogCapture() : m_previous(std::cout.rdbuf(&m_buffer))
    {
    }
    ~LogCapture()
    {
        std::cout.rdbuf(m_previous);
    }
    LogCapture(const LogCapture &) = delete;
    LogCapture &operator=(const LogCapture &) = delete;

    std::string text() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_text;
    }

    // Blocks until the sink holds `needle`, or the timeout elapses.
    bool waitFor(const std::string &needle, int timeoutMs)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_ready.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                [&] { return m_text.find(needle) != std::string::npos; });
    }

    void append(const char *data, std::streamsize count)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_text.append(data, static_cast<size_t>(count));
        }
        m_ready.notify_all();
    }

  private:
    class Buffer final : public std::streambuf
    {
      public:
        explicit Buffer(LogCapture &owner) : m_owner(owner)
        {
        }

      protected:
        std::streamsize xsputn(const char *data, std::streamsize count) override
        {
            m_owner.append(data, count);
            return count;
        }

        int overflow(int value) override
        {
            if (value != traits_type::eof())
            {
                const char byte = static_cast<char>(value);
                m_owner.append(&byte, 1);
            }
            return value;
        }

      private:
        LogCapture &m_owner;
    };

    mutable std::mutex m_mutex;
    std::condition_variable m_ready;
    std::string m_text;
    Buffer m_buffer{*this};
    std::streambuf *m_previous;
};

} // namespace lte::test
