//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

// Opt-in, one-shot S1 failure injection for the test-owned eNB.
//
// The mechanism does not exist at all unless a control file is configured, so
// an ordinary deployment has no injection code path. It never touches the live
// EPC, never uses a firewall and never kills a process: it only invalidates the
// simulator's own SCTP association.
//
// It is declared in its own header so the command parsing and its one-shot
// consumption can be exercised directly when verifying that an injected loss
// and an unexpected transport failure are counted as separate events.
#pragma once

#include "types.hpp"

#include <chrono>
#include <fstream>
#include <string>

namespace lte::enb
{

class FailureInjector
{
  public:
    enum class Command
    {
        NONE,
        // Tear the association down immediately.
        LOSS,
        // Drop the next S1AP PDU the eNB would have sent and tear the
        // association down instead. Deterministically produces an in-flight
        // interruption, e.g. during Initial Context Setup.
        LOSS_BEFORE_S1AP_RESPONSE,
        // The control file named a command this simulator does not implement.
        UNKNOWN
    };

    explicit FailureInjector(const FailureInjectionConfig &config) : m_config(config)
    {
    }

    // False when no control file is configured, which removes the mechanism
    // entirely rather than leaving it inert-but-reachable.
    [[nodiscard]] bool enabled() const
    {
        return !m_config.controlFile.empty();
    }

    // Raw text of the most recent non-empty command line, retained only so the
    // caller can report an unknown command to the operator. It is never used
    // to decide anything.
    [[nodiscard]] const std::string &lastCommand() const
    {
        return m_lastCommand;
    }

    // Reads at most one command and consumes it, so a command cannot fire
    // twice. An empty, absent or unknown command consumes nothing observable
    // and yields NONE or UNKNOWN.
    Command poll()
    {
        if (m_config.controlFile.empty())
            return Command::NONE;
        const auto now = std::chrono::steady_clock::now();
        if (now < m_nextPoll)
            return Command::NONE;
        m_nextPoll = now + std::chrono::milliseconds(m_config.pollIntervalMs);

        std::ifstream input(m_config.controlFile);
        if (!input.is_open())
            return Command::NONE;
        std::string line;
        std::getline(input, line);
        input.close();
        // One-shot: the command is consumed so it cannot fire twice.
        std::ofstream(m_config.controlFile, std::ios::trunc).close();

        const std::string command = Trim(line);
        if (command.empty())
            return Command::NONE;
        m_lastCommand = command;
        if (command == "loss")
            return Command::LOSS;
        if (command == "loss-before-s1ap-response")
            return Command::LOSS_BEFORE_S1AP_RESPONSE;
        return Command::UNKNOWN;
    }

  private:
    static std::string Trim(const std::string &text)
    {
        const auto first = text.find_first_not_of(" \t\r\n");
        if (first == std::string::npos)
            return {};
        const auto last = text.find_last_not_of(" \t\r\n");
        return text.substr(first, last - first + 1U);
    }

    FailureInjectionConfig m_config;
    std::chrono::steady_clock::time_point m_nextPoll{};
    std::string m_lastCommand;
};

} // namespace lte::enb
