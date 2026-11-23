//
// This file is a part of UERANSIM project.
// Copyright (c) 2027 ALİ GÜNGÖR.
//

// Phase 18-F-B6-D: the explicit simulated Uu endpoint configuration.
//
// The endpoint is opt-in and must be distinct from every other local UDP
// endpoint the same process binds. These tests load the shipped sample
// configuration with and without a 'uu' block, so the parser is exercised
// through the real loader rather than a hand-built struct.
#include <ext/doctest/doctest.h>

#include <lte/enb/config.hpp>
#include <lte/enb/types.hpp>
#include <lte/ue/config.hpp>
#include <lte/ue/types.hpp>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

namespace
{

const char *EnbSample = "open5gs-lte-enb.yaml";
const char *UeSample = "open5gs-lte-ue.yaml";

// ctest runs the binary from the build directory, so the shipped fixtures are
// addressed through the absolute source path the build defines.
std::string Sample(const char *name)
{
    return std::string(UNIRANSIM_SOURCE_DIR) + "/config/" + name;
}

std::string Read(const std::string &path)
{
    std::ifstream in(path);
    REQUIRE(in.good());
    std::ostringstream text;
    text << in.rdbuf();
    return text.str();
}

std::string WithUu(const std::string &path, const std::string &block)
{
    std::string body = Read(path);
    if (!body.empty() && body.back() != '\n')
        body += "\n";
    body += block;
    return body;
}

std::string WriteTemp(const std::string &name, const std::string &body)
{
    const std::string path = "/tmp/" + name;
    std::ofstream out(path);
    REQUIRE(out.good());
    out << body;
    out.close();
    return path;
}

} // namespace

TEST_CASE("lte/uu-config/the enb uu endpoint is optional and loads when present")
{
    const auto plain = lte::enb::LoadConfig(Sample(EnbSample));
    CHECK(plain.uuAddress.empty());
    CHECK(plain.uuPort == 0);

    const std::string path = WriteTemp("b6d-enb-uu.yaml",
                                       WithUu(Sample(EnbSample), "uu:\n  address: 127.0.0.9\n  port: 21500\n"));
    const auto loaded = lte::enb::LoadConfig(path);
    CHECK(loaded.uuAddress == "127.0.0.9");
    CHECK(loaded.uuPort == 21500);
    // The legacy endpoint is untouched.
    CHECK(loaded.ueLinkAddress == plain.ueLinkAddress);
    CHECK(loaded.ueLinkPort == plain.ueLinkPort);
}

TEST_CASE("lte/uu-config/an enb uu endpoint may not reuse another local endpoint")
{
    const auto plain = lte::enb::LoadConfig(Sample(EnbSample));
    const std::string duplicate = "uu:\n  address: " + plain.ueLinkAddress + "\n  port: " +
                                  std::to_string(plain.ueLinkPort) + "\n";
    const std::string path = WriteTemp("b6d-enb-uu-duplicate.yaml", WithUu(Sample(EnbSample), duplicate));
    CHECK_THROWS_AS(lte::enb::LoadConfig(path), std::runtime_error);

    const std::string zero = WithUu(Sample(EnbSample), "uu:\n  address: 127.0.0.9\n  port: 0\n");
    CHECK_THROWS_AS(lte::enb::LoadConfig(WriteTemp("b6d-enb-uu-zero.yaml", zero)), std::exception);
}

TEST_CASE("lte/uu-config/the ue uu endpoint is optional and loads when present")
{
    const auto plain = lte::ue::LoadConfig(Sample(UeSample));
    CHECK_FALSE(plain.uu.enabled);

    const std::string path = WriteTemp("b6d-ue-uu.yaml", WithUu(Sample(UeSample),
        "uu:\n  localAddress: 127.0.0.2\n  localPort: 21600\n  address: 127.0.0.1\n  port: 21500\n"));
    const auto loaded = lte::ue::LoadConfig(path);
    REQUIRE(loaded.uu.enabled);
    CHECK(loaded.uu.localAddress == "127.0.0.2");
    CHECK(loaded.uu.localPort == 21600);
    CHECK(loaded.uu.enbAddress == "127.0.0.1");
    CHECK(loaded.uu.enbPort == 21500);
    // The legacy radio link keeps its own endpoint.
    CHECK(loaded.link.localPort == plain.link.localPort);
}

TEST_CASE("lte/uu-config/a ue uu endpoint may not collide with its own legacy endpoint")
{
    const auto plain = lte::ue::LoadConfig(Sample(UeSample));
    const std::string duplicate = "uu:\n  localAddress: " + plain.link.localAddress + "\n  localPort: " +
                                  std::to_string(plain.link.localPort) +
                                  "\n  address: 127.0.0.1\n  port: 21500\n";
    const std::string path = WriteTemp("b6d-ue-uu-duplicate.yaml", WithUu(Sample(UeSample), duplicate));
    CHECK_THROWS_AS(lte::ue::LoadConfig(path), std::runtime_error);

    const std::string selfish = "uu:\n  localAddress: 127.0.0.2\n  localPort: 21600\n"
                                "  address: 127.0.0.2\n  port: 21600\n";
    CHECK_THROWS_AS(lte::ue::LoadConfig(WriteTemp("b6d-ue-uu-self.yaml", WithUu(Sample(UeSample), selfish))),
                    std::runtime_error);
}
