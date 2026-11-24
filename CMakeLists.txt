cmake_minimum_required(VERSION 3.17)
project(ueransim)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

include_directories(src)

#################### BUILD OPTIONS ####################

# Builds every target with the given sanitizers, e.g. -DUERANSIM_SANITIZE=address,undefined. UBSan findings abort
# instead of only being printed, so that they fail the test that triggered them.
set(UERANSIM_SANITIZE "" CACHE STRING "Comma separated sanitizers to build with, e.g. address,undefined")
if (UERANSIM_SANITIZE)
    add_compile_options(-fsanitize=${UERANSIM_SANITIZE} -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${UERANSIM_SANITIZE})
    # Bounds checks in the standard containers as well: ASan cannot see an index past the size of a vector as long as
    # it is still within its capacity.
    add_compile_definitions(_GLIBCXX_ASSERTIONS)
endif ()

# Instruments the first-party libraries for gcov; meant for a Debug build. Applied once the targets exist, below.
option(UERANSIM_COVERAGE "Instrument the first-party code for coverage reports" OFF)

#################### SUB DIRECTORIES ####################

add_subdirectory(src/ext)
add_subdirectory(src/utils)
add_subdirectory(src/asn/asn1c)
add_subdirectory(src/asn/rrc)
add_subdirectory(src/asn/ngap)
add_subdirectory(src/asn/lte-rrc)
add_subdirectory(src/lib)
add_subdirectory(src/gnb)
add_subdirectory(src/ue)
add_subdirectory(src/lte)

#################### GNB EXECUTABLE ####################

add_executable(nr-gnb src/gnb.cpp)

target_link_libraries(nr-gnb pthread)

target_compile_options(nr-gnb PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-gnb asn-rrc)
target_link_libraries(nr-gnb asn-ngap)
target_link_libraries(nr-gnb common-lib)
target_link_libraries(nr-gnb gnb)

#################### UE EXECUTABLE ####################

add_executable(nr-ue src/ue.cpp)
target_link_libraries(nr-ue pthread)
target_compile_options(nr-ue PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-ue common-lib)
target_link_libraries(nr-ue ue)

###################### IF BINDER ######################
add_library(devbnd SHARED src/binder.cpp)
target_compile_options(devbnd PRIVATE -D_GNU_SOURCE -Wall -Wextra)
target_link_options(devbnd PRIVATE -nostartfiles)
target_link_libraries(devbnd dl)
if (UERANSIM_SANITIZE)
    # devbnd is LD_PRELOADed into arbitrary programs, which cannot pull in a sanitizer runtime that way.
    target_compile_options(devbnd PRIVATE -fno-sanitize=all)
    target_link_options(devbnd PRIVATE -fno-sanitize=all)
endif ()

#################### CLI EXECUTABLE ####################
add_executable(nr-cli src/cli.cpp)
target_link_libraries(nr-cli pthread)
target_compile_options(nr-cli PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-cli common-lib)

#################### LTE ENB EXECUTABLE ####################
add_executable(lte-enb src/lte_enb.cpp)
target_compile_options(lte-enb PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(lte-enb pthread lte-enb-lib)

#################### LTE UE EXECUTABLE ####################
add_executable(lte-ue src/lte_ue.cpp)
target_compile_options(lte-ue PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(lte-ue pthread lte-ue-lib)

#################### TEST EXECUTABLE ####################
# Built by default so the tests cannot rot, but it is not part of what `make build` installs.
option(BUILD_TESTS "Build the nr-tests executable" ON)

if (BUILD_TESTS)
    # CONFIGURE_DEPENDS so that adding a test file re-runs cmake instead of silently skipping it.
    file(GLOB_RECURSE TEST_SRC_FILES CONFIGURE_DEPENDS test/*.cpp)
    add_executable(nr-tests ${TEST_SRC_FILES})
    target_include_directories(nr-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    # Fixture files (shipped example configurations) are addressed through this
    # absolute path: ctest runs the binary from the build directory, so a path
    # relative to the source tree would not resolve.
    target_compile_definitions(nr-tests PRIVATE UNIRANSIM_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(nr-tests pthread)
    target_compile_options(nr-tests PRIVATE -Wall -Wextra -pedantic)
    target_link_libraries(nr-tests common-lib)
    target_link_libraries(nr-tests ue)
    target_link_libraries(nr-tests ext)
    target_link_libraries(nr-tests lte-enb-lib)
    target_link_libraries(nr-tests lte-rrc)
    target_include_directories(nr-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/lte-rrc
                                                ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/asn1c)
    target_link_libraries(nr-tests lte-ue-lib)

    # The deterministic EPC peer for the two-process Attach acceptance. It is a
    # test artifact, never installed, and it links the production eNB bridge and
    # NAS code rather than reimplementing them.
    add_executable(lte-uu-attach-peer tools/lte-uu-attach-peer.cpp)
    target_compile_options(lte-uu-attach-peer PRIVATE -Wall -Wextra -pedantic)
    target_include_directories(lte-uu-attach-peer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/lte-rrc
                                                        ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/asn1c)
    target_link_libraries(lte-uu-attach-peer pthread common-lib ext lte-enb-lib lte-rrc lte-ue-lib)
    add_dependencies(nr-tests lte-uu-attach-peer)

    # Phase 18-F-B6-D7: the deterministic SGW-U/PGW-U user-plane endpoint. It
    # terminates the real GTP-U tunnel and owns a real Core-side Linux TUN.
    add_executable(lte-uu-sgw-peer tools/lte-uu-sgw-peer.cpp)
    target_compile_options(lte-uu-sgw-peer PRIVATE -Wall -Wextra -pedantic)
    target_include_directories(lte-uu-sgw-peer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/lte-rrc
                                                      ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/asn1c)
    target_link_libraries(lte-uu-sgw-peer pthread common-lib utils ext lte-enb-lib lte-ue-lib
                          lte-user-plane-common)
    add_dependencies(nr-tests lte-uu-sgw-peer)

    # Phase 18-F-B6-D7: the production eNB + deterministic MME user-plane peer.
    add_executable(lte-uu-user-plane-peer tools/lte-uu-user-plane-peer.cpp)
    target_compile_options(lte-uu-user-plane-peer PRIVATE -Wall -Wextra -pedantic)
    target_include_directories(lte-uu-user-plane-peer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/lte-rrc
                                                             ${CMAKE_CURRENT_SOURCE_DIR}/src/asn/asn1c)
    target_link_libraries(lte-uu-user-plane-peer pthread common-lib utils ext lte-enb-lib lte-rrc lte-ue-lib)
    add_dependencies(nr-tests lte-uu-user-plane-peer)

    # Phase 18-F-B6-D7: real UDP/TCP traffic probe used inside the acceptance
    # network namespaces. It is a test tool, not part of the production stack.
    add_executable(lte-uu-traffic-probe tools/lte-uu-traffic-probe.cpp)
    target_compile_options(lte-uu-traffic-probe PRIVATE -Wall -Wextra -pedantic)
    target_link_libraries(lte-uu-traffic-probe pthread utils)
    add_dependencies(nr-tests lte-uu-traffic-probe)

    enable_testing()
    # Registers each doctest test case as its own ctest test, as listed by the built binary, so a failure or a crash
    # is reported against the test case that caused it instead of the whole suite. A test that hangs fails after a
    # minute rather than holding the run up for ctest's default of 25.
    include(src/ext/doctest/doctest.cmake)
    doctest_discover_tests(nr-tests PROPERTIES TIMEOUT 60)
endif ()

#################### OFFLINE EXPERIMENTS ####################
# Measurement tools that must never run inside the CI matrix. They are off by
# default so a normal build and every CI job stay exactly as they were; a
# measurement run configures with -DBUILD_EXPERIMENTS=ON.
option(BUILD_EXPERIMENTS "Build the offline measurement tools in tools/" OFF)

if (BUILD_EXPERIMENTS)
    add_executable(lte-downlink-experiment tools/lte-downlink-receive-experiment.cpp)
    target_compile_options(lte-downlink-experiment PRIVATE -Wall -Wextra -pedantic)
    target_link_libraries(lte-downlink-experiment pthread common-lib lte-ue-lib)

    add_executable(lte-socket-buffer-experiment tools/lte-socket-buffer-experiment.cpp)
    target_compile_options(lte-socket-buffer-experiment PRIVATE -Wall -Wextra -pedantic)
    target_link_libraries(lte-socket-buffer-experiment pthread common-lib lte-enb-lib)
endif ()

#################### COVERAGE ####################
# Only the first-party libraries are instrumented. The generated ASN.1 code and the vendored libraries would dominate
# the report and slow the build down, and they are not what the tests are written for.
if (UERANSIM_COVERAGE)
    foreach (target utils common-lib gnb ue lte-user-plane-common lte-tft lte-radio-link lte-security lte-rrc-runtime lte-enb-lib lte-ue-lib)
        target_compile_options(${target} PRIVATE --coverage)
        target_link_options(${target} INTERFACE --coverage)
    endforeach ()
endif ()
