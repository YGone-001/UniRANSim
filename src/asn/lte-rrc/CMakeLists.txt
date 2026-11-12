file(GLOB HDR_FILES *.h)
file(GLOB SRC_FILES *.c)

# Generated from tools/lte-rrc-15.6.0.asn1 with asn1c. The generation command is
# recorded in docs/lte-rrc-handover-codec.md; the sources here are its output and
# are not edited by hand.
add_library(asn-lte-rrc ${HDR_FILES} ${SRC_FILES})
target_link_libraries(asn-lte-rrc asn-asn1c)
