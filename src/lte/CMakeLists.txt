file(GLOB_RECURSE LTE_ENB_HDR_FILES enb/*.hpp)
file(GLOB_RECURSE LTE_ENB_SRC_FILES enb/*.cpp)
file(GLOB_RECURSE LTE_UE_HDR_FILES ue/*.hpp)
file(GLOB_RECURSE LTE_UE_SRC_FILES ue/*.cpp)
list(REMOVE_ITEM LTE_UE_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/ue/radio_link.cpp)

add_library(lte-user-plane-common ip_packet.cpp ip_packet.hpp)
target_compile_options(lte-user-plane-common PRIVATE -Wall -Wextra -pedantic)

add_library(lte-radio-link ue/radio_link.cpp ue/radio_link.hpp)
target_compile_options(lte-radio-link PRIVATE -Wall -Wextra -pedantic)

add_library(lte-enb-lib ${LTE_ENB_HDR_FILES} ${LTE_ENB_SRC_FILES})
target_compile_options(lte-enb-lib PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(lte-enb-lib PUBLIC common-lib lte-radio-link lte-user-plane-common)

add_library(lte-ue-lib ${LTE_UE_HDR_FILES} ${LTE_UE_SRC_FILES})
target_compile_options(lte-ue-lib PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(lte-ue-lib PUBLIC common-lib lte-enb-lib lte-radio-link ue)
