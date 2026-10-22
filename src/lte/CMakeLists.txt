file(GLOB_RECURSE LTE_ENB_HDR_FILES enb/*.hpp)
file(GLOB_RECURSE LTE_ENB_SRC_FILES enb/*.cpp)

add_library(lte-enb-lib ${LTE_ENB_HDR_FILES} ${LTE_ENB_SRC_FILES})
target_compile_options(lte-enb-lib PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(lte-enb-lib PUBLIC common-lib)
