include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        irm.c
        irm_create_ipcp.c
        irm_destroy_ipcp.c
        irm_bootstrap_ipcp.c
        irm_enroll_ipcp.c
        irm_register.c
        irm_unregister.c
        irm_utils.c
)

add_executable (irm ${SOURCE_FILES})

target_link_libraries (irm LINK_PUBLIC ouroboros)

install(TARGETS irm RUNTIME DESTINATION bin)
