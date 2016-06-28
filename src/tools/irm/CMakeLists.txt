include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        irm.c
        irm_ipcp_create.c
        irm_ipcp_destroy.c
        irm_ipcp_bootstrap.c
        irm_ipcp_enroll.c
        irm_unbind.c
        irm_bind.c
        irm_ipcp.c
        irm_register.c
        irm_unregister.c
        irm_utils.c
)

add_executable (irm ${SOURCE_FILES})

target_link_libraries (irm LINK_PUBLIC ouroboros)

install(TARGETS irm RUNTIME DESTINATION sbin)
