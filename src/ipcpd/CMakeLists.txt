set(IPCP_SOURCES
        # Add source files here
        ${CMAKE_CURRENT_SOURCE_DIR}/flow.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ipcp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ipcp-data.c
)

add_subdirectory(local)
add_subdirectory(normal)
add_subdirectory(shim-udp)
add_subdirectory(shim-eth-llc)
