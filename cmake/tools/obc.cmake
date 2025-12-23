add_executable(obc "${TOOLS_SOURCE_DIR}/obc/obc.c")
target_include_directories(obc PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(obc PUBLIC ouroboros-dev)
install(TARGETS obc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
