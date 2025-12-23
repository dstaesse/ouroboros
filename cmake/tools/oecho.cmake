add_executable(oecho "${TOOLS_SOURCE_DIR}/oecho/oecho.c")
target_include_directories(oecho PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(oecho PUBLIC ouroboros-dev)
install(TARGETS oecho RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
