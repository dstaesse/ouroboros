add_executable(ocbr "${TOOLS_SOURCE_DIR}/ocbr/ocbr.c")
target_include_directories(ocbr PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(ocbr PUBLIC ouroboros-dev)
install(TARGETS ocbr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
