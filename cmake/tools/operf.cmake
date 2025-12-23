add_executable(operf "${TOOLS_SOURCE_DIR}/operf/operf.c")
target_include_directories(operf PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(operf PUBLIC ouroboros-dev)
install(TARGETS operf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
