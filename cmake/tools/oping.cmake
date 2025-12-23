add_executable(oping "${TOOLS_SOURCE_DIR}/oping/oping.c")
target_include_directories(oping PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(oping PUBLIC ${LIBM_LIBRARIES} ouroboros-dev)
install(TARGETS oping RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
