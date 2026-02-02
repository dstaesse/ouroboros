# Tools build configuration

set(TOOLS_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
)

set(IRM_SOURCES
  irm/irm.c
  irm/irm_bind_program.c
  irm/irm_bind_process.c
  irm/irm_bind_ipcp.c
  irm/irm_ipcp_create.c
  irm/irm_ipcp_destroy.c
  irm/irm_ipcp_bootstrap.c
  irm/irm_ipcp_enroll.c
  irm/irm_ipcp_list.c
  irm/irm_ipcp_connect.c
  irm/irm_ipcp_disconnect.c
  irm/irm_unbind_program.c
  irm/irm_unbind_process.c
  irm/irm_unbind_ipcp.c
  irm/irm_unbind.c
  irm/irm_bind.c
  irm/irm_ipcp.c
  irm/irm_name.c
  irm/irm_name_create.c
  irm/irm_name_destroy.c
  irm/irm_name_reg.c
  irm/irm_name_unreg.c
  irm/irm_name_list.c
  irm/irm_utils.c
)

add_executable(irm ${IRM_SOURCES})
target_include_directories(irm PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(irm PRIVATE ouroboros-irm)
install(TARGETS irm RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

add_executable(oping oping/oping.c)
target_include_directories(oping PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(oping PRIVATE ${LIBM_LIBRARIES} ouroboros-dev)
install(TARGETS oping RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(oecho oecho/oecho.c)
target_include_directories(oecho PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(oecho PRIVATE ouroboros-dev)
install(TARGETS oecho RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(ocbr ocbr/ocbr.c)
target_include_directories(ocbr PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(ocbr PRIVATE ouroboros-dev)
install(TARGETS ocbr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(obc obc/obc.c)
target_include_directories(obc PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(obc PRIVATE ouroboros-dev)
install(TARGETS obc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(operf operf/operf.c)
target_include_directories(operf PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(operf PRIVATE ouroboros-dev)
install(TARGETS operf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(ovpn ovpn/ovpn.c)
  target_include_directories(ovpn PRIVATE ${TOOLS_INCLUDE_DIRS})
  target_link_libraries(ovpn PRIVATE ouroboros-dev)
  install(TARGETS ovpn RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
