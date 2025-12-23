set(IRM_SOURCE_DIR "${TOOLS_SOURCE_DIR}/irm")

set(IRM_SOURCES
  "${IRM_SOURCE_DIR}/irm.c"
  "${IRM_SOURCE_DIR}/irm_bind_program.c"
  "${IRM_SOURCE_DIR}/irm_bind_process.c"
  "${IRM_SOURCE_DIR}/irm_bind_ipcp.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_create.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_destroy.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_bootstrap.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_enroll.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_list.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_connect.c"
  "${IRM_SOURCE_DIR}/irm_ipcp_disconnect.c"
  "${IRM_SOURCE_DIR}/irm_unbind_program.c"
  "${IRM_SOURCE_DIR}/irm_unbind_process.c"
  "${IRM_SOURCE_DIR}/irm_unbind_ipcp.c"
  "${IRM_SOURCE_DIR}/irm_unbind.c"
  "${IRM_SOURCE_DIR}/irm_bind.c"
  "${IRM_SOURCE_DIR}/irm_ipcp.c"
  "${IRM_SOURCE_DIR}/irm_name.c"
  "${IRM_SOURCE_DIR}/irm_name_create.c"
  "${IRM_SOURCE_DIR}/irm_name_destroy.c"
  "${IRM_SOURCE_DIR}/irm_name_reg.c"
  "${IRM_SOURCE_DIR}/irm_name_unreg.c"
  "${IRM_SOURCE_DIR}/irm_name_list.c"
  "${IRM_SOURCE_DIR}/irm_utils.c"
)

add_executable(irm ${IRM_SOURCES})
target_include_directories(irm PRIVATE ${TOOLS_INCLUDE_DIRS})
target_link_libraries(irm PUBLIC ouroboros-irm)
install(TARGETS irm RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
