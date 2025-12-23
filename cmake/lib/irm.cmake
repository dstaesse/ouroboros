set(SOURCE_FILES_IRM
  irm.c
)

# Convert relative paths to absolute
set(SOURCE_FILES_IRM_ABS)
foreach(src ${SOURCE_FILES_IRM})
  list(APPEND SOURCE_FILES_IRM_ABS "${LIB_SOURCE_DIR}/${src}")
endforeach()

add_library(ouroboros-irm SHARED ${SOURCE_FILES_IRM_ABS})

set_target_properties(ouroboros-irm PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ouroboros-irm -DCONFIG_OUROBOROS_DEBUG)
endif ()

target_include_directories(ouroboros-irm PUBLIC
  ${LIB_SOURCE_DIR}
  ${LIB_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_BINARY_DIR}
  ${PROTOBUF_C_INCLUDE_DIRS}
  ${SYS_RND_HDR}
  ${LIBGCRYPT_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})

target_link_libraries(ouroboros-irm ouroboros-common)

install(TARGETS ouroboros-irm LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
