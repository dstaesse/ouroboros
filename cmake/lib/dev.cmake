set(SOURCE_FILES_DEV
  cep.c
  dev.c
)

# Convert relative paths to absolute
set(SOURCE_FILES_DEV_ABS)
foreach(src ${SOURCE_FILES_DEV})
  list(APPEND SOURCE_FILES_DEV_ABS "${LIB_SOURCE_DIR}/${src}")
endforeach()

add_library(ouroboros-dev SHARED
  ${SOURCE_FILES_DEV_ABS}
  ${CEP_PROTO_SRCS})

set_target_properties(ouroboros-dev PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ouroboros-dev -DCONFIG_OUROBOROS_DEBUG)
endif ()

target_include_directories(ouroboros-dev PUBLIC
  ${LIB_SOURCE_DIR}
  ${LIB_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_BINARY_DIR}
  ${PROTOBUF_C_INCLUDE_DIRS}
  ${SYS_RND_HDR}
  ${LIBGCRYPT_INCLUDE_DIR}
  ${OPENSSL_INCLUDE_DIR})

target_link_libraries(ouroboros-dev ouroboros-common)

install(TARGETS ouroboros-dev LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
