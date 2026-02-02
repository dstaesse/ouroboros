# Global configuration options for Ouroboros
# These options affect the entire framework

# Installation directories
set(OUROBOROS_CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/ouroboros" CACHE PATH
  "Configuration directory")

# Security directories
set(OUROBOROS_SECURITY_DIR "${OUROBOROS_CONFIG_DIR}/security" CACHE PATH
  "Security directory holding authentication information")
set(OUROBOROS_CA_CRT_DIR "${OUROBOROS_SECURITY_DIR}/cacert" CACHE PATH
  "Directory holding trusted CA certificates")
set(OUROBOROS_SRV_CRT_DIR "${OUROBOROS_SECURITY_DIR}/server" CACHE PATH
  "Directory holding server certificates")
set(OUROBOROS_CLI_CRT_DIR "${OUROBOROS_SECURITY_DIR}/client" CACHE PATH
  "Directory holding client certificates")
set(OUROBOROS_UNTRUSTED_DIR "${OUROBOROS_SECURITY_DIR}/untrusted" CACHE PATH
  "Directory holding untrusted intermediate certificates")

# Shared memory naming
set(SHM_PREFIX "ouroboros" CACHE STRING
  "String to prepend to POSIX shared memory filenames")
set(SHM_LOCKFILE_NAME "/${SHM_PREFIX}.lockfile" CACHE INTERNAL
  "Filename for the POSIX shared memory lockfile")

# FUSE configuration
if(HAVE_FUSE)
  set(FUSE_PREFIX "/tmp/ouroboros" CACHE STRING
    "Mountpoint for RIB filesystem")
endif()

# Secure memory configuration
set(IRMD_SECMEM_MAX 1048576 CACHE STRING "IRMd secure heap size")
set(PROC_SECMEM_MAX 1048576 CACHE STRING "Process secure heap size")
set(SECMEM_GUARD 32 CACHE STRING "Secure heap min size")

# Container/deployment options
set(BUILD_CONTAINER FALSE CACHE BOOL
  "Disable thread priority setting for container compatibility")
set(DISABLE_CORE_LOCK TRUE CACHE BOOL
  "Disable locking performance threads to a core")

# IPC socket configuration
set(SOCK_BUF_SIZE 10240 CACHE STRING
  "Size of the buffer used by the UNIX sockets for local IPC")
