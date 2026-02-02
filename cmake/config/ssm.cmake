# Secure Shared Memory (SSM) pool configuration for Ouroboros
# This file defines the allocation parameters for the secure shared memory
# pool allocator

# Shared memory pool naming configuration
set(SSM_PREFIX "ouroboros" CACHE STRING
    "Prefix for secure shared memory pools")

# Pool naming (internal)
set(SSM_GSPP_NAME "/${SSM_PREFIX}.gspp" CACHE INTERNAL
    "Name for the Global Shared Packet Pool")
set(SSM_PUP_NAME_FMT "/${SSM_PREFIX}.pup.%d" CACHE INTERNAL
    "Format string for Per-User Pool names (uid as argument)")

# Packet buffer configuration
set(SSM_POOL_NAME "/${SHM_PREFIX}.pool" CACHE INTERNAL
    "Name for the main POSIX shared memory pool")
set(SSM_POOL_BLOCKS 16384 CACHE STRING
    "Number of blocks in SSM packet pool, must be a power of 2")
set(SSM_PK_BUFF_HEADSPACE 256 CACHE STRING
    "Bytes of headspace to reserve for future headers")
set(SSM_PK_BUFF_TAILSPACE 32 CACHE STRING
    "Bytes of tailspace to reserve for future tails")
set(SSM_RBUFF_SIZE 1024 CACHE STRING
    "Number of blocks in rbuff buffer, must be a power of 2")
set(SSM_RBUFF_PREFIX "/${SHM_PREFIX}.rbuff." CACHE INTERNAL
    "Prefix for rbuff POSIX shared memory filenames")
set(SSM_FLOW_SET_PREFIX "/${SHM_PREFIX}.set." CACHE INTERNAL
    "Prefix for the POSIX shared memory flow set")

# Number of shards per size class for reducing contention
set(SSM_POOL_SHARDS 4 CACHE STRING
    "Number of allocator shards per size class")

# Global Shared Packet Pool (GSPP) - for privileged processes
# Shared by all processes in 'ouroboros' group (~60 MB total)
set(SSM_GSPP_256_BLOCKS 1024 CACHE STRING
    "GSPP: Number of 256B blocks")
set(SSM_GSPP_512_BLOCKS 768 CACHE STRING
    "GSPP: Number of 512B blocks")
set(SSM_GSPP_1K_BLOCKS 512 CACHE STRING
    "GSPP: Number of 1KB blocks")
set(SSM_GSPP_2K_BLOCKS 384 CACHE STRING
    "GSPP: Number of 2KB blocks")
set(SSM_GSPP_4K_BLOCKS 256 CACHE STRING
    "GSPP: Number of 4KB blocks")
set(SSM_GSPP_16K_BLOCKS 128 CACHE STRING
    "GSPP: Number of 16KB blocks")
set(SSM_GSPP_64K_BLOCKS 64 CACHE STRING
    "GSPP: Number of 64KB blocks")
set(SSM_GSPP_256K_BLOCKS 32 CACHE STRING
    "GSPP: Number of 256KB blocks")
set(SSM_GSPP_1M_BLOCKS 16 CACHE STRING
    "GSPP: Number of 1MB blocks")

# Per-User Pool (PUP) - for unprivileged applications
# Each unprivileged app gets its own smaller pool (~7.5 MB total)
set(SSM_PUP_256_BLOCKS 128 CACHE STRING
    "PUP: Number of 256B blocks")
set(SSM_PUP_512_BLOCKS 96 CACHE STRING
    "PUP: Number of 512B blocks")
set(SSM_PUP_1K_BLOCKS 64 CACHE STRING
    "PUP: Number of 1KB blocks")
set(SSM_PUP_2K_BLOCKS 48 CACHE STRING
    "PUP: Number of 2KB blocks")
set(SSM_PUP_4K_BLOCKS 32 CACHE STRING
    "PUP: Number of 4KB blocks")
set(SSM_PUP_16K_BLOCKS 16 CACHE STRING
    "PUP: Number of 16KB blocks")
set(SSM_PUP_64K_BLOCKS 8 CACHE STRING
    "PUP: Number of 64KB blocks")
set(SSM_PUP_256K_BLOCKS 2 CACHE STRING
    "PUP: Number of 256KB blocks")
set(SSM_PUP_1M_BLOCKS 0 CACHE STRING
    "PUP: Number of 1MB blocks")

# SSM pool size calculations
include(utils/HumanReadable)

math(EXPR SSM_GSPP_TOTAL_SIZE
    "(1 << 8) * ${SSM_GSPP_256_BLOCKS} + \
     (1 << 9) * ${SSM_GSPP_512_BLOCKS} + \
     (1 << 10) * ${SSM_GSPP_1K_BLOCKS} + \
     (1 << 11) * ${SSM_GSPP_2K_BLOCKS} + \
     (1 << 12) * ${SSM_GSPP_4K_BLOCKS} + \
     (1 << 14) * ${SSM_GSPP_16K_BLOCKS} + \
     (1 << 16) * ${SSM_GSPP_64K_BLOCKS} + \
     (1 << 18) * ${SSM_GSPP_256K_BLOCKS} + \
     (1 << 20) * ${SSM_GSPP_1M_BLOCKS}")

set(SSM_GSPP_TOTAL_SIZE ${SSM_GSPP_TOTAL_SIZE} CACHE INTERNAL
    "GSPP total size in bytes")

math(EXPR SSM_PUP_TOTAL_SIZE
    "(1 << 8) * ${SSM_PUP_256_BLOCKS} + \
     (1 << 9) * ${SSM_PUP_512_BLOCKS} + \
     (1 << 10) * ${SSM_PUP_1K_BLOCKS} + \
     (1 << 11) * ${SSM_PUP_2K_BLOCKS} + \
     (1 << 12) * ${SSM_PUP_4K_BLOCKS} + \
     (1 << 14) * ${SSM_PUP_16K_BLOCKS} + \
     (1 << 16) * ${SSM_PUP_64K_BLOCKS} + \
     (1 << 18) * ${SSM_PUP_256K_BLOCKS} + \
     (1 << 20) * ${SSM_PUP_1M_BLOCKS}")

set(SSM_PUP_TOTAL_SIZE ${SSM_PUP_TOTAL_SIZE} CACHE INTERNAL
    "PUP total size in bytes")

set(SSM_POOL_TOTAL_SIZE ${SSM_GSPP_TOTAL_SIZE} CACHE INTERNAL
    "Total shared memory pool size in bytes")

format_bytes_human_readable(${SSM_GSPP_TOTAL_SIZE} SSM_GSPP_SIZE_DISPLAY)
format_bytes_human_readable(${SSM_PUP_TOTAL_SIZE} SSM_PUP_SIZE_DISPLAY)

message(STATUS "Secure Shared Memory Pool Configuration:")
message(STATUS "  Pool prefix: ${SSM_PREFIX}")
message(STATUS "  Size classes: "
    "256B, 512B, 1KiB, 2KiB, 4KiB, 16KiB, 64KiB, 256KiB, 1MiB")
message(STATUS "  Max allocation: 1 MB")
message(STATUS "  Shards per class: ${SSM_POOL_SHARDS}")
message(STATUS "  GSPP (privileged): ${SSM_GSPP_SIZE_DISPLAY} "
    "(${SSM_GSPP_TOTAL_SIZE} bytes)")
message(STATUS "    Blocks: ${SSM_GSPP_256_BLOCKS}, ${SSM_GSPP_512_BLOCKS}, "
    "${SSM_GSPP_1K_BLOCKS}, ${SSM_GSPP_2K_BLOCKS}, ${SSM_GSPP_4K_BLOCKS}, "
    "${SSM_GSPP_16K_BLOCKS}, ${SSM_GSPP_64K_BLOCKS}, ${SSM_GSPP_256K_BLOCKS}, "
    "${SSM_GSPP_1M_BLOCKS}")
message(STATUS "  PUP (unprivileged): ${SSM_PUP_SIZE_DISPLAY} "
    "(${SSM_PUP_TOTAL_SIZE} bytes)")
message(STATUS "    Blocks: ${SSM_PUP_256_BLOCKS}, ${SSM_PUP_512_BLOCKS}, "
    "${SSM_PUP_1K_BLOCKS}, ${SSM_PUP_2K_BLOCKS}, ${SSM_PUP_4K_BLOCKS}, "
    "${SSM_PUP_16K_BLOCKS}, ${SSM_PUP_64K_BLOCKS}, ${SSM_PUP_256K_BLOCKS}, "
    "${SSM_PUP_1M_BLOCKS}")
