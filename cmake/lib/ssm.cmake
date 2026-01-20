# Pool size configuration for Ouroboros secure shared memory
# This file defines the allocation parameters for the
# secure shared memory pool allocator

# Shared memory pool naming configuration
set(SSM_PREFIX "o7s.ssm" CACHE STRING
    "Prefix for secure shared memory pools")
set(SSM_GSMP_SUFFIX ".gsmp" CACHE STRING
    "Suffix for Group Shared Memory Pool")
set(SSM_PPP_SUFFIX ".ppp" CACHE STRING
    "Suffix for Process Private Pool")

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

# Pool blocks per size class
# This determines how many blocks of each size are preallocated in the pool
# Higher values reduce allocation failures but increase memory usage
set(SSM_POOL_256_BLOCKS 1024 CACHE STRING
    "Number of 256B blocks in pool")
set(SSM_POOL_512_BLOCKS 768 CACHE STRING
    "Number of 512B blocks in pool")
set(SSM_POOL_1K_BLOCKS 512 CACHE STRING
    "Number of 1KB blocks in pool")
set(SSM_POOL_2K_BLOCKS 384 CACHE STRING
    "Number of 2KB blocks in pool")
set(SSM_POOL_4K_BLOCKS 256 CACHE STRING
    "Number of 4KB blocks in pool")
set(SSM_POOL_16K_BLOCKS 128 CACHE STRING
    "Number of 16KB blocks in pool")
set(SSM_POOL_64K_BLOCKS 64 CACHE STRING
    "Number of 64KB blocks in pool")
set(SSM_POOL_256K_BLOCKS 32 CACHE STRING
    "Number of 256KB blocks in pool")
set(SSM_POOL_1M_BLOCKS 16 CACHE STRING
    "Number of 1MB blocks in pool")

# Number of shards per size class for reducing contention
set(SSM_POOL_SHARDS 4 CACHE STRING
    "Number of allocator shards per size class")

# SSM packet buffer overhead - computed at compile time via sizeof()
# Defined in config.h.in as sizeof(_ssm_memory_block) + sizeof(_ssm_pk_buff)
# This makes it portable across platforms with different pid_t sizes and padding

# Total shared memory pool size calculation
math(EXPR SSM_POOL_TOTAL_SIZE
    "(1 << 8) * ${SSM_POOL_256_BLOCKS} + \
     (1 << 9) * ${SSM_POOL_512_BLOCKS} + \
     (1 << 10) * ${SSM_POOL_1K_BLOCKS} + \
     (1 << 11) * ${SSM_POOL_2K_BLOCKS} + \
     (1 << 12) * ${SSM_POOL_4K_BLOCKS} + \
     (1 << 14) * ${SSM_POOL_16K_BLOCKS} + \
     (1 << 16) * ${SSM_POOL_64K_BLOCKS} + \
     (1 << 18) * ${SSM_POOL_256K_BLOCKS} + \
     (1 << 20) * ${SSM_POOL_1M_BLOCKS}")

set(SSM_POOL_TOTAL_SIZE ${SSM_POOL_TOTAL_SIZE} CACHE INTERNAL
    "Total shared memory pool size in bytes")

include(utils/HumanReadable)
format_bytes_human_readable(${SSM_POOL_TOTAL_SIZE} SSM_POOL_SIZE_DISPLAY)

# Display configuration summary
message(STATUS "Secure Shared Memory Pool Configuration:")
message(STATUS "  Pool prefix: ${SSM_PREFIX}")
message(STATUS "  Size classes: "
  "256B, 512B, 1KiB, 2KiB, 4KiB, 16KiB, 64KiB, 256KiB, 1MiB")
message(STATUS "  Max allocation: 1 MB")
message(STATUS "  Total pool size: ${SSM_POOL_SIZE_DISPLAY} "
               "(${SSM_POOL_TOTAL_SIZE} bytes)")
message(STATUS "  Shards per class: ${SSM_POOL_SHARDS}")
message(STATUS "  Blocks per class: ${SSM_POOL_256_BLOCKS}, "
               "${SSM_POOL_512_BLOCKS}, ${SSM_POOL_1K_BLOCKS}, "
               "${SSM_POOL_2K_BLOCKS}, ${SSM_POOL_4K_BLOCKS}, "
               "${SSM_POOL_16K_BLOCKS}, ${SSM_POOL_64K_BLOCKS}, "
               "${SSM_POOL_256K_BLOCKS}, ${SSM_POOL_1M_BLOCKS}")
