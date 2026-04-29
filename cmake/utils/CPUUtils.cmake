include(CheckCSourceRuns)

# Compile + run a probe so we only enable a feature the host CPU
# actually implements (toolchains accept flags the silicon may lack).
# Cross-compile without an emulator: feature off.
function(detect_cpu_feature _result_var _flags _source)
  set(_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(_save_quiet "${CMAKE_REQUIRED_QUIET}")
  set(CMAKE_REQUIRED_FLAGS "${_save_flags} ${_flags}")
  set(CMAKE_REQUIRED_QUIET TRUE)
  if(CMAKE_CROSSCOMPILING AND NOT CMAKE_CROSSCOMPILING_EMULATOR)
    set(${_result_var} FALSE CACHE INTERNAL
        "${_result_var} (cross-compile without emulator: off)")
  else()
    check_c_source_runs("${_source}" ${_result_var})
  endif()
  set(CMAKE_REQUIRED_FLAGS "${_save_flags}")
  set(CMAKE_REQUIRED_QUIET "${_save_quiet}")
endfunction()

# x86 PCLMULQDQ + SSE4.1. argc-derived input defeats constant folding;
# SIGILL handler exits cleanly so the kernel skips the core dump.
function(detect_pclmul)
  detect_cpu_feature(_HAVE_PCLMUL "-mpclmul"
"#include <wmmintrin.h>
#include <signal.h>
#include <unistd.h>
static void on_sigill(int sig) { (void) sig; _exit(1); }
int main(int argc, char ** argv) {
        __m128i a;
        __m128i b;
        (void) argv;
        signal(SIGILL, on_sigill);
        a = _mm_set1_epi32(argc);
        b = _mm_clmulepi64_si128(a, a, 0);
        return _mm_cvtsi128_si32(b) & 0;
}")
  detect_cpu_feature(_HAVE_SSE41 "-msse4.1"
"#include <smmintrin.h>
#include <signal.h>
#include <unistd.h>
static void on_sigill(int sig) { (void) sig; _exit(1); }
int main(int argc, char ** argv) {
        __m128i a;
        (void) argv;
        signal(SIGILL, on_sigill);
        a = _mm_set1_epi32(argc);
        return _mm_extract_epi32(a, 0) & 0;
}")
  if(_HAVE_PCLMUL AND _HAVE_SSE41)
    set(HAVE_PCLMUL TRUE CACHE INTERNAL
        "x86 PCLMUL + SSE4.1 intrinsics available")
  else()
    unset(HAVE_PCLMUL CACHE)
  endif()
endfunction()

# aarch64 FEAT_PMULL (vmull_p64). Pi 4's BCM2711 accepts +crypto at
# compile time but lacks the hardware — the runtime probe catches that.
function(detect_pmull)
  detect_cpu_feature(_HAVE_PMULL "-march=armv8-a+crypto"
"#include <arm_neon.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
static void on_sigill(int sig) { (void) sig; _exit(1); }
int main(int argc, char ** argv) {
        poly64_t   a;
        poly128_t  c;
        (void) argv;
        signal(SIGILL, on_sigill);
        a = (poly64_t) (uint64_t) argc;
        c = vmull_p64(a, a);
        return (int) (vgetq_lane_u64((uint64x2_t) c, 0) & 0);
}")
  if(_HAVE_PMULL)
    set(HAVE_PMULL TRUE CACHE INTERNAL
        "aarch64 PMULL intrinsics available")
  else()
    unset(HAVE_PMULL CACHE)
  endif()
endfunction()
