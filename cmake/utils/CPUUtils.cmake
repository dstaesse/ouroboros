include(CheckCSourceCompiles)

# Detect a CPU feature by attempting to compile a small program with
# the matching compiler flag.
function(detect_cpu_feature _result_var _flags _source)
  set(_save_flags "${CMAKE_REQUIRED_FLAGS}")
  set(_save_quiet "${CMAKE_REQUIRED_QUIET}")
  set(CMAKE_REQUIRED_FLAGS "${_save_flags} ${_flags}")
  set(CMAKE_REQUIRED_QUIET TRUE)
  check_c_source_compiles("${_source}" ${_result_var})
  set(CMAKE_REQUIRED_FLAGS "${_save_flags}")
  set(CMAKE_REQUIRED_QUIET "${_save_quiet}")
endfunction()

# x86 PCLMULQDQ (carry-less multiply) + SSE4.1.  Sets HAVE_PCLMUL only
# when both intrinsic groups compile.
function(detect_pclmul)
  detect_cpu_feature(_HAVE_PCLMUL "-mpclmul"
"#include <wmmintrin.h>
int main(void) {
        __m128i a = _mm_setzero_si128();
        __m128i b = _mm_clmulepi64_si128(a, a, 0);
        return (int) _mm_cvtsi128_si32(b);
}")
  detect_cpu_feature(_HAVE_SSE41 "-msse4.1"
"#include <smmintrin.h>
int main(void) {
        __m128i a = _mm_setzero_si128();
        return _mm_extract_epi32(a, 0);
}")
  if(_HAVE_PCLMUL AND _HAVE_SSE41)
    set(HAVE_PCLMUL TRUE CACHE INTERNAL
        "x86 PCLMUL + SSE4.1 intrinsics available")
  else()
    unset(HAVE_PCLMUL CACHE)
  endif()
endfunction()

# aarch64 FEAT_PMULL (vmull_p64 / vmull_high_p64) carry-less multiply.
function(detect_pmull)
  detect_cpu_feature(_HAVE_PMULL "-march=armv8-a+crypto"
"#include <arm_neon.h>
int main(void) {
        poly64_t   a = (poly64_t) 0;
        poly128_t  c = vmull_p64(a, a);
        return (int) vgetq_lane_u64((uint64x2_t) c, 0);
}")
  if(_HAVE_PMULL)
    set(HAVE_PMULL TRUE CACHE INTERNAL
        "aarch64 PMULL intrinsics available")
  else()
    unset(HAVE_PMULL CACHE)
  endif()
endfunction()
