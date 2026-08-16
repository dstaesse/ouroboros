# Encryption configuration for Ouroboros Options for the key schedule and packet protection in
# src/lib/crypt/

# Encryption
set(KEY_LEAF_BITS 20 CACHE STRING
  "Packets per leaf key as a power of two (2^20 = AEAD-safe default)")
set(KEY_NODE_BITS 6 CACHE STRING
  "Leaf keys per node key, power of two (2^6 = 64; leak compartment)")
set(KEY_NODE_COUNT 128 CACHE STRING
  "Node keys per batch (N); <= 4096, the 12-bit on-wire node index")
set(KEY_REKEY_WATERMARK 4 CACHE STRING
  "Re-key when this many node keys remain; 0 disables the count trigger")
set(KEY_REPLAY_WINDOW 2048 CACHE STRING
  "RX replay window in packets; power of two, >= 128")
set(KEY_REKEY_WM_CHECK_BITS 16 CACHE STRING
  "Re-key watermark is consulted once per 2^n flow writes")
if(NOT KEY_REPLAY_WINDOW MATCHES "^[0-9]+$")
  message(FATAL_ERROR "KEY_REPLAY_WINDOW must be a positive integer")
endif()
math(EXPR _krw_p2 "${KEY_REPLAY_WINDOW} & (${KEY_REPLAY_WINDOW} - 1)")
if(KEY_REPLAY_WINDOW LESS 128 OR NOT _krw_p2 EQUAL 0)
  message(FATAL_ERROR "KEY_REPLAY_WINDOW must be a power of two >= 128")
endif()

# Re-key must finish within its lead window - KEY_REKEY_WATERMARK node keys worth of packets -
# before the batch exhausts and TX fails closed. dev.c only evaluates the watermark once per
# FLOW_WM_CHECK writes, so a lead below ~2x that leaves a high-rate flow no room to complete the
# exchange. Production defaults are vast; this guards under-sized (test) geometries.
if(KEY_REKEY_WATERMARK GREATER 0)
  math(EXPR _rk_wm_check "1 << ${KEY_REKEY_WM_CHECK_BITS}")
  math(EXPR _rk_lead
    "${KEY_REKEY_WATERMARK} << (${KEY_LEAF_BITS} + ${KEY_NODE_BITS})")
  math(EXPR _rk_min "2 * ${_rk_wm_check}")
  if(_rk_lead LESS _rk_min)
    message(WARNING
      "Re-key lead is ${_rk_lead} packets vs the watermark check interval "
      "${_rk_wm_check}; a high-rate flow may exhaust its key batch before the "
      "re-key completes (TX fails closed until it does). Raise KEY_LEAF_BITS, "
      "KEY_NODE_BITS, or KEY_REKEY_WATERMARK.")
  endif()
endif()
