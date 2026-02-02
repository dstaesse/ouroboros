# Utility functions for Ouroboros target configuration
set(OUROBOROS_DEBUG_CONFIGS
  Debug
  DebugASan
  DebugTSan
  DebugLSan
  DebugUSan
  DebugAnalyzer
)

# Add CONFIG_OUROBOROS_DEBUG definition for debug build types
function(ouroboros_target_debug_definitions target)
  list(JOIN OUROBOROS_DEBUG_CONFIGS "," _configs)
  target_compile_definitions(${target} PRIVATE
    "$<$<CONFIG:${_configs}>:CONFIG_OUROBOROS_DEBUG>")
endfunction()
