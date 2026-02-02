# DDNS (Dynamic DNS) support detection
# Requires nsupdate and nslookup tools

find_program(NSUPDATE_EXECUTABLE
  NAMES nsupdate
  DOC "The nsupdate tool that enables DDNS")

find_program(NSLOOKUP_EXECUTABLE
  NAMES nslookup
  DOC "The nslookup tool that resolves DNS names")

mark_as_advanced(NSLOOKUP_EXECUTABLE NSUPDATE_EXECUTABLE)

if(NSLOOKUP_EXECUTABLE AND NSUPDATE_EXECUTABLE)
  set(DISABLE_DDNS FALSE CACHE BOOL "Disable DDNS support")
  if(NOT DISABLE_DDNS)
    message(STATUS "DDNS support enabled")
    set(HAVE_DDNS TRUE CACHE INTERNAL "Dynamic DNS support available")
  else()
    message(STATUS "DDNS support disabled by user")
    unset(HAVE_DDNS CACHE)
  endif()
else()
  if(NSLOOKUP_EXECUTABLE)
    message(STATUS "Install nsupdate to enable DDNS support")
  elseif(NSUPDATE_EXECUTABLE)
    message(STATUS "Install nslookup to enable DDNS support")
  else()
    message(STATUS "Install nslookup and nsupdate to enable DDNS support")
  endif()
endif()
