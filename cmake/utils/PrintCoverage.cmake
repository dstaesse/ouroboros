# Script to parse and display coverage results from CTest
#
# This script is invoked by the 'make coverage' target and parses the CTest
# Coverage.xml file to generate a formatted coverage report grouped by component.
#
# This script is run with cmake -P, so CMAKE_SOURCE_DIR won't be set correctly.
# Use PROJECT_SOURCE_DIR and PROJECT_BINARY_DIR passed as -D arguments.

if(NOT DEFINED PROJECT_SOURCE_DIR)
  message(FATAL_ERROR "PROJECT_SOURCE_DIR must be defined")
endif()
if(NOT DEFINED PROJECT_BINARY_DIR)
  message(FATAL_ERROR "PROJECT_BINARY_DIR must be defined")
endif()

# Include coverage parsing functions
include(${CMAKE_CURRENT_LIST_DIR}/ParseCoverage.cmake)

# Create padding strings (CMake 2.8 compatible)
function(make_padding LENGTH OUTPUT_VAR)
  set(RESULT "")
  if(LENGTH GREATER 0)
    foreach(i RANGE 1 ${LENGTH})
      set(RESULT "${RESULT} ")
    endforeach()
  endif()
  set(${OUTPUT_VAR} "${RESULT}" PARENT_SCOPE)
endfunction()

# Format a number with padding for right alignment
function(format_number VALUE WIDTH OUTPUT_VAR)
  string(LENGTH "${VALUE}" VALUE_LEN)
  math(EXPR PAD_LEN "${WIDTH} - ${VALUE_LEN}")
  make_padding(${PAD_LEN} PADDING)
  set(${OUTPUT_VAR} "${PADDING}${VALUE}" PARENT_SCOPE)
endfunction()

# Format a complete coverage row with consistent alignment
function(format_coverage_row LABEL TESTED TESTED_FC UNTESTED UNTESTED_FC TOTAL PERCENT OUTPUT_VAR)
  string(LENGTH "${LABEL}" LABEL_LEN)
  math(EXPR LABEL_PAD "28 - ${LABEL_LEN}")
  make_padding(${LABEL_PAD} LP)

  format_number(${TESTED} 6 TS)
  format_number(${TESTED_FC} 3 TFC)
  format_number(${UNTESTED} 8 US)
  format_number(${UNTESTED_FC} 3 UFC)
  format_number(${TOTAL} 5 TT)
  format_number(${PERCENT} 3 PC)
  set(${OUTPUT_VAR} "    ${LABEL}${LP}${TS}[${TFC}] ${US}[${UFC}]   ${TT}    ${PC}%" PARENT_SCOPE)
endfunction()

# Format the header row to align with data columns
function(format_coverage_header OUTPUT_VAR)
  set(HEADER "    Component                        Tested      Untested   Total       %")
  set(${OUTPUT_VAR} "${HEADER}" PARENT_SCOPE)
endfunction()

# Calculate metrics from entry list (pipe-delimited: path|name|tested|untested|total|percent)
function(calculate_metrics ENTRIES OUT_TESTED OUT_UNTESTED OUT_TESTED_FC OUT_UNTESTED_FC)
  set(TESTED 0)
  set(UNTESTED 0)
  set(TESTED_FC 0)
  set(UNTESTED_FC 0)

  foreach(ENTRY ${ENTRIES})
    string(REPLACE "|" ";" PARTS "${ENTRY}")
    list(GET PARTS 2 ENTRY_TESTED)
    list(GET PARTS 3 ENTRY_UNTESTED)

    math(EXPR TESTED "${TESTED} + ${ENTRY_TESTED}")
    math(EXPR UNTESTED "${UNTESTED} + ${ENTRY_UNTESTED}")

    if(ENTRY_TESTED EQUAL 0)
      math(EXPR UNTESTED_FC "${UNTESTED_FC} + 1")
    else()
      math(EXPR TESTED_FC "${TESTED_FC} + 1")
    endif()
  endforeach()

  set(${OUT_TESTED} "${TESTED}" PARENT_SCOPE)
  set(${OUT_UNTESTED} "${UNTESTED}" PARENT_SCOPE)
  set(${OUT_TESTED_FC} "${TESTED_FC}" PARENT_SCOPE)
  set(${OUT_UNTESTED_FC} "${UNTESTED_FC}" PARENT_SCOPE)
endfunction()

# Discover components and sub-components from source tree
function(discover_components PROJECT_SOURCE_DIR OUT_COMPONENTS OUT_COMP_SUBCOMPS)
  file(GLOB COMPONENT_DIRS "${PROJECT_SOURCE_DIR}/src/*")
  set(COMPONENTS "")
  set(SKIP_DIRS "include;doc;tests")

  foreach(DIR ${COMPONENT_DIRS})
    if(IS_DIRECTORY ${DIR})
      get_filename_component(COMP_NAME ${DIR} NAME)
      list(FIND SKIP_DIRS ${COMP_NAME} SKIP_IDX)
      if(SKIP_IDX EQUAL -1)
        list(APPEND COMPONENTS ${COMP_NAME})

        file(GLOB SUBCOMP_DIRS "${DIR}/*")
        set(COMP_${COMP_NAME}_SUBCOMPS "")
        foreach(SUBDIR ${SUBCOMP_DIRS})
          if(IS_DIRECTORY ${SUBDIR})
            get_filename_component(SUBCOMP_NAME ${SUBDIR} NAME)
            list(FIND SKIP_DIRS ${SUBCOMP_NAME} SKIP_IDX2)
            if(SKIP_IDX2 EQUAL -1)
              list(APPEND COMP_${COMP_NAME}_SUBCOMPS ${SUBCOMP_NAME})
              set(COMP_${COMP_NAME}_${SUBCOMP_NAME} "")
            endif()
          endif()
        endforeach()
      endif()
    endif()
  endforeach()

  set(${OUT_COMPONENTS} "${COMPONENTS}" PARENT_SCOPE)
  foreach(COMP ${COMPONENTS})
    set(COMP_${COMP}_SUBCOMPS "${COMP_${COMP}_SUBCOMPS}" PARENT_SCOPE)
  endforeach()
endfunction()

# Print a coverage line
function(print_coverage_line LABEL TESTED TESTED_FC UNTESTED UNTESTED_FC TOTAL PERCENT)
  format_coverage_row("${LABEL}" ${TESTED} ${TESTED_FC} ${UNTESTED} ${UNTESTED_FC} ${TOTAL} ${PERCENT} ROW)
  execute_process(COMMAND ${CMAKE_COMMAND} -E echo "${ROW}")
endfunction()

# Locate the coverage file
if(NOT EXISTS "${CMAKE_BINARY_DIR}/Testing/TAG")
  message(WARNING "Testing/TAG file not found. Coverage may not have run successfully.")
  return()
endif()

file(STRINGS "${CMAKE_BINARY_DIR}/Testing/TAG" TAG_CONTENTS LIMIT_COUNT 1)
string(STRIP "${TAG_CONTENTS}" TEST_DIR)
set(COVERAGE_FILE "${CMAKE_BINARY_DIR}/Testing/${TEST_DIR}/Coverage.xml")

if(NOT EXISTS "${COVERAGE_FILE}")
  message(WARNING "Coverage file not found: ${COVERAGE_FILE}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E echo "Note: Coverage results should be in Testing/${TEST_DIR}/")
  return()
endif()

# Parse the coverage XML file
parse_coverage_xml("${COVERAGE_FILE}" "${PROJECT_SOURCE_DIR}")

if(NOT LOC_TESTED OR NOT LOC_UNTESTED)
  message(WARNING "Could not parse coverage metrics")
  return()
endif()

math(EXPR TOTAL_LOC "${LOC_TESTED} + ${LOC_UNTESTED}")
if(NOT TOTAL_LOC GREATER 0)
  message(WARNING "No coverage data found")
  return()
endif()

math(EXPR COVERAGE_PERCENT "(${LOC_TESTED} * 100) / ${TOTAL_LOC}")

# Discover and group files by component
if(NOT FILE_COVERAGE_LIST)
  execute_process(COMMAND ${CMAKE_COMMAND} -E echo "No coverage data for source files (excluding tests)")
  return()
endif()

# Discover components from source tree (only src/ directory)
discover_components("${PROJECT_SOURCE_DIR}" COMPONENTS COMP_SUBCOMPS)

# Find all source files and identify completely untested ones
file(GLOB_RECURSE ALL_SOURCE_FILES "${PROJECT_SOURCE_DIR}/src/*.c")
set(UNCOVERED_FILES "")
foreach(SRC_FILE ${ALL_SOURCE_FILES})
  if(SRC_FILE MATCHES "test" OR SRC_FILE MATCHES "/tests/")
    continue()
  endif()

  list(FIND COVERED_FILES "${SRC_FILE}" FILE_IDX)
  if(FILE_IDX EQUAL -1)
    file(STRINGS "${SRC_FILE}" FILE_LINES)
    list(LENGTH FILE_LINES LINE_COUNT)
    if(LINE_COUNT GREATER 0)
      get_filename_component(FILE_NAME "${SRC_FILE}" NAME)
      list(APPEND UNCOVERED_FILES "${SRC_FILE}|${FILE_NAME}|0|${LINE_COUNT}|${LINE_COUNT}|0")
    endif()
  endif()
endforeach()

# Combine covered and uncovered files
set(ALL_FILES ${FILE_COVERAGE_LIST})
if(UNCOVERED_FILES)
  list(APPEND ALL_FILES ${UNCOVERED_FILES})
endif()

# Group files into components and sub-components
foreach(ENTRY ${ALL_FILES})
  string(REPLACE "|" ";" ENTRY_PARTS "${ENTRY}")
  list(GET ENTRY_PARTS 0 F_PATH)

  # Normalize path and extract relative path from src/
  # Remove leading ./ if present, then ensure path starts with src/
  string(REGEX REPLACE "^\\./" "" REL_PATH "${F_PATH}")
  string(REGEX REPLACE "^.*/src/" "src/" REL_PATH "${REL_PATH}")

  # Tokenize on /: ["src", "component", "subcomponent", "file.c"]
  string(REPLACE "/" ";" PATH_TOKENS "${REL_PATH}")
  list(LENGTH PATH_TOKENS TOKEN_COUNT)

  if(TOKEN_COUNT EQUAL 3)
    # src/component/file.c - add to component main
    list(GET PATH_TOKENS 1 FILE_COMP)
    list(FIND COMPONENTS ${FILE_COMP} COMP_IDX)
    if(COMP_IDX GREATER -1)
      list(APPEND COMP_${FILE_COMP} "${ENTRY}")
      list(APPEND COMP_${FILE_COMP}_main "${ENTRY}")
    endif()
  elseif(TOKEN_COUNT GREATER 3)
    # src/component/subdir/.../file.c - check if subdir is a known subcomponent
    list(GET PATH_TOKENS 1 FILE_COMP)
    list(GET PATH_TOKENS 2 FILE_SUBCOMP)

    list(FIND COMPONENTS ${FILE_COMP} COMP_IDX)
    if(COMP_IDX GREATER -1)
      list(APPEND COMP_${FILE_COMP} "${ENTRY}")

      # Check if subdir is a recognized subcomponent
      list(FIND COMP_${FILE_COMP}_SUBCOMPS ${FILE_SUBCOMP} SUBCOMP_IDX)
      if(SUBCOMP_IDX GREATER -1)
        list(APPEND COMP_${FILE_COMP}_${FILE_SUBCOMP} "${ENTRY}")
      else()
        # Subdir not recognized, treat as main
        list(APPEND COMP_${FILE_COMP}_main "${ENTRY}")
      endif()
    endif()
  endif()
endforeach()

execute_process(COMMAND ${CMAKE_COMMAND} -E echo "")
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "=============================================================================")
format_coverage_header(HEADER)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "${HEADER}")
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "=============================================================================")

# Process and display each component
foreach(COMP_NAME ${COMPONENTS})
  set(COMP_LIST ${COMP_${COMP_NAME}})

  if(NOT COMP_LIST)
    continue()
  endif()

  calculate_metrics("${COMP_LIST}" COMP_TESTED COMP_UNTESTED COMP_TESTED_FILE_COUNT COMP_UNTESTED_FILE_COUNT)
  math(EXPR COMP_TOTAL "${COMP_TESTED} + ${COMP_UNTESTED}")
  if(COMP_TOTAL GREATER 0)
    math(EXPR COMP_PERCENT "(${COMP_TESTED} * 100) / ${COMP_TOTAL}")
  else()
    set(COMP_PERCENT 0)
  endif()

  print_coverage_line("${COMP_NAME}" ${COMP_TESTED} ${COMP_TESTED_FILE_COUNT} ${COMP_UNTESTED} ${COMP_UNTESTED_FILE_COUNT} ${COMP_TOTAL} ${COMP_PERCENT})

  # Display "main" sub-component first if it has files
  set(MAIN_LIST ${COMP_${COMP_NAME}_main})
  if(MAIN_LIST)
    calculate_metrics("${MAIN_LIST}" MAIN_TESTED MAIN_UNTESTED MAIN_TESTED_FILE_COUNT MAIN_UNTESTED_FILE_COUNT)
    math(EXPR MAIN_TOTAL "${MAIN_TESTED} + ${MAIN_UNTESTED}")
    if(MAIN_TOTAL GREATER 0)
      math(EXPR MAIN_PERCENT "(${MAIN_TESTED} * 100) / ${MAIN_TOTAL}")
    else()
      set(MAIN_PERCENT 0)
    endif()

    print_coverage_line("  ." ${MAIN_TESTED} ${MAIN_TESTED_FILE_COUNT} ${MAIN_UNTESTED} ${MAIN_UNTESTED_FILE_COUNT} ${MAIN_TOTAL} ${MAIN_PERCENT})
  endif()

  # Display sub-components
  foreach(SUBCOMP ${COMP_${COMP_NAME}_SUBCOMPS})
    set(SUBCOMP_LIST ${COMP_${COMP_NAME}_${SUBCOMP}})
    if(NOT SUBCOMP_LIST)
      continue()
    endif()

    calculate_metrics("${SUBCOMP_LIST}" SUBCOMP_TESTED SUBCOMP_UNTESTED SUBCOMP_TESTED_FILE_COUNT SUBCOMP_UNTESTED_FILE_COUNT)
    math(EXPR SUBCOMP_TOTAL "${SUBCOMP_TESTED} + ${SUBCOMP_UNTESTED}")
    if(SUBCOMP_TOTAL GREATER 0)
      math(EXPR SUBCOMP_PERCENT "(${SUBCOMP_TESTED} * 100) / ${SUBCOMP_TOTAL}")
    else()
      set(SUBCOMP_PERCENT 0)
    endif()

    print_coverage_line("  ${SUBCOMP}" ${SUBCOMP_TESTED} ${SUBCOMP_TESTED_FILE_COUNT} ${SUBCOMP_UNTESTED} ${SUBCOMP_UNTESTED_FILE_COUNT} ${SUBCOMP_TOTAL} ${SUBCOMP_PERCENT})
  endforeach()

  execute_process(COMMAND ${CMAKE_COMMAND} -E echo "")
endforeach()

# Calculate overall coverage
set(TOTAL_TESTED ${LOC_TESTED})
set(TOTAL_UNTESTED ${LOC_UNTESTED})

# Count file coverage for totals
set(TOTAL_TESTED_FILE_COUNT 0)
set(TOTAL_UNTESTED_FILE_COUNT 0)

foreach(ENTRY ${FILE_COVERAGE_LIST})
  string(REPLACE "|" ";" PARTS "${ENTRY}")
  list(GET PARTS 2 ENTRY_TESTED)
  if(ENTRY_TESTED EQUAL 0)
    math(EXPR TOTAL_UNTESTED_FILE_COUNT "${TOTAL_UNTESTED_FILE_COUNT} + 1")
  else()
    math(EXPR TOTAL_TESTED_FILE_COUNT "${TOTAL_TESTED_FILE_COUNT} + 1")
  endif()
endforeach()

# Add untested file counts
foreach(ENTRY ${UNCOVERED_FILES})
  string(REPLACE "|" ";" PARTS "${ENTRY}")
  list(GET PARTS 3 ENTRY_UNTESTED)
  math(EXPR TOTAL_UNTESTED "${TOTAL_UNTESTED} + ${ENTRY_UNTESTED}")
  math(EXPR TOTAL_UNTESTED_FILE_COUNT "${TOTAL_UNTESTED_FILE_COUNT} + 1")
endforeach()

math(EXPR TOTAL_ALL_LOC "${TOTAL_TESTED} + ${TOTAL_UNTESTED}")
if(TOTAL_ALL_LOC GREATER 0)
  math(EXPR OVERALL_COVERAGE_PERCENT "(${TOTAL_TESTED} * 100) / ${TOTAL_ALL_LOC}")
else()
  set(OVERALL_COVERAGE_PERCENT 0)
endif()

execute_process(COMMAND ${CMAKE_COMMAND} -E echo "=============================================================================")
print_coverage_line("Total" ${TOTAL_TESTED} ${TOTAL_TESTED_FILE_COUNT} ${TOTAL_UNTESTED} ${TOTAL_UNTESTED_FILE_COUNT} ${TOTAL_ALL_LOC} ${OVERALL_COVERAGE_PERCENT})
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "=============================================================================")
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "")
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "Detailed XML report: ${COVERAGE_FILE}")
