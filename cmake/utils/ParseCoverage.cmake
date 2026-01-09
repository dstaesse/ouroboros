# Parse CTest Coverage.xml file and extract structured coverage data.
#
# Sets in PARENT_SCOPE:
#   LOC_TESTED, LOC_UNTESTED - Overall metrics
#   FILE_COVERAGE_LIST - "path|name|tested|untested|total|percent" entries
#   COVERED_FILES - Absolute paths of covered files

# Regex building blocks
set(R_NUMBER "[0-9]+")
set(R_NON_TAG "[^<]*")
set(R_NON_BRACKET "[^>]*")
set(R_NON_QUOTE "[^\"]+")

# XML element patterns
set(R_LOC_TESTED_ELEM "<LOCTested>(${R_NUMBER})</LOCTested>")
set(R_LOC_TESTED_SKIP "<LOCTested>${R_NUMBER}</LOCTested>")
set(R_LOC_UNTESTED_ELEM "<LOCUntested>(${R_NUMBER})</LOCUntested>")
set(R_LOC_UNTESTED_CAP "<LOCUnTested>(${R_NUMBER})</LOCUnTested>")

# Regex patterns for XML parsing
set(REGEX_LOC_TESTED "</File>${R_NON_TAG}${R_LOC_TESTED_ELEM}")
set(REGEX_LOC_UNTESTED "</File>${R_NON_TAG}${R_LOC_TESTED_SKIP}${R_NON_TAG}${R_LOC_UNTESTED_ELEM}")
set(REGEX_FILE_ENTRY "<File${R_NON_BRACKET}Name=\"(${R_NON_QUOTE})\"${R_NON_BRACKET}>${R_NON_TAG}${R_LOC_TESTED_ELEM}${R_NON_TAG}${R_LOC_UNTESTED_CAP}")

# Regex patterns for filtering
set(REGEX_TEST_FILE "test")
set(REGEX_TEST_DIR "/tests/")
set(REGEX_PROTOBUF_C "\\.pb-c\\.c$")
set(REGEX_PROTOBUF_ALT "\\.pb\\.c$")
set(REGEX_DOTSLASH_SRC "^\\.\\/src\\/")

function(should_skip_file FILE_PATH OUTPUT_VAR)
  if(FILE_PATH MATCHES "${REGEX_TEST_FILE}" OR FILE_PATH MATCHES "${REGEX_TEST_DIR}" OR
     FILE_PATH MATCHES "${REGEX_PROTOBUF_C}" OR FILE_PATH MATCHES "${REGEX_PROTOBUF_ALT}")
    set(${OUTPUT_VAR} TRUE PARENT_SCOPE)
  else()
    set(${OUTPUT_VAR} FALSE PARENT_SCOPE)
  endif()
endfunction()

function(normalize_coverage_path FILE_PATH PROJECT_SOURCE_DIR OUTPUT_VAR)
  if(NOT IS_ABSOLUTE "${FILE_PATH}")
    string(REGEX REPLACE "${REGEX_DOTSLASH_SRC}" "src/" FILE_PATH "${FILE_PATH}")
    get_filename_component(FILE_PATH "${PROJECT_SOURCE_DIR}/${FILE_PATH}" ABSOLUTE)
  endif()
  set(${OUTPUT_VAR} "${FILE_PATH}" PARENT_SCOPE)
endfunction()

function(extract_xml_attribute XML_STRING ATTRIBUTE OUTPUT_VAR)
  string(REGEX MATCH "${ATTRIBUTE}=\"([^\"]+)\"" _ "${XML_STRING}")
  set(${OUTPUT_VAR} "${CMAKE_MATCH_1}" PARENT_SCOPE)
endfunction()

function(extract_xml_element XML_STRING ELEMENT OUTPUT_VAR)
  string(REGEX MATCH "<${ELEMENT}>([^<]+)</${ELEMENT}>" _ "${XML_STRING}")
  set(${OUTPUT_VAR} "${CMAKE_MATCH_1}" PARENT_SCOPE)
endfunction()

function(build_coverage_entry PATH NAME TESTED UNTESTED OUTPUT_VAR)
  math(EXPR TOTAL "${TESTED} + ${UNTESTED}")
  if(NOT TOTAL GREATER 0)
    set(${OUTPUT_VAR} "" PARENT_SCOPE)
    return()
  endif()
  math(EXPR PERCENT "(${TESTED} * 100) / ${TOTAL}")
  set(${OUTPUT_VAR} "${PATH}|${NAME}|${TESTED}|${UNTESTED}|${TOTAL}|${PERCENT}" PARENT_SCOPE)
endfunction()

function(parse_coverage_xml COVERAGE_FILE PROJECT_SOURCE_DIR)
  if(NOT EXISTS "${COVERAGE_FILE}")
    return()
  endif()

  file(READ "${COVERAGE_FILE}" COVERAGE_XML)

  string(REGEX MATCH "${REGEX_LOC_TESTED}" _ "${COVERAGE_XML}")
  set(TESTED "${CMAKE_MATCH_1}")

  string(REGEX MATCH "${REGEX_LOC_UNTESTED}" _ "${COVERAGE_XML}")
  set(UNTESTED "${CMAKE_MATCH_1}")

  if(NOT TESTED OR NOT UNTESTED)
    return()
  endif()

  string(REGEX MATCHALL "${REGEX_FILE_ENTRY}" FILE_MATCHES "${COVERAGE_XML}")

  set(COVERED_LIST "")
  set(COVERAGE_DATA "")

  foreach(MATCH ${FILE_MATCHES})
    extract_xml_attribute("${MATCH}" "FullPath" PATH)
    extract_xml_attribute("${MATCH}" "Name" NAME)

    should_skip_file("${PATH}" SKIP)
    if(SKIP)
      continue()
    endif()

    normalize_coverage_path("${PATH}" "${PROJECT_SOURCE_DIR}" ABS_PATH)
    list(APPEND COVERED_LIST "${ABS_PATH}")

    extract_xml_element("${MATCH}" "LOCTested" TESTED_LINES)
    extract_xml_element("${MATCH}" "LOCUnTested" UNTESTED_LINES)

    if(NOT TESTED_LINES OR NOT UNTESTED_LINES)
      continue()
    endif()

    build_coverage_entry("${PATH}" "${NAME}" "${TESTED_LINES}" "${UNTESTED_LINES}" ENTRY)
    if(ENTRY)
      list(APPEND COVERAGE_DATA "${ENTRY}")
    endif()
  endforeach()

  set(LOC_TESTED "${TESTED}" PARENT_SCOPE)
  set(LOC_UNTESTED "${UNTESTED}" PARENT_SCOPE)
  set(FILE_COVERAGE_LIST "${COVERAGE_DATA}" PARENT_SCOPE)
  set(COVERED_FILES "${COVERED_LIST}" PARENT_SCOPE)
endfunction()
