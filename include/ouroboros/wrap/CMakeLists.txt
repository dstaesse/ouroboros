include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_package(SWIG QUIET)
if (NOT SWIG_FOUND)
  message(STATUS "Install SWIG to enable bindings for other languages")
else ()
  set(DISABLE_SWIG TRUE CACHE BOOL "Disable SWIG support")
  if (NOT DISABLE_SWIG)
    message(STATUS "SWIG support enabled")
    include(${SWIG_USE_FILE})
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_SWIG_FLAGS "")

    find_package(PythonInterp QUIET)
    find_package(PythonLibs QUIET)
    if (NOT PYTHONLIBS_FOUND OR NOT PYTHONINTERP_FOUND)
      message(STATUS "Python not found: Python bindings will not be built")
    else ()
      message(STATUS "Python found: Python bindings will be built")
      include_directories(${PYTHON_INCLUDE_PATH})

      # Python assumes C99 since Python 3.6
      test_and_set_c_compiler_flag_global(-std=c99)
      # SWIG generates code for varargs with an unused parameter
      test_and_set_c_compiler_flag_global(-Wno-unused-parameter)

      # CMake > 3.8 deprecates swig_add_module
      if (${CMAKE_VERSION} VERSION_LESS 3.8.0)
        swig_add_module(ouroboros python ouroboros.i)
      else ()
        swig_add_library(ouroboros
          LANGUAGE python
          SOURCES ouroboros.i
          TYPE MODULE)
      endif()

      swig_link_libraries(ouroboros ${PYTHON_LIBRARIES} ouroboros-common
        ouroboros-dev ouroboros-irm)

      # Installation directives
      if (CMAKE_INSTALL_PREFIX STREQUAL "")
        execute_process(
          COMMAND ${PYTHON_EXECUTABLE} -c
            "from distutils import sysconfig; print(sysconfig.get_python_lib())"
          OUTPUT_VARIABLE PYTHON_MODULE_PATH
          OUTPUT_STRIP_TRAILING_WHITESPACE)
      else ()
        execute_process(
          COMMAND ${PYTHON_EXECUTABLE} -c
            "from distutils import sysconfig; print(sysconfig.get_python_lib(plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}'))"
          OUTPUT_VARIABLE _ABS_PYTHON_MODULE_PATH
          OUTPUT_STRIP_TRAILING_WHITESPACE)
        get_filename_component(_ABS_PYTHON_MODULE_PATH
          ${_ABS_PYTHON_MODULE_PATH} ABSOLUTE)
        file(RELATIVE_PATH PYTHON_MODULE_PATH
          ${CMAKE_INSTALL_PREFIX} ${_ABS_PYTHON_MODULE_PATH})
      endif ()

      install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${SWIG_MODULE_ouroboros_REAL_NAME}.so
        DESTINATION ${PYTHON_MODULE_PATH})
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ouroboros.py
        DESTINATION ${PYTHON_MODULE_PATH})
    endif ()
  else ()
    message(STATUS "SWIG support disabled by user")
  endif ()
endif ()

mark_as_advanced(SWIG_EXECUTABLE)
