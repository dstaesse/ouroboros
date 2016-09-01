find_package(SWIG)

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

if (NOT SWIG_FOUND)
  message("-- SWIG not found: Bindings for other languages disabled.")
else ()
  include(${SWIG_USE_FILE})
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  set(CMAKE_SWIG_FLAGS "")

  find_package(PythonLibs)
  if (NOT PYTHONLIBS_FOUND)
    message("-- Python not found: Python bindings will not be built.")
  else ()
    include_directories(${PYTHON_INCLUDE_PATH})

    swig_add_module(ouroboros python ouroboros.i)
    swig_link_libraries(ouroboros ${PYTHON_LIBRARIES} ouroboros)

    # Installation directives
    if (CMAKE_INSTALL_PREFIX STREQUAL "")
      execute_process(
        COMMAND python -c "from distutils import sysconfig; print(sysconfig.get_python_lib())"
        OUTPUT_VARIABLE PYTHON_MODULE_PATH
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    else ()
      execute_process(
        COMMAND python -c "from distutils import sysconfig; print(sysconfig.get_python_lib(plat_specific=True, prefix='${CMAKE_INSTALL_PREFIX}'))"
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
endif ()
