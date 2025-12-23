set(DOC_SOURCE_DIR "${CMAKE_SOURCE_DIR}/doc")
set(DOC_BINARY_DIR "${CMAKE_BINARY_DIR}/doc")

set(MAN_NAMES
  # Add man page sources here
  flow_accept.3
  flow_alloc.3
  flow_dealloc.3
  flow_read.3
  flow_write.3
  fccntl.3
  fqueue.3
  fqueue_create.3
  fqueue_destroy.3
  fqueue_next.3
  fevent.3
  fset.3
  fset_create.3
  fset_destroy.3
  fset_zero.3
  fset_add.3
  fset_del.3
  fset_has.3
  ouroboros-glossary.7
  ouroboros-tutorial.7
  ouroboros.8
  irmd.8
  irm.8
  )

macro(INSTALL_MAN __mans)
  foreach (_man ${ARGV})
    string(REGEX REPLACE "^.+[.]([1-9]).gz" "\\1" _mansect ${_man})
    install(FILES ${_man} DESTINATION "${CMAKE_INSTALL_MANDIR}/man${_mansect}")
  endforeach (_man)
endmacro(INSTALL_MAN __mans)

find_program(GZIP_EXECUTABLE
  NAMES gzip
  DOC "Will gzip the man pages")

mark_as_advanced(GZIP_EXECUTABLE)

if (GZIP_EXECUTABLE)
  # Create the doc output directory
  file(MAKE_DIRECTORY ${DOC_BINARY_DIR})

  foreach (m ${MAN_NAMES})
    set(md ${DOC_BINARY_DIR}/${m}.gz)

    add_custom_command(
      OUTPUT ${md}
      COMMAND ${GZIP_EXECUTABLE}
      ARGS -c ${DOC_SOURCE_DIR}/man/${m} > ${md}
      COMMENT "Compressing manpage ${m}"
      VERBATIM)

    set(MAN_FILES ${MAN_FILES} ${md})
  endforeach ()

  add_custom_target(man ALL DEPENDS ${MAN_FILES})

  INSTALL_MAN(${MAN_FILES})
endif ()
