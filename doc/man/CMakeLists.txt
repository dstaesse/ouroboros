set(MAN_NAMES
  # Add man page sources here
  ouroboros_init.3
  ouroboros_fini.3
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
  )

macro(INSTALL_MAN __mans)
  foreach (_man ${ARGV})
    string(REGEX REPLACE "^.+[.]([1-9]).gz" "\\1" _mansect ${_man})
    install(FILES ${_man} DESTINATION "usr/share/man/man${_mansect}")
  endforeach (_man)
endmacro(INSTALL_MAN __mans)

find_program(GZIP_EXECUTABLE
  NAMES gzip
  DOC "Will gzip the man pages")

mark_as_advanced(GZIP_EXECUTABLE)

if (GZIP_EXECUTABLE)
  foreach (m ${MAN_NAMES})
    set(md ${CMAKE_CURRENT_BINARY_DIR}/${m}.gz)

    add_custom_command(
      OUTPUT ${md}
      COMMAND ${GZIP_EXECUTABLE}
      ARGS -c ${CMAKE_CURRENT_SOURCE_DIR}/${m} > ${md}
      COMMENT "Compressing manpage ${m}"
      VERBATIM)

    set(MAN_FILES ${MAN_FILES} ${md})
  endforeach ()

  add_custom_target(man ALL DEPENDS ${MAN_FILES})

  INSTALL_MAN(${MAN_FILES})
endif ()
