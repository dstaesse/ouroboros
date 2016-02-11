# - MACRO_ADD_COMPILE_FLAGS(<_target> "flags...")

# Copyright (c) 2006, Oswald Buddenhagen, <ossi@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.


macro(MACRO_ADD_COMPILE_FLAGS _target _flg)

   get_target_property(_flags ${_target} COMPILE_FLAGS)
   if (_flags)
      set(_flags "${_flags} ${_flg}")
   else (_flags)
      set(_flags "${_flg}")
   endif (_flags)
   set_target_properties(${_target} PROPERTIES COMPILE_FLAGS "${_flags}")

endmacro(MACRO_ADD_COMPILE_FLAGS)
