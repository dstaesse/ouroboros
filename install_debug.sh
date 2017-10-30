#!/usr/bin/env bash

if (($# == 1 ))
then
    PREFIX=${1/%\//}
else
    PREFIX="/usr/local/ouroboros"
fi

BUILDDIR=build
DEBUGDIR=debug

bash compile_debug.sh "$PREFIX"

cd $BUILDDIR/$DEBUGDIR || exit 1
make install
