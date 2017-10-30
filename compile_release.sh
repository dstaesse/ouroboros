#!/usr/bin/env bash

ME=compile_release

if (($# == 1 ))
then
    PREFIX=${1/%\//}
else
    PREFIX=""
fi

BUILDDIR=build
RELEASEDIR=release

echo "$ME: Prefix is $PREFIX"

echo "$ME: Build directory will be '$BUILDDIR'"
if test -n "$BUILDDIR" ; then
    mkdir -p $BUILDDIR || {
        echo "$ME: Cannot create directory '$BUILDDIR'"
    }
fi
cd $BUILDDIR || exit 1

echo "$ME: Release directory will be '$RELEASEDIR'"
if test -n "$RELEASEDIR" ; then
    mkdir -p $RELEASEDIR || {
        echo "$ME: Cannot create directory '$RELEASEDIR'"
    }
fi
cd $RELEASEDIR || exit 1

cmake -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_BUILD_TYPE=Release ../..

make
