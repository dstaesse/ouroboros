#!/bin/bash

ME=compile_debug

if (($# == 1 ))
then
    PREFIX=`echo "$1"|sed -e "s,\/$,,"`
else
    PREFIX="/usr/local/ouroboros"
fi

BUILDDIR=build
DEBUGDIR=debug

echo "$ME: Prefix is $PREFIX"

echo "$ME: Build directory will be '$BUILDDIR'"
if test -n "$BUILDDIR" ; then
    mkdir -p $BUILDDIR || {
        echo "$ME: Cannot create directory '$BUILDDIR'"
    }
fi
cd $BUILDDIR

echo "$ME: Debug directory will be '$DEBUGDIR'"
if test -n "$DEBUGDIR" ; then
    mkdir -p $DEBUGDIR || {
        echo "$ME: Cannot create directory '$DEBUGDIR'"
    }
fi
cd $DEBUGDIR

cmake -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_BUILD_TYPE=Debug ../..

make && make check
