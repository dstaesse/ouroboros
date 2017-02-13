#!/usr/bin/env bash

BUILDDIR=build
DEBUGDIR=debug

bash compile_debug.sh $1

cd $BUILDDIR/$DEBUGDIR
make install
