#!/bin/bash

ME=install_debug

if (($# == 1 ))
then
    PREFIX=$1
else
    PREFIX="/usr/local/ouroboros"
fi

BUILDDIR=build
DEBUGDIR=debug

bash compile_debug.sh $PREFIX

cd $BUILDDIR/$DEBUGDIR
make install
