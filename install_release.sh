#!/bin/bash

ME=install_release

if (($# == 1 ))
then
    PREFIX=`echo "$1"|sed -e "s,\/$,,"`
else
    PREFIX="/usr/local/ouroboros"
fi

BUILDDIR=build
RELEASEDIR=release

bash compile_debug.sh $PREFIX

cd $BUILDDIR/$RELEASEDIR
make install
