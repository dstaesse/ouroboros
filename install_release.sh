#!/bin/bash

ME=install_release

if (($# == 1 ))
then
    PREFIX=`echo "$1"|sed -e "s,\/$,,"`
else
    PREFIX="/usr"
fi

BUILDDIR=build
RELEASEDIR=release

bash compile_release.sh $PREFIX

cd $BUILDDIR/$RELEASEDIR
make install
