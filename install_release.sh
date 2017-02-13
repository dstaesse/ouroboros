#!/usr/bin/env bash

ME=install_release

if (($# == 1 ))
then
    PREFIX=`echo "$1"|sed -e "s,\/$,,"`
else
    PREFIX=""
fi

BUILDDIR=build
RELEASEDIR=release

bash compile_release.sh $PREFIX

cd $BUILDDIR/$RELEASEDIR
make install
