#!/bin/bash

ME=install_release

if (($# == 1 ))
then
    PREFIX=$1
else
    PREFIX="/"
fi

BUILDDIR=build
RELEASEDIR=release

bash compile_release.sh $PREFIX

cd $BUILDDIR/$RELEASEDIR
make install
