#!/bin/bash

pushd quickjs

export CFLAGS='-fsanitize-coverage=trace-pc-guard'
export CXXFLAGS='-fsanitize-coverage=trace-pc-guard'

# build quickjs
# Makefile should not override CFLAGS
sed -i -e 's/CFLAGS=/CFLAGS+=/' Makefile
CONFIG_CLANG=y make libquickjs.a -j

popd

unset CC
unset CXX
unset CFLAGS
unset CXXFLAGS

cargo +nightly build --release

export CC=`pwd`/target/release/libafl_cc
export CXX=`pwd`/target/release/libafl_cxx
export CFLAGS='-fsanitize-coverage=trace-pc-guard'
export CXXFLAGS='-fsanitize-coverage=trace-pc-guard'

FUZZ_TARGETS="fuzz_eval"
for f in $FUZZ_TARGETS; do
    $CC $CFLAGS -Iquickjs -c $f.c -o $f.o
    $CXX $CXXFLAGS $f.o -o $f quickjs/libquickjs.a `python3-config --embed --ldflags`
done
