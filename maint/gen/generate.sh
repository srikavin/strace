#!/bin/sh -euf

make

mkdir -p ../../src/gen

while IFS="$(printf '\t')" read in out; do
	./gen "$in" "../../src/gen/gen_$out"
done < generate.in