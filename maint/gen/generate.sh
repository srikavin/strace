#!/bin/sh -euf

OUTPUT_PATH=../../src/gen

make all

mkdir -p "$OUTPUT_PATH"

while read -r in out; do
	echo "generating $OUTPUT_PATH/gen_$out" 1>&2
	./gen "$in" "$OUTPUT_PATH/gen_$out"
done < generate.in
