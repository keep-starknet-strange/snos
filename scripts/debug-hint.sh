#!/bin/bash

# PYTHONPATH=cairo-lang/src cairo-run \
#     --program build/programs/$1.json \
#     --program_input build/input.json \
#     --layout=small --print_output

echo -e "\nrecompiling cairo program($1)...\n"
#cairo-format -i tests/programs/*
cairo-compile tests/programs/$1.cairo --output build/programs/$1.json --cairo_path cairo-lang/src:~/cairo_venv/lib/python3.9/site-packages/

if [ $? -ne 0 ]; then
    echo -e "$1 failed to recompile...\n"
    rm -f build/$1.json
else
    echo -e "$1 sucessfully recompiled...\n"
fi

cargo test "$1_test" -- --nocapture
