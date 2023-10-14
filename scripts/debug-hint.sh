#!/bin/bash

echo -e "\nrecompiling cairo program($1)...\n"
cairo-format -i tests/programs/*
cairo-compile tests/programs/$1.cairo --output build/programs/$1.json --cairo_path cairo-lang/src:~/cairo_venv/lib/python3.9/site-packages/

if [ $? -ne 0 ]; then
    echo -e "$1 failed to recompile...\n"
    rm -f build/$1.json
else
    echo -e "$1 sucessfully recompiled...\n"
fi

cargo test -q "$1_test" -- --nocapture
