#!/bin/bash

shopt -s extglob

git submodule deinit -f .
git submodule update --init

# remove compiled contracts
rm -f build/!(os_latest.json)
