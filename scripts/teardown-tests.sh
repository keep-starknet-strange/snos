#!/bin/bash

shopt -s extglob

echo -e "\ncleaning cairo submodule...\n"
git submodule deinit -f .
git submodule update --init

# remove compiled contracts
echo -e "\nremoving compiled contracts/programs...\n"
rm starkware
rm -rf build/!(os_latest.json)
rm -rf build/!(os_latest.json.gz)
