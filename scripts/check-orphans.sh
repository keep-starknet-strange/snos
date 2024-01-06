#!/bin/bash
cargo run --quiet --example hints orphans | jq -e 'if length == 0 then . else empty end'
if [ $? -ne '0' ]; then
  echo -e "orphaned hints found:"
  cargo run --quiet --example hints orphans | jq .
  exit 1
fi