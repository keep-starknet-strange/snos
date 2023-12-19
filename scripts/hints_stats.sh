#!/bin/bash

ALL=`cargo run --quiet --bin hints all | jq length`
WHITELISTED=`cargo run --quiet --bin hints whitelisted | jq length`
SNOS=`cargo run --quiet --bin hints snos | jq length`
IMPLEMENTED=`cargo run --quiet --bin hints implemented | jq length`
UNIMPLEMENTED=`cargo run --quiet --bin hints unimplemented | jq length`
ORPHANS=`cargo run --quiet --bin hints orphans | jq length`

echo 'Snos hints stats'
echo 'all:' $ALL
echo 'implemented:' $IMPLEMENTED
echo '  whitelisted:' $WHITELISTED
echo '  snos:' $SNOS
echo 'unimplemented:' $UNIMPLEMENTED
echo 'orphans:' $ORPHANS