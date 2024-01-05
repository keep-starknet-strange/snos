#!/bin/bash

ALL=`cargo run --quiet --example hints all | jq length`
EXTERNALLY=`cargo run --quiet --example hints implemented_externally | jq length`
SNOS=`cargo run --quiet --example hints implemented_in_snos | jq length`
IMPLEMENTED=`cargo run --quiet --example hints implemented | jq length`
UNIMPLEMENTED=`cargo run --quiet --example hints unimplemented | jq length`
ORPHANS=`cargo run --quiet --example hints orphans | jq length`

echo 'Snos hints stats'
echo 'all:' $ALL
echo 'implemented:' $IMPLEMENTED
echo '  externally:' $EXTERNALLY
echo '  snos:' $SNOS
echo 'unimplemented:' $UNIMPLEMENTED
echo 'orphans:' $ORPHANS