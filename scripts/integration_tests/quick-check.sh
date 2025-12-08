#!/bin/bash
# script for easily running all tests
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
set -eux
bash $SCRIPT_DIR/run-tests.sh FIVE_NODES
bash $SCRIPT_DIR/run-tests.sh PAYMENTS_ETH
bash $SCRIPT_DIR/run-tests.sh PAYMENTS_ALTHEA
bash $SCRIPT_DIR/run-tests.sh MULTI_EXIT
bash $SCRIPT_DIR/run-tests.sh DEBTS
