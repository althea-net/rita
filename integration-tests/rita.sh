#!/usr/bin/env bash
set -euo pipefail

cd $(dirname $0)

./rita-deps.sh
sudo python3 rita.py