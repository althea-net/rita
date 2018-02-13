#!/usr/bin/env bash
set -euo pipefail

cd $(dirname $0)

build_babel () {
  if [ ! -d "deps/babeld" ] ; then
      git clone -b althea "https://github.com/althea-mesh/babeld" "deps/babeld"
  fi

  pushd deps/babeld
  make
  popd
}

get_python_deps () {
  sudo pip3 install -r requirements.txt
}

fetch_netlab () {
  if [ ! -d "deps/network-lab" ] ; then
    git clone "https://github.com/kingoflolz/network-lab" "deps/network-lab" # TODO: Change this back when PR is upstreamed
  fi

  chmod 777 deps/network-lab deps/network-lab/network-lab.sh
}

build_rita () {
  pushd ../rita
  cargo build
  popd
}

build_bounty () {
  pushd ../bounty_hunter
  cargo build
  rm -rf test.db
  diesel migration run
  rm -rf ../integration-tests/test.db
  cp test.db ../integration-tests/test.db
  popd
}

get_python_deps
fetch_netlab
build_babel
build_rita
build_bounty

sudo python3 rita.py