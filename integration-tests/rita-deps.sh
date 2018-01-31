#!/usr/bin/env bash
set -euo pipefail

build_babel () {
  if [ ! -d "deps/babeld" ] ; then
      git clone -b althea "https://github.com/althea-mesh/babeld" "deps/babeld"
  fi

  pushd deps/babeld
  make
  popd
}

fetch_netlab () {
  if [ ! -d "deps/network-lab" ] ; then
    git clone "https://github.com/kingoflolz/network-lab" "deps/network-lab" # TODO: Change this back when PR is upstreamed
  fi
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
  popd
}

fetch_netlab
build_babel
build_rita
build_bounty