#!/usr/bin/env bash
set -euo pipefail

cd $(dirname $0)

build_babel () {
  rm -rf "deps/babeld"
  git clone -b althea "https://github.com/drozdziak1/babeld" "deps/babeld"

  pushd deps/babeld
  git checkout code-cleanup

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

  chmod +x deps/network-lab deps/network-lab/network-lab.sh
}

build_rita () {
  pushd ../rita
  cargo build --all
  popd
  pushd ../exit_db
  rm -rf test.db
  diesel migration run
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

if [ ! -z "${BUILD_BABELD-}" ]; then
    build_babel
fi

build_rita
build_bounty

pwd
sudo python3 rita.py "$@"