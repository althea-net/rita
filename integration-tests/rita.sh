#!/usr/bin/env bash
BABELD_DIR="deps/babeld"
NETLAB_PATH="deps/network-lab/network-lab.sh"

REMOTE_A=${REMOTE_A:=https://github.com/althea-mesh/althea_rs.git}
REVISION_A=${REVISION_A:=master}
DIR_A=${DIR_A:=althea_rs_a} # Don't override without good reason, this one and $DIR_B are git ignored

REMOTE_B=${REMOTE_B:=$REMOTE_A}
REVISION_B=${REVISION_B:=release}
DIR_B=${DIR_B:=althea_rs_b}

set -euxo pipefail

cd $(dirname $0) # Make the script runnable from anywhere

build_rev() {
  remote=$1
  revision=$2
  dir=$3

  if [ -z "${NO_PULL-}" ] ; then
    rm -rf $dir
    git clone $remote $dir
  fi

  pushd $dir

    git checkout $revision

    cargo build --all

    # Exit database
    pushd exit_db
      rm -rf test.db
      diesel migration run
    popd

    # Bounty hunter database
    pushd bounty_hunter
      rm -rf test.db
      diesel migration run
    popd

  popd

  cp $dir/bounty_hunter/test.db .
}

sudo pip3 install -r requirements.txt

if [ ! -f "${NETLAB_PATH-}" ] ; then
  git clone "https://github.com/kingoflolz/network-lab" "deps/network-lab" # TODO: Change this back when PR is upstreamed
fi

chmod +x deps/network-lab deps/network-lab/network-lab.sh

# Build Babel if not built
if [ ! -f "${BABELD_DIR-}/babeld" ]; then
  rm -rf $BABELD_DIR
  git clone -b master https://github.com/althea-mesh/babeld.git $BABELD_DIR
  make -C $BABELD_DIR
fi


# Only care about revisions if a compat layout was picked
if [ ! -z "${COMPAT_LAYOUT-}" ] ; then
  build_rev $REMOTE_A $REVISION_A $DIR_A
  export RITA_A="$DIR_A/target/debug/rita"
  export RITA_EXIT_A="$DIR_A/target/debug/rita_exit"
  export BOUNTY_HUNTER_A="$DIR_A/target/debug/bounty_hunter"


  build_rev $REMOTE_B $REVISION_B $DIR_B
  export RITA_B="$DIR_B/target/debug/rita"
  export RITA_EXIT_B="$DIR_B/target/debug/rita_exit"
  export BOUNTY_HUNTER_B="$DIR_B/target/debug/bounty_hunter"
else
  pushd ..
    cargo build --all

    pushd exit_db
      rm -rf test.db
      diesel migration run
    popd

    pushd bounty_hunter
      rm -rf test.db
      diesel migration run
    popd
  popd

  cp ../bounty_hunter/test.db .
fi

sudo -E python3 rita.py $@
