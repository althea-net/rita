#!/usr/bin/env bash
# export PATH="$PATH:$HOME/.cargo/bin"
BABELD_DIR="deps/babeld"
NETLAB_PATH="deps/network-lab/network-lab.sh"

REMOTE_A=${REMOTE_A:=https://github.com/althea-mesh/althea_rs.git}
REVISION_A=${REVISION_A:=master}
DIR_A=${DIR_A:=althea_rs_a} # Don't override without good reason, this one and $DIR_B are git ignored
TARGET_DIR_A=${TARGET_DIR_A:=target_a} # Don't override without good reason, this one and $TARGET_DIR_B are git ignored

REMOTE_B=${REMOTE_B:=$REMOTE_A}
REVISION_B=${REVISION_B:=release}
DIR_B=${DIR_B:=althea_rs_b}
TARGET_DIR_B=${TARGET_DIR_B:=target_b}

set -euxo pipefail

cd $(dirname $0) # Make the script runnable from anywhere

build_rev() {
  remote=$1
  revision=$2
  dir=$3
  target_dir=$4

  mkdir -p $target_dir

  if [ -z "${NO_PULL-}" ] ; then
    rm -rf $dir
    git clone $remote $dir
  fi

  pushd $dir
    git checkout $revision

    CARGO_TARGET_DIR="../$target_dir" cargo build --all --features guac
  popd
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
  build_rev $REMOTE_A $REVISION_A $DIR_A $TARGET_DIR_A
  export RITA_A="$target_dir/debug/rita"
  export RITA_EXIT_A="$target_dir/debug/rita_exit"
  export BOUNTY_HUNTER_A="$target_dir/debug/bounty_hunter"
  export DIR_A=$DIR_A

  # Save on common dep artifacts between A and B
  cp -r $TARGET_DIR_A $TARGET_DIR_B

  build_rev $REMOTE_B $REVISION_B $DIR_B $TARGET_DIR_B
  export RITA_B="$target_dir/debug/rita"
  export RITA_EXIT_B="$target_dir/debug/rita_exit"
  export BOUNTY_HUNTER_B="$target_dir/debug/bounty_hunter"
  export DIR_B=$DIR_B
else
  pushd ..
    cargo build --all --features guac
  popd
fi

sudo -E PATH="$PATH:$HOME/.cargo/bin" python3 rita.py $@
