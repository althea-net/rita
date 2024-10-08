#!/bin/bash
set -eux
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/../exit_trust_root
set +e
rm ../scripts/exit_trust_root
set -e
# set for target cpu of target machine
cross build --target x86_64-unknown-linux-musl -p exit_trust_root --bin exit_trust_root
cp ../target/x86_64-unknown-linux-musl/debug/exit_trust_root ../scripts
popd

pushd $DIR
ansible-playbook -i hosts  deploy-exit-root-server.yml
popd
