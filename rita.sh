#!/usr/bin/env bash
set -euo pipefail

cd ../babeld
make
make install

cd ../rita
cargo build

cd ../integration-tests

network_lab=./deps/network-lab/network-lab.sh

babeld=../babeld/babeld
rita=../rita/target/debug/rita

# This is a basic integration test for the Althea fork of Babeld, it focuses on
# validating that instances actually come up and communicate

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root :("
   exit 1
fi

fail_string()
{
 if grep -q "$1" "$2"; then
   echo "FAILED: $1 in $2"
   exit 1
 fi
}

pass_string()
{
 if ! grep -q "$1" "$2"; then
   echo "FAILED: $1 not in $2"
   exit 1
 fi
}

stop_babel()
{
  set +eux
    for f in babeld-*.pid
    do
      echo "Processing $f file..."
      # take action on each file. $f store current file name
      kill -9 "$(cat $f)"
    done
  set -eux
}

cleanup()
{
  rm -f babeld-n*
}

stop_babel
cleanup

source $network_lab << EOF
{
  "nodes": {
    "1": { "ip": "1.0.0.1" },
    "2": { "ip": "1.0.0.2" },
    "3": { "ip": "1.0.0.3" }  

},
  "edges": [
     {
      "nodes": ["1", "2"],
      "->": "loss random 0%",
      "<-": "loss random 0%"
     },
     {
      "nodes": ["2", "3"],
      "->": "loss random 0%",
      "<-": "loss random 0%"
     }
  ]
}
EOF



ip netns exec netlab-1 sysctl -w net.ipv4.ip_forward=1
ip netns exec netlab-1 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec netlab-1 ip link set up lo
ip netns exec netlab-1 $babeld -I babeld-n1.pid -d 1 -L babeld-n1.log -h 1 -P 5 -w veth-1-2 -G 8080 &

ip netns exec netlab-2 sysctl -w net.ipv4.ip_forward=1
ip netns exec netlab-2 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec netlab-2 ip link set up lo
ip netns exec netlab-2 $babeld -I babeld-n2.pid -d 1 -L babeld-n2.log -h 1 -P 10 -w veth-2-1 -w veth-2-3 -G 8080 &
RUST_BACKTRACE=1 ip netns exec netlab-2 $rita > rita-n2.log &

ip netns exec netlab-3 sysctl -w net.ipv4.ip_forward=1
ip netns exec netlab-3 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec netlab-3 ip link set up lo
ip netns exec netlab-3 $babeld -I babeld-n3.pid -d 1 -L babeld-n3.log -h 1 -P 1 -w veth-3-2 -G 8080 &

sleep 20

stop_babel

fail_string "malformed" "babeld-n1.log"
fail_string "malformed" "babeld-n2.log"
fail_string "malformed" "babeld-n3.log"
fail_string "unknown version" "babeld-n1.log"
fail_string "unknown version" "babeld-n2.log"
fail_string "unknown version" "babeld-n3.log"
pass_string "dev veth-1-2 reach" "babeld-n1.log"
pass_string "dev veth-2-1 reach" "babeld-n2.log"
pass_string "dev veth-2-3 reach" "babeld-n2.log"
pass_string "dev veth-3-2 reach" "babeld-n3.log"
pass_string "nexthop 1.0.0.2" "babeld-n1.log"
pass_string "nexthop 1.0.0.1" "babeld-n2.log"
pass_string "nexthop 1.0.0.3" "babeld-n2.log"
pass_string "nexthop 1.0.0.2" "babeld-n3.log"

cleanup

echo "$0 PASS"