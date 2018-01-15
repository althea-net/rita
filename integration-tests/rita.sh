#!/usr/bin/env bash
set -euo pipefail


build_babel () {
  if [ ! -d "./babeld" ] ; then
      git clone -b althea "https://github.com/althea-mesh/babeld" "./babeld"
  fi

  cd ./babeld
  make
  make install
  cd ../
}

build_rita () {
  cd ../rita
  cargo build
  cd ../integration-tests
}

network_lab=./deps/network-lab/network-lab.sh
babeld=./babeld/babeld
rita=../rita/target/debug/rita


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

stop_processes()
{
  set +eux
    for f in *.pid
    do
      kill -9 "$(cat $f)"
    done
    killall ping6
  set -eux
}

cleanup()
{
  rm -f ./*.pid
  rm -f ./*.log
}

build_babel
build_rita

stop_processes
cleanup

source $network_lab << EOF
{
  "nodes": {
    "1": { "ip": "2001::1" },
    "2": { "ip": "2001::2" },
    "3": { "ip": "2001::3" }  

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

prep_netns () {
  ip netns exec "$1" sysctl -w net.ipv4.ip_forward=1
  ip netns exec "$1" sysctl -w net.ipv6.conf.all.forwarding=1
  ip netns exec "$1" ip link set up lo
}

create_bridge () {
  ip netns exec "$1" brctl addbr "br-$2"
  ip netns exec "$1" brctl addif "br-$2" "veth-$2"
  ip netns exec "$1" ip link set up "br-$2"
  ip netns exec "$1" ip addr add 2001::2 dev "br-$2"
}

prep_netns netlab-1
ip netns exec netlab-1 $babeld -I babeld-n1.pid -d 1 -L babeld-n1.log -h 1 -P 5 -w veth-1-2 -G 8080 &
ip netns exec netlab-1 bash -c 'failed=1
                            while [ $failed -ne 0 ]
                            do
                              ping6 -n -s 1400 2001::3 &> ping.log
                              failed=$?
                              sleep 1
                            done' &
ip netns exec netlab-1 echo $! > ping_retry.pid

prep_netns netlab-2
create_bridge netlab-2 2-1 2001::2
create_bridge netlab-2 2-3 2001::2
ip netns exec netlab-2 $babeld -I babeld-n2.pid -d 1 -L babeld-n2.log -h 1 -P 10 -w br-2-1 br-2-3 -G 8080 &
RUST_BACKTRACE=full ip netns exec netlab-2 $rita --pid rita-n2.pid &> rita-n2.log &
ip netns exec netlab-2 brctl show

prep_netns netlab-3
ip netns exec netlab-3 $babeld -I babeld-n3.pid -d 1 -L babeld-n3.log -h 1 -P 1 -w veth-3-2 -G 8080 &

sleep 20

ip netns exec netlab-2 ip r

sleep 2

stop_processes

sleep 1

fail_string "malformed" "babeld-n1.log"
fail_string "malformed" "babeld-n2.log"
fail_string "malformed" "babeld-n3.log"
fail_string "unknown version" "babeld-n1.log"
fail_string "unknown version" "babeld-n2.log"
fail_string "unknown version" "babeld-n3.log"
pass_string "dev veth-1-2 reach" "babeld-n1.log"
pass_string "dev br-2-1 reach" "babeld-n2.log"
pass_string "dev br-2-3 reach" "babeld-n2.log"
pass_string "dev veth-3-2 reach" "babeld-n3.log"
pass_string "2001::3\/128.*via veth-1-2" "babeld-n1.log"
pass_string "2001::1\/128.*via br-2-1" "babeld-n2.log"
pass_string "2001::3\/128.*via br-2-3" "babeld-n2.log"
pass_string "2001::2\/128.*via veth-3-2" "babeld-n3.log"

pass_string "destination: V6(2001::3), bytes: 7240" "rita-n2.log"
pass_string "destination: V6(2001::1), bytes: 7240" "rita-n2.log"
pass_string "Calculated neighbor debt. price: 11, debt: 79640" "rita-n2.log"
pass_string "Calculated neighbor debt. price: 15, debt: 108600" "rita-n2.log"
pass_string "prefix: V6(Ipv6Network { network_address: 2001::1, netmask: 128 })" "rita-n2.log"
pass_string "prefix: V6(Ipv6Network { network_address: 2001::3, netmask: 128 })" "rita-n2.log"

echo "$0 PASS"