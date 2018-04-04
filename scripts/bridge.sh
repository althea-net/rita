#!/usr/bin/env bash
# this bridges a router into the integration test mesh

ip link set enx000ec6a0b495 netns netlab-1
ip netns exec netlab-1 ifconfig enx000ec6a0b495 up

ifconfig enx001cc2330150 down
dhclient enx001cc2330150
ip route delete default dev enx001cc2330150
ifconfig enx001cc2330150 up