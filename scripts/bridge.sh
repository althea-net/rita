#!/usr/bin/env bash
# this bridges a router into the integration test mesh

# ip link set enx000ec6a0b495 netns netlab-1
# ip netns exec netlab-1 ifconfig enx000ec6a0b495 up

ifconfig enp7s0f3u3u2u1 down
dhclient enp7s0f3u3u2u1
ip route delete default dev enp7s0f3u3u2u1
ifconfig enp7s0f3u3u2u1 up