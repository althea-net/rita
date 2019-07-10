#!/usr/bin/python3

from pprint import pprint
from termcolor import colored

import errno
import json
import os
import random
import re
import shlex
import signal
import subprocess
import sys
import time
import toml

from connection import Connection 
from utils import exec_or_exit
from utils import exec_no_exit
from utils import get_rita_defaults
from utils import save_rita_settings
from utils import get_rita_exit_defaults
from utils import assert_test
from utils import register_to_exit
from utils import email_verif
from utils import teardown
from utils import check_log_contains
from world import World
from node import Node 

# find our own file, then go up one level
abspath = os.path.abspath(__file__)
dname = os.path.dirname(os.path.dirname(abspath))
os.chdir(dname)

EXIT_NAMESPACE="netlab-5"

NETWORK_LAB = os.path.join(dname, 'deps/network-lab/network-lab.sh')
BABELD = os.path.join(dname, 'deps/babeld/babeld')

RITA_DEFAULT = os.path.join(dname, '../target/debug/rita')
RITA_EXIT_DEFAULT = os.path.join(dname, '../target/debug/rita_exit')
BOUNTY_HUNTER_DEFAULT = os.path.join(dname, '/tmp/bounty_hunter/target/debug/bounty_hunter')

# Envs for controlling postgres
POSTGRES_USER = os.getenv('POSTGRES_USER')
INITDB_BIN = os.getenv('INITDB_BIN')
POSTGRES_BIN = os.getenv('POSTGRES_BIN')
POSTGRES_CONFIG = os.getenv('POSTGRES_CONFIG')
POSTGRES_DATABASE = os.getenv('POSTGRES_DATABASE')

# Envs for controlling compat testing
RITA_A = os.getenv('RITA_A', RITA_DEFAULT)
RITA_EXIT_A = os.getenv('RITA_EXIT_A', RITA_EXIT_DEFAULT)
BOUNTY_HUNTER_A = os.getenv('BOUNTY_HUNTER_A', BOUNTY_HUNTER_DEFAULT)
DIR_A = os.getenv('DIR_A', 'althea_rs_a')
RITA_B = os.getenv('RITA_B', RITA_DEFAULT)
RITA_EXIT_B = os.getenv('RITA_EXIT_B', RITA_EXIT_DEFAULT)
BOUNTY_HUNTER_B = os.getenv('BOUNTY_HUNTER_B', BOUNTY_HUNTER_DEFAULT)
DIR_B = os.getenv('DIR_B', 'althea_rs_b')

# Current binary paths (They change to *_A or *_B depending on which node is
# going to be run at a given moment, according to the layout)
RITA = RITA_DEFAULT
RITA_EXIT = RITA_EXIT_DEFAULT
BOUNTY_HUNTER = BOUNTY_HUNTER_DEFAULT

# COMPAT_LAYOUTS[None] sets everything to *_A
COMPAT_LAYOUT = os.getenv('COMPAT_LAYOUT', None)

BACKOFF_FACTOR = float(os.getenv('BACKOFF_FACTOR', 1))
CONVERGENCE_DELAY = float(os.getenv('CONVERGENCE_DELAY', 50))
DEBUG = os.getenv('DEBUG') is not None
INITIAL_POLL_INTERVAL = float(os.getenv('INITIAL_POLL_INTERVAL', 1))
PING6 = os.getenv('PING6', 'ping6')
VERBOSE = os.getenv('VERBOSE', None)

TEST_PASSES = True

EXIT_SETTINGS = {
    "exits": {
        "exit_a": {
            "id": {
                "mesh_ip": "fd00::5",
                "eth_address": "0x0101010101010101010101010101010101010101",
                "wg_public_key": "fd00::5",
            },
            "registration_port": 4875,
            "state": "New"
        }
    },
    "current_exit": "exit_a",
    "wg_listen_port": 59999,
    "reg_details": {
        "zip_code": "1234",
        "email": "1234@gmail.com"
    }
}

EXIT_SELECT = {
    "exits": {
        "exit_a": {
            "state": "Registering",
        }
    },
}

COMPAT_LAYOUTS = {
        None: ['a'] * 7,  # Use *_A binaries for every node
        'old_exit': ['a'] * 4 + ['b'] + ['a'] * 2,  # The exit sports Rita B
        'new_exit': ['b'] * 4 + ['a'] + ['b'] * 2,  # Like above but opposite
        'inner_ring_old': ['a', 'b', 'b', 'a', 'a', 'b', 'b'],
        'inner_ring_new': ['b', 'a', 'a', 'b', 'b', 'a', 'a'],
        'random':   None,  # Randomize revisions used (filled at runtime)
        }


def main():
    COMPAT_LAYOUTS["random"] = ['a' if random.randint(0, 1) else 'b' for _ in range(7)]

    if VERBOSE:
        print("Random compat test layout: {}".format(COMPAT_LAYOUTS["random"]))

    a1 = Node(1, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    b2 = Node(2, 25, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    c3 = Node(3, 60, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    d4 = Node(4, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    e5 = Node(5, 0, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    f6 = Node(6, 50, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    g7 = Node(7, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    # h8 = Node(8, 0)

    # Note: test_routes() relies heavily on this node and price layout not to
    # change. If you need to alter the test mesh, please update test_routes()
    # accordingly
    world = World()
    world.add_node(a1)
    world.add_node(b2)
    world.add_node(c3)
    world.add_node(d4)
    world.add_exit_node(e5)
    world.add_node(f6)
    world.add_node(g7)
    # world.add_external_node(h8)

    world.add_connection(Connection(a1, f6))
    world.add_connection(Connection(f6, g7))
    world.add_connection(Connection(c3, g7))
    world.add_connection(Connection(b2, c3))
    world.add_connection(Connection(b2, f6))
    world.add_connection(Connection(b2, d4))
    world.add_connection(Connection(e5, g7))
    # world.add_connection(Connection(e5, h8))

    world.set_bounty(3)  # TODO: Who should be the bounty hunter?

    world.create(VERBOSE, COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA, RITA_EXIT, BOUNTY_HUNTER, DIR_A, DIR_B, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B, BOUNTY_HUNTER_A, BOUNTY_HUNTER_B, NETWORK_LAB, BABELD, POSTGRES_DATABASE, POSTGRES_USER, POSTGRES_CONFIG, POSTGRES_BIN, INITDB_BIN, EXIT_NAMESPACE, EXIT_SETTINGS, dname)

    print("Waiting for network to stabilize")
    start_time = time.time()

    interval = INITIAL_POLL_INTERVAL

    if DEBUG:
        print("Debug mode active, examine the mesh and press y to continue " +
              "with the tests or anything else to exit")
        choice = input()
        if choice != 'y':
            sys.exit(0)

    # While we're before convergence deadline
    while (time.time() - start_time) <= CONVERGENCE_DELAY:
        all_reachable = world.test_reach_all(PING6, verbose=False, global_fail=False)
        routes_ok = world.test_routes(verbose=False, global_fail=False)
        if all_reachable and routes_ok:
            break      # We converged!
        time.sleep(interval)  # Let's check again after a delay
        interval *= BACKOFF_FACTOR
        if VERBOSE is not None:
            print("%.2fs/%.2fs (going to sleep for %.2fs)" %
                  (time.time() - start_time, CONVERGENCE_DELAY, interval))

    print("Test reachabibility and optimum routes...")
    time.sleep(120)

    duration = time.time() - start_time

    # Test (and fail if necessary) for real and print stats on success
    if world.test_reach_all(PING6) and world.test_routes():
        print(("Converged in " + colored("%.2f seconds", "green")) % duration)
    else:
        print(("No convergence after more than " +
        colored("%d seconds", "red") +
        ", quitting...") % CONVERGENCE_DELAY)
        sys.exit(1)

    print("Waiting for clients to get info from exits")
    time.sleep(5)

    for k, v in world.nodes.items():
        if k != world.exit_id:
            register_to_exit(v)

    print("waiting for emails to be sent")
    time.sleep(16)

    for k, v in world.nodes.items():
        if k != world.exit_id:
            email_verif(v)

    world.test_endpoints_all(VERBOSE)

    if DEBUG:
        print("Debug mode active, examine the mesh and press y to continue " +
              "with the tests or anything else to exit")
        choice = input()
        if choice != 'y':
            sys.exit(0)

    world.test_traffic(c3, f6, {
        1: 0,
        2: 0,
        3: -10 * 1.05,
        4: 0,
        5: 0,
        6: 0 * 1.05,
        7: 10 * 1.05
    })

    world.test_traffic(d4, a1, {
        1: 0 * 1.05,
        2: 25 * 1.05,
        3: 0,
        4: -75 * 1.05,
        5: 0,
        6: 50 * 1.05,
        7: 0
    })

    world.test_traffic(a1, c3, {
        1: -60 * 1.05,
        2: 0,
        3: 0,
        4: 0,
        5: 0,
        6: 50 * 1.05,
        7: 10 * 1.05
    })

    world.test_traffic(d4, e5, {
        1: 0,
        2: 110 * 1.1,
        3: 0,
        4: -220 * 1.1,
        5: 50 * 1.1,
        6: 50 * 1.1,
        7: 10 * 1.1
    })

    world.test_traffic(e5, d4, {
        1: 0,
        2: 25 * 1.1,
        3: 0,
        4: -135 * 1.1,
        5: 50 * 1.1,
        6: 50 * 1.1,
        7: 10 * 1.1
    })

    world.test_traffic(c3, e5, {
        1: 0,
        2: 0,
        3: -60 * 1.1,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: 20 * 1.1
    })

    world.test_traffic(e5, c3, {
        1: 0,
        2: 0,
        3: -60 * 1.1,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: 10 * 1.1
    })

    world.test_traffic(g7, e5, {
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: -50 * 1.1
    })

    world.test_traffic(e5, g7, {
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: -50 * 1.1
    })

    print("Check that tunnels have not been suspended")

    assert_test(not check_log_contains("rita-n1.log", "suspending forwarding"), "Suspension of 1 (A)")
    assert_test(not check_log_contains("rita-n2.log", "suspending forwarding"), "Suspension of 2 (B)")
    assert_test(not check_log_contains("rita-n3.log", "suspending forwarding"), "Suspension of 3 (C)")
    assert_test(not check_log_contains("rita-n4.log", "suspending forwarding"), "Suspension of 4 (D)")
    assert_test(not check_log_contains("rita-n6.log", "suspending forwarding"), "Suspension of 6 (F)")
    assert_test(not check_log_contains("rita-n7.log", "suspending forwarding"), "Suspension of 7 (G)")

    if DEBUG:
        print("Debug mode active, examine the mesh after tests and press " +
              "Enter to exit")
        input()

    teardown()

    print("done... exiting")

    if TEST_PASSES:
        print("All Rita tests passed!!")
        exit(0)
    else:
        print("Rita tests have failed :(")
        exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt as e:
        print("Received interrupt, exitting")
        teardown()
