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
import random
import networkx as nx
import matplotlib.pyplot as plt
import multiprocessing

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
from joblib import Parallel, delayed


# find our own file, then go up one level
abspath = os.path.abspath(__file__)
dname = os.path.dirname(os.path.dirname(abspath))
os.chdir(dname)

NETWORK_LAB = os.path.join(dname, 'deps/network-lab/network-lab.sh')
BABELD = os.path.join(dname, 'deps/babeld/babeld')

RITA_DEFAULT = os.path.join(dname, '../target/release/rita')
RITA_EXIT_DEFAULT = os.path.join(dname, '../target/release/rita_exit')

# Envs for controlling postgres
POSTGRES_USER = os.getenv('POSTGRES_USER')
INITDB_BIN = os.getenv('INITDB_BIN')
POSTGRES_BIN = os.getenv('POSTGRES_BIN')
POSTGRES_CONFIG = os.getenv('POSTGRES_CONFIG')
POSTGRES_DATABASE = os.getenv('POSTGRES_DATABASE')

# Envs for controlling compat testing
RITA_A = os.getenv('RITA_A', RITA_DEFAULT)
RITA_EXIT_A = os.getenv('RITA_EXIT_A', RITA_EXIT_DEFAULT)
DIR_A = os.getenv('DIR_A', 'althea_rs_a')
RITA_B = os.getenv('RITA_B', RITA_DEFAULT)
RITA_EXIT_B = os.getenv('RITA_EXIT_B', RITA_EXIT_DEFAULT)
DIR_B = os.getenv('DIR_B', 'althea_rs_b')

# Current binary paths (They change to *_A or *_B depending on which node is
# going to be run at a given moment, according to the layout)
RITA = RITA_DEFAULT
RITA_EXIT = RITA_EXIT_DEFAULT

# COMPAT_LAYOUTS[None] sets everything to *_A
COMPAT_LAYOUT = os.getenv('COMPAT_LAYOUT', None)

BACKOFF_FACTOR = float(os.getenv('BACKOFF_FACTOR', 1))
CONVERGENCE_DELAY = float(os.getenv('CONVERGENCE_DELAY', 600))
DEBUG = os.getenv('DEBUG') is not None
INITIAL_POLL_INTERVAL = float(os.getenv('INITIAL_POLL_INTERVAL', 10))
PING6 = os.getenv('PING6', 'ping6')
VERBOSE = os.getenv('VERBOSE', None)
NODES = os.getenv('NODES', None)

# bandwidth test vars
# in seconds
TIME = int(os.getenv('SPEEDTEST_DURATION'))
# in Mbit/s
SPEED = int(os.getenv('SPEEDTEST_THROUGHPUT'))

TEST_PASSES = True

EXIT_SETTINGS = {
    "new_exits": {
        "exit_a": {
            "root_ip": "fd00::5",
            "id": {
                "mesh_ip": "fd00::5",
                "eth_address": "0xbe398dc24de37c73cec974d688018e58f94d6e0a",
                "wg_public_key": "H/ABwzXk834OwGYU8CZGfFxNZOd+BAJEaVDHiEiWWhU=",
            },
            "eth_address": "0xbe398dc24de37c73cec974d688018e58f94d6e0a",
            "wg_public_key": "H/ABwzXk834OwGYU8CZGfFxNZOd+BAJEaVDHiEiWWhU=",
            "althea_address": "althea11lrsu892mqx2mndyvjufrh2ux56tyfxl2e3eht3",
            "registration_port": 4875,
            "state": "New",
        }
    },
    "current_exit": "exit_a",
    "wg_listen_port": 59999,
}

EXIT_SELECT = {
    "new_exits": {
        "exit_a": {
            "state": "Registering",
        }
    },
}


def setup_arbitrary_node_config(nodes):
    """Generates an arbitrarily sized test network"""
    COMPAT_LAYOUTS = {
        None: ['a'] * nodes
    }
    world = World()
    for n in range(nodes):
        node = Node(n, random.randint(0, 500), COMPAT_LAYOUT, COMPAT_LAYOUTS)
        if n == 5:
            world.add_exit_node(node)
        else:
            world.add_node(node)

    # generates graphs with small world properties, as such it simulates micropops well
    # https://en.wikipedia.org/wiki/Watts%E2%80%93Strogatz_model
    ws = nx.connected_watts_strogatz_graph(
        nodes, random.randint(2, int(nodes/4)), 0.1)
    nx.draw(ws)
    plt.savefig("graph.png")

    # associate the nodes list with it's generated prices with
    # the networkx graph and it's generated topolgoy
    for graph_node, rita_node in zip(ws.nodes, world.nodes):
        print("Associating {} with {}".format(graph_node, rita_node))
        neighbors = get_neighbors(graph_node, ws.edges)
        if len(neighbors) == 0:
            print("Disconnected node!")
            exit(1)

        rita_node = world.nodes[rita_node]
        graph_node = ws[graph_node]
        graph_node = {
            "weight": rita_node.local_fee, "id": rita_node.id}

        for neighbor in neighbors:
            world.add_connection(Connection(rita_node, world.nodes[neighbor]))

    # generate the all_routes list of routes to use for testing
    all_routes = {}
    for rita_node in world.nodes:
        rita_node = world.nodes[rita_node]
        all_routes[rita_node] = []
        for n in world.nodes:
            (next_hop, cost) = next_hop_and_cost(ws, rita_node.id, n, world)
            next_hop = world.nodes[next_hop]
            n = world.nodes[n]
            all_routes[rita_node].append((n, cost, next_hop))

    traffic_test_pairs = []
    for _ in range(10):
        index_a = random.randint(0, nodes - 1)
        index_b = random.randint(0, nodes - 1)
        if index_a == index_b:
            continue
        a = world.nodes[index_a]
        b = world.nodes[index_b]
        traffic_test_pairs.append((a, b))

    EXIT_NAMESPACE = "netlab-{}".format(world.exit_id)
    EXIT_ID = world.exit_id

    GATEWAY_NAMESPACE = "netlab-0"
    GATEWAY_ID = 0

    return (COMPAT_LAYOUTS, all_routes, traffic_test_pairs, world, EXIT_NAMESPACE, EXIT_ID, GATEWAY_NAMESPACE, GATEWAY_ID)


def get_neighbors(node, ajacency_list):
    """Networkx only provides the very large adjaceny list, this filters that down"""
    neighs = set()
    for (a, b) in ajacency_list:
        if a == node:
            neighs.add(b)
        elif b == node:
            neighs.add(a)
    return neighs


def next_hop_and_cost(graph, start, finish, world):
    """Returns the path cost computed in the Althea style"""
    path = nx.dijkstra_path(graph, start, finish)
    cost = 0
    for node in path:
        if node == start or node == finish:
            continue
        print(world.nodes)
        cost += world.nodes[node].local_fee
    if len(path) == 1:
        return (path[0], 0)
    if len(path) >= 2:
        print(path)
        return (path[1], cost)


def setup_seven_node_config():
    COMPAT_LAYOUTS = {
        None: ['a'] * 7,  # Use *_A binaries for every node
        'old_exit': ['a'] * 4 + ['b'] + ['a'] * 2,  # The exit sports Rita B
        'new_exit': ['b'] * 4 + ['a'] + ['b'] * 2,  # Like above but opposite
        'inner_ring_old': ['a', 'b', 'b', 'a', 'a', 'b', 'b'],
        'inner_ring_new': ['b', 'a', 'a', 'b', 'b', 'a', 'a'],
        'random':   None,  # Randomize revisions used (filled at runtime)
    }

    a1 = Node(1, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    b2 = Node(2, 25, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    c3 = Node(3, 60, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    d4 = Node(4, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    e5 = Node(5, 0, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    f6 = Node(6, 50, COMPAT_LAYOUT, COMPAT_LAYOUTS)
    g7 = Node(7, 10, COMPAT_LAYOUT, COMPAT_LAYOUTS)

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

    world.add_connection(Connection(a1, f6))
    world.add_connection(Connection(f6, g7))
    world.add_connection(Connection(c3, g7))
    world.add_connection(Connection(b2, c3))
    world.add_connection(Connection(b2, f6))
    world.add_connection(Connection(b2, d4))
    world.add_connection(Connection(e5, g7))

    traffic_test_pairs = [(c3, f6), (d4, a1), (a1, c3), (d4, e5),
                          (e5, d4), (c3, e5), (e5, c3), (g7, e5), (e5, g7)]

    nodes = world.nodes

    all_routes = {
        nodes[1]: [
            (nodes[2], 50, nodes[6]),
            (nodes[3], 60, nodes[6]),
            (nodes[4], 75, nodes[6]),
            (nodes[5], 60, nodes[6]),
            (nodes[6], 0, nodes[6]),
            (nodes[7], 50, nodes[6]),
        ],
        nodes[2]: [
            (nodes[1], 50, nodes[6]),
            (nodes[3], 0, nodes[3]),
            (nodes[4], 0, nodes[4]),
            (nodes[5], 60, nodes[6]),
            (nodes[6], 0, nodes[6]),
            (nodes[7], 50, nodes[6]),
        ],
        nodes[3]: [
            (nodes[1], 60, nodes[7]),
            (nodes[2], 0, nodes[2]),
            (nodes[4], 25, nodes[2]),
            (nodes[5], 10, nodes[7]),
            (nodes[6], 10, nodes[7]),
            (nodes[7], 0, nodes[7]),
        ],
        nodes[4]: [
            (nodes[1], 75, nodes[2]),
            (nodes[2], 0, nodes[2]),
            (nodes[3], 25, nodes[2]),
            (nodes[5], 85, nodes[2]),
            (nodes[6], 25, nodes[2]),
            (nodes[7], 75, nodes[2]),
        ],
        nodes[5]: [
            (nodes[1], 60, nodes[7]),
            (nodes[2], 60, nodes[7]),
            (nodes[3], 10, nodes[7]),
            (nodes[4], 85, nodes[7]),
            (nodes[6], 10, nodes[7]),
            (nodes[7], 0, nodes[7]),
        ],
        nodes[6]: [
            (nodes[1], 0, nodes[1]),
            (nodes[2], 0, nodes[2]),
            (nodes[3], 10, nodes[7]),
            (nodes[4], 25, nodes[2]),
            (nodes[5], 10, nodes[7]),
            (nodes[7], 0, nodes[7]),
        ],
        nodes[7]: [
            (nodes[1], 50, nodes[6]),
            (nodes[2], 50, nodes[6]),
            (nodes[3], 0, nodes[3]),
            (nodes[4], 75, nodes[6]),
            (nodes[5], 0, nodes[5]),
            (nodes[6], 0, nodes[6]),
        ],
    }

    EXIT_NAMESPACE = "netlab-5"
    EXIT_ID = 5

    GATEWAY_NAMESPACE = "netlab-7"
    GATEWAY_ID = 7

    return (COMPAT_LAYOUTS, all_routes, traffic_test_pairs, world, EXIT_NAMESPACE, EXIT_ID, GATEWAY_NAMESPACE, GATEWAY_ID)


def main():
    if NODES is None or 'None' in NODES:
        nodes = 7
        (COMPAT_LAYOUTS, all_routes, traffic_test_pairs,
         world, EXIT_NAMESPACE, EXIT_ID, GATEWAY_NAMESPACE, GATEWAY_ID) = setup_seven_node_config()
    else:
        nodes = int(NODES)
        (COMPAT_LAYOUTS, all_routes, traffic_test_pairs,
         world, EXIT_NAMESPACE, EXIT_ID, GATEWAY_NAMESPACE, GATEWAY_ID) = setup_arbitrary_node_config(nodes)

    COMPAT_LAYOUTS["random"] = [
        'a' if random.randint(0, 1) else 'b' for _ in range(7)]

    if VERBOSE:
        print("Random compat test layout: {}".format(COMPAT_LAYOUTS["random"]))

    world.create(VERBOSE, COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA, RITA_EXIT, DIR_A, DIR_B, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B, NETWORK_LAB,
                 BABELD, POSTGRES_DATABASE, POSTGRES_USER, POSTGRES_CONFIG, POSTGRES_BIN, INITDB_BIN, EXIT_NAMESPACE, EXIT_SETTINGS, dname)

    # in scale configuration we reduce some testing and otherwise reduce disk io
    scale_configuration = len(world.nodes) > 10

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
        all_reachable = world.test_reach_all(
            PING6, verbose=False, global_fail=False)
        # test all routes, but not in the case of a scale configuration since we
        # don't write out the logs in that case
        routes_ok = world.test_routes(
            all_routes, verbose=False, global_fail=False) or scale_configuration
        if all_reachable and routes_ok:
            break      # We converged!
        time.sleep(interval)  # Let's check again after a delay
        interval *= BACKOFF_FACTOR
        if VERBOSE is not None:
            print("%.2fs/%.2fs (going to sleep for %.2fs)" %
                  (time.time() - start_time, CONVERGENCE_DELAY, interval))

    print("Test reachability and optimum routes...")

    duration = time.time() - start_time

    # Test (and fail if necessary) for real and print stats on success if we are in a scale
    # configuration don't test routes. The route dumping produces disk load that's not possible
    # to deal with above a few nodes
    if world.test_reach_all(PING6) and (scale_configuration or world.test_routes(all_routes)):
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
    time.sleep(15)

    for k, v in world.nodes.items():
        if k != world.exit_id:
            email_verif(v)

    time.sleep(15)

    world.test_endpoints_all(VERBOSE)

    if DEBUG:
        print("Debug mode active, examine the mesh and press y to continue " +
              "with the tests or anything else to exit")
        choice = input()
        if choice != 'y':
            sys.exit(0)

    world.test_exit_reach_all(global_fail=True)

    world.test_traffic(traffic_test_pairs, TIME, SPEED)

    # wait a few seconds after traffic generation for all nodes to update their debts
    time.sleep(10)
    traffic = world.get_debts()
    print("Test post-traffic balance agreement...")
    world.test_debts_reciprocal_matching(traffic)
    world.test_debts_values(traffic_test_pairs, TIME,
                            SPEED, traffic, all_routes, EXIT_ID, world.exit_price)

    print("Check that tunnels have not been suspended")

    for id in world.nodes:
        assert_test(not check_log_contains("rita-n{}.log".format(id),
                                           "suspending forwarding"), "Suspension of {}".format(id))

    # we reduce logging when doing larger tests and this check isn't possible.
    if len(world.nodes) < 10:
        assert_test(check_log_contains("rita-n{}.log".format(GATEWAY_ID),
                                       "We are a gateway!, Acting accordingly"), "Successful gateway/exit detection")

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
