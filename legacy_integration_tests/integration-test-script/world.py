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

from utils import cleanup
from utils import exec_or_exit
from utils import exec_no_exit
from utils import prep_netns
from utils import switch_binaries
from utils import start_rita_exit
from utils import start_rita
from utils import start_babel
from utils import get_rita_settings
from utils import assert_test
from utils import ip_to_num
from utils import num_to_ip
from utils import fuzzy_traffic_match
from utils import fuzzy_match


class World:
    def __init__(self):
        self.nodes = {}
        self.connections = {}
        self.bounty_id = None
        self.exit_id = None
        self.external = None

    def add_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node

    def add_exit_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node
        self.exit_id = node.id

    def add_external_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node
        self.external = node.id

    def add_connection(self, connection):
        connection.canonicalize()
        self.connections[(connection.a.id, connection.b.id)] = connection
        connection.a.add_neighbor(connection.b.id)
        connection.b.add_neighbor(connection.a.id)

    def to_ip(self, node):
        if self.exit_id == node.id:
            return "172.168.1.254"
        else:
            return "fd00::{}".format(node.id)

    def create(self, VERBOSE, COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA, RITA_EXIT, DIR_A, DIR_B, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B, NETWORK_LAB, BABELD, POSTGRES_DATABASE, POSTGRES_USER, POSTGRES_CONFIG, POSTGRES_BIN, INITDB_BIN, EXIT_NAMESPACE, EXIT_SETTINGS, dname):
        cleanup()
        # scale config modifies tests to reduce disk usage and disable
        # some infeasible tests to allow for larger numbers of nodes
        scale_configuration = len(self.nodes.items()) > 10

        nodes = {}
        for id in self.nodes:
            nodes[str(id)] = {"ip": num_to_ip(id)}

        edges = []

        for id, conn in self.connections.items():
            edges.append({
                "nodes": ["{}".format(conn.a.id), "{}".format(conn.b.id)],
                "->": "",
                "<-": ""
            })

        network = {"nodes": nodes, "edges": edges}

        network_string = json.dumps(network)

        print("network topology: {}".format(network))

        print(NETWORK_LAB)
        proc = subprocess.Popen(
            ['/bin/bash', NETWORK_LAB], stdin=subprocess.PIPE, universal_newlines=True)
        proc.stdin.write(network_string)
        proc.stdin.close()

        proc.wait()

        print("network-lab completed")

        for id in self.nodes:
            prep_netns(id)

        print("namespaces prepped")

        print("Starting postgres in exit namespace")
        if POSTGRES_DATABASE is not None:
            exec_or_exit("sudo ip netns exec {} sudo -u {} {} -D {} -c config_file={}".format(
                EXIT_NAMESPACE, POSTGRES_USER, POSTGRES_BIN, POSTGRES_DATABASE, POSTGRES_CONFIG), False)
            time.sleep(30)
        else:
            exec_no_exit("sudo ip netns exec {} sudo -u {} PGDATA=/var/lib/postgresql/data {} --no-locale".format(
                EXIT_NAMESPACE, POSTGRES_USER, INITDB_BIN), True)
            exec_or_exit("sudo ip netns exec {} sudo -u {} PGDATA=/var/lib/postgresql/data {}".format(
                EXIT_NAMESPACE, POSTGRES_USER, POSTGRES_BIN), False)
            time.sleep(30)

        exec_no_exit("psql -c 'drop database test;' -U postgres", True)
        exec_no_exit("psql -c 'create database test;' -U postgres", True)

        print("Perform initial database migrations")
        exec_or_exit('sudo ip netns exec {} diesel migration run --database-url="postgres://postgres@localhost/test" --migration-dir=../exit_db/migrations'.format(EXIT_NAMESPACE))

        # redo the migration so that we can run several times
        exec_or_exit('sudo ip netns exec {} diesel migration redo --database-url="postgres://postgres@localhost/test" --migration-dir=../exit_db/migrations'.format(EXIT_NAMESPACE))

        print("starting babel")

        # if this is set to zero route checking won't work
        # but it will reduce logging pressure in large networks
        log = "1"
        scale = False
        if scale_configuration:
            log = "0"
        for id, node in self.nodes.items():
            start_babel(node, log, scale_configuration, BABELD)

        print("babel started")

        (RITA, RITA_EXIT) = switch_binaries(self.exit_id, VERBOSE, RITA, RITA_EXIT,
                                            COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B)
        start_rita_exit(self.nodes[self.exit_id], dname, RITA_EXIT)

        time.sleep(1)

        self.exit_price = get_rita_settings(
            self.exit_id)["exit_network"]["exit_price"]

        EXIT_SETTINGS["new_exits"]["exit_a"]["wg_public_key"] = get_rita_settings(
            self.exit_id)["exit_network"]["wg_public_key"]
        EXIT_SETTINGS["new_exits"]["exit_a"]["id"]["wg_public_key"] = get_rita_settings(
            self.exit_id)["exit_network"]["wg_public_key"]
        EXIT_SETTINGS["new_exits"]["exit_a"]["payment"] = {}
        EXIT_SETTINGS["new_exits"]["exit_a"]["payment"]["eth_address"] = get_rita_settings(
            self.exit_id)["payment"]["eth_address"]
            

        print("starting rita")
        log = "TRACE"
        # reduce logging in large configurations to keep disk pressure
        # from going insane
        if scale_configuration:
            log = "ERROR"
        for id, node in self.nodes.items():
            if id != self.exit_id and id != self.external:
                (RITA, RITA_EXIT) = switch_binaries(id, VERBOSE, RITA, RITA_EXIT,
                                                    COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B)
                start_rita(node, dname, log, RITA, EXIT_SETTINGS)
            time.sleep(0.5 + random.random() / 2)  # wait 0.5s - 1s
            print()
        print("rita started")

    def test_reach(self, node_from, node_to, PING6):
        ping = subprocess.Popen(
            ["ip", "netns", "exec", "netlab-{}".format(node_from.id), PING6,
             num_to_ip(node_to.id),
             "-c", "1"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = ping.stdout.read().decode("utf-8")
        return "1 packets transmitted, 1 received, 0% packet loss" in output

    def test_exit_reach(self, node, exit_internal_ip):
        ping = subprocess.Popen(
            ["ip", "netns", "exec", "netlab-{}".format(node.id), "ping",
             "{}".format(exit_internal_ip),
             "-c", "1"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = ping.stdout.read().decode("utf-8")
        return "1 packets transmitted, 1 received, 0% packet loss" in output

    def test_reach_all(self, PING6, verbose=True, global_fail=True):
        for i in self.nodes.values():
            for j in self.nodes.values():
                if not assert_test(self.test_reach(i, j, PING6), "Reachability " +
                                   "from node {} ({}) to {} ({})".format(i.id,
                                                                         i.revision, j.id, j.revision),
                                   verbose=verbose, global_fail=global_fail):
                    return False
        return True

    def test_exit_reach_all(self, verbose=True, global_fail=True):
        exit_internal_ip = get_rita_settings(
            self.exit_id)["exit_network"]["own_internal_ip"]
        ret = True
        for node in self.nodes.values():
            if node.id == self.exit_id:
                continue
            elif not assert_test(self.test_exit_reach(node, exit_internal_ip), "Exit Reachability " +
                                 "from node {} ({})".format(node.id,
                                                            node.revision),
                                 verbose=verbose, global_fail=global_fail):
                ret = False
        if global_fail and not ret:
            exit(1)
        return ret

    def test_routes(self, all_routes, verbose=True, global_fail=True):
        """
        Check the presence of all optimal routes.
        """
        result = True

        # Caution: all_routes directly relies on the layout of the netlab mesh.
        #
        # The routes are organized into a dictionary with nodes as keys and
        # the expected routes as values:
        # all_routes = {
        #     <where_from>: [
        #                 (<where_to>, <price>, <next_hop>),
        #                 [...]
        #             ],
        #     [...]
        # }

        for node, routes in all_routes.items():
            for route in routes:
                if node.id == route[0].id:
                    continue
                desc = ("Optimal route from node {} ({}) " +
                        "to {} ({}) with next-hop {} ({}) and price {}").format(
                    node.id,
                    node.revision,
                    route[0].id,
                    route[0].revision,
                    route[2].id,
                    route[2].revision,
                    route[1])
                result = result and assert_test(node.has_route(*route,
                                                               verbose=verbose
                                                               ),
                                                desc, verbose=verbose,
                                                global_fail=global_fail)
        return result

    def test_endpoints_all(self, VERBOSE):
        curl_args = "curl -sfg6 --retry 5 -m 60 "
        for node in self.nodes.values():

            # We don't expect the exit to work the same as others
            if node.id == self.exit_id:
                # Exit-specific stuff
                continue

            print(colored("====== Endpoints for node {} ======".format(node.id), "green"))

            # /neighbors
            if VERBOSE:
                print(colored("Hitting /neighbors:", "green"))

            result = subprocess.Popen(shlex.split("ip netns exec "
                                                  + "netlab-{} {} [::1]:4877/neighbors".format(node.id, curl_args)),
                                      stdout=subprocess.PIPE)
            assert_test(not result.wait(), "curl-ing /neighbors")
            stdout = result.stdout.read().decode('utf-8')
            try:
                print("Received neighbors:")
                if VERBOSE:
                    neighbors = json.loads(stdout)
                    pprint(neighbors)
                else:
                    print(stdout)
            except ValueError as e:
                print('Unable to decode JSON {!r}: {}'.format(stdout, e))
                assert_test(False, "Decoding the neighbors JSON")

            # /exits
            if VERBOSE:
                print(colored("Hitting /exits:", "green"))

            result = subprocess.Popen(shlex.split("ip netns exec "
                                                  + "netlab-{} {} [::1]:4877/exits".format(node.id, curl_args)),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert_test(not result.wait(), "curl-ing /exits")
            stdout = result.stdout.read().decode('utf-8')
            try:
                print("Received exits:")
                if VERBOSE:
                    exits = json.loads(stdout)
                    pprint(exits)
                else:
                    print(stdout)
            except ValueError as e:
                print('Unable to decode JSON {!r}: {}'.format(stdout, e))
                assert_test(False, "Decoding the exits JSON")

            # /info
            if VERBOSE:
                print(colored("Hitting /info:", "green"))

            result = subprocess.Popen(shlex.split("ip netns exec "
                                                  + "netlab-{} {} [::1]:4877/info".format(node.id, curl_args)),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert_test(not result.wait(), "curl-ing /info")
            stdout = result.stdout.read().decode('utf-8')
            try:
                print("Received info:")
                if VERBOSE:
                    info = json.loads(stdout)
                    pprint(info)
                else:
                    print(stdout)
            except ValueError as e:
                print('Unable to decode JSON {!r}: {}'.format(stdout, e))
                assert_test(False, "Decoding the info JSON")

            # /settings
            if VERBOSE:
                print(colored("Hitting /settings:", "green"))

            result = subprocess.Popen(shlex.split("ip netns exec "
                                                  + "netlab-{} {} [::1]:4877/settings".format(node.id, curl_args)),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert_test(not result.wait(), "curl-ing /settings")
            stdout = result.stdout.read().decode('utf-8')
            try:
                print("Received settings:")
                if VERBOSE:
                    settings = json.loads(stdout)
                    pprint(settings)
                else:
                    print(stdout)
            except ValueError as e:
                print('Unable to decode JSON {!r}: {}'.format(stdout, e))
                assert_test(False, "Decoding the settings JSON")

    def get_debts(self):
        """Creates a nested dictionary of balances, for example balances[1][3] is the balance node 1 has for node 3"""
        status = True
        balances = {}
        n = 0

        while True:
            ip = num_to_ip(n)
            status = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(n), "curl", "-s", "-g", "-6",
                 "[::1]:4877/debts"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            status.wait()
            output = status.stdout.read().decode("utf-8")
            # not zero is a hack to deal with the fact that the 7 node format is
            # one indexed and the arbitrary node one is zero indexed
            if output == "" and n != 0:
                break
            elif output == "" and n == 0:
                n += 1
                continue
            status = json.loads(output)
            balances[ip_to_num(ip)] = {}
            for i in status:
                peer_ip = i["identity"]["mesh_ip"]
                peer_debt = int(i["payment_details"]["debt"])
                balances[ip_to_num(ip)][ip_to_num(peer_ip)] = peer_debt
            n += 1

        return balances

    def gen_traffic(self, from_node, to_node, duration, speed):
        if from_node.id == self.exit_id:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-s", "-V"])
            time.sleep(2)
            client = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-c",
                 self.to_ip(from_node), "-V", "-u", "-t {}".format(duration), "-b {}M".format(speed), "-R", ])

        else:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-s", "-V"])
            time.sleep(2)
            client = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-c",
                 self.to_ip(to_node), "-V", "-u", "-t {}".format(duration), "-b {}M".format(speed)])
        client.wait()
        server.send_signal(signal.SIGKILL)
        server.wait()

    def test_traffic(self, traffic_test_pairs, time, speed):
        """Generates test traffic from and to the specified nodes, then ensure that all nodes agree"""
        for (from_node, to_node) in traffic_test_pairs:
            print("Test traffic...")
            self.gen_traffic(from_node, to_node, time, speed)

    def test_debts_values(self, test_traffic_pairs, time, speed, debts, all_routes, exit_id, exit_price):
        """Uses the traffic pairs and the provided time and speed to compute what every node should owe every other node"""
        intended_debts = {}
        # the data transferred by each test, remember some tests overlap in paths
        # prices are in wei/byte so this is in bytes
        expected_data_transfer = (time * speed * 1000000) / 8
        for (from_node, to_node) in test_traffic_pairs:
            # exit fees are owed independently of routing to the destination
            if to_node.id == exit_id or from_node.id == exit_id:
                exit_node = self.get_node(to_node, from_node, exit_id)
                other_node = self.get_not_node(to_node, from_node, exit_id)
                self.init_pair(intended_debts, from_node, to_node)
                self.init_pair(intended_debts, to_node, from_node)
                # exit is owed
                intended_debts[exit_node][other_node] -= exit_price * \
                    expected_data_transfer
                # client owes
                intended_debts[other_node][exit_node] += exit_price * \
                    expected_data_transfer

            last_via = from_node
            via = from_node
            while True:
                (via, price) = self.get_best_route(all_routes, via, to_node)
                if via.id == to_node.id:
                    break
                if last_via.id == exit_id:
                    exit = from_node
                    client = to_node
                    self.init_pair(intended_debts, client, exit)
                    self.init_pair(intended_debts, exit, client)
                    intended_debts[exit][client] -= \
                        price * expected_data_transfer
                    intended_debts[client][exit] += \
                        price * expected_data_transfer
                self.init_pair(intended_debts, last_via, via)
                self.init_pair(intended_debts, via, last_via)
                # we add what's owed to the first node, but now we must
                # follow the entire path adding smaller amounts each time
                intended_debts[last_via][via] += \
                    price * expected_data_transfer
                intended_debts[via][last_via] -= \
                    price * expected_data_transfer
                last_via = via
        for node in intended_debts.keys():
            for owed in intended_debts[node].keys():
                if node.id not in debts or owed.id not in debts[node.id]:
                    print("Debts map is incomplete! {} Has a predicted debt of {} for {} but no actual debt".format(
                        node.id, intended_debts[node][owed], owed.id))
                    continue
                if not fuzzy_match(debts[node.id][owed.id], intended_debts[node][owed]):
                    if debts[node.id][owed.id] != 0:
                        print("{} has a predicted debt of {} for {} but actual debt is {} {:.2%} accurate".format(
                        node.id, intended_debts[node][owed], owed.id, debts[node.id][owed.id], intended_debts[node][owed]/debts[node.id][owed.id]))
                    else:
                        print("{} has a predicted debt of {} for {} but actual debt is {}".format(
                        node.id, intended_debts[node][owed], owed.id, debts[node.id][owed.id]))
                # exit(1)

    def get_best_route(self, all_routes, from_node, target_node):
        """Very simple utility function to find routes"""
        best = 99999999
        best_route = None
        for (to, price, via) in all_routes[from_node]:
            if price < best and to is target_node:
                best_route = via
                best = price
        if best_route is None:
            print("There's a problem with the provided all_routes values!")
            exit(1)
        return (best_route, best)

    def init_pair(self, d, a, b):
        """helper function to create zero entires for nested dicts"""
        if a not in d:
            d[a] = {}
        if b not in d[a]:
            d[a][b] = 0

    def get_node(self, a, b, id):
        if a.id == id:
            return a
        elif b.id == id:
            return b
        else:
            exit(1)

    def get_not_node(self, a, b, id):
        if a.id != id:
            return a
        elif b.id != id:
            return b
        else:
            exit(1)

    def test_debts_reciprocal_matching(self, debts):
        """Tests that in a network nodes generally agree on debts, within a few percent this is done by making sure that
        debts[1][3] is within a few percent of debts[3][1]"""

        for node in debts.keys():
            for node_to_compare in debts[node].keys():
                if node_to_compare not in debts:
                    print("{} is not in the debts list".format(
                        node_to_compare))
                    continue
                elif node not in debts[node_to_compare]:
                    print("Node {} has a debt for Node {} but not the other way around!".format(
                        node, node_to_compare))
                    continue
                res = fuzzy_traffic_match(
                    debts[node][node_to_compare], debts[node_to_compare][node])
                if not res:
                    print("Nodes {} and {} do not agree! {} has {} and {} has {}!".format(
                        node, node_to_compare, node, debts[node][node_to_compare], node_to_compare, debts[node_to_compare][node]))
                    # exit(1)
        print("All debts match their reciprocal!")
