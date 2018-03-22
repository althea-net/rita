#!/usr/bin/python3

from termcolor import colored

import errno
import json
import os
import random
import signal
import shlex
import subprocess
import sys
import time
import toml

NETWORK_LAB = os.path.join(os.path.dirname(__file__), "deps/network-lab/network-lab.sh")
BABELD = os.path.join(os.path.dirname(__file__), "deps/babeld/babeld")
RITA = os.path.join(os.path.dirname(__file__), "../target/debug/rita")
RITA_EXIT = os.path.join(os.path.dirname(__file__), "../target/debug/rita_exit")
BOUNTY_HUNTER = os.path.join(os.path.dirname(__file__), "../target/debug/bounty_hunter")
PING6 = os.getenv('PING6', "ping6")
CONVERGENCE_DELAY = float(os.getenv('CONVERGENCE_DELAY', 10))

tests_passes = True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)


def exec_or_exit(command, blocking=True, delay=0.01):
    """
    Executes a command and terminates the program if it fails.

    :param str command: A string containing the command to run
    :param bool blocking: Decides whether to block until :data:`command` exits
    :param float delay: How long to wait before obtaining the return value
    (useful in non-blocking mode where e.g. a ``cat`` command with a
    non-existent file would very likely fail before, say, 100ms pass)
    """
    process = subprocess.Popen(shlex.split(command))

    time.sleep(delay)

    if not blocking:
        # If it didn't fail yet we get a None
        retval = process.poll() or 0
    else:
        retval = process.wait()

    if retval != 0:
        try:
            errname = errno.errorcode[retval]
        except KeyError: # The error code doesn't have a canonical name
            errname = '<unknown>'
        print('Command "{c}" failed: "{strerr}" (code {rv})'.format(
            c=command,
            strerr=os.strerror(retval), # strerror handles unknown errors gracefuly
            rv=errname,
            file=sys.stderr
            )
            )
        sys.exit(retval)


def cleanup():
    os.system("rm -rf *.log *.pid *.toml")
    os.system("killall babeld rita bounty_hunter iperf")  # TODO: This is very inconsiderate


def teardown():
    os.system("rm -rf *.pid *.toml")
    os.system("killall babeld rita bounty_hunter iperf")  # TODO: This is very inconsiderate


class Node:
    def __init__(self, id, fwd_price):
        self.id = id
        self.fwd_price = fwd_price
        self.neighbors = []

    def add_neighbor(self, id):
        if id not in self.neighbors:
            self.neighbors.append(id)

    def get_interfaces(self):
        interfaces = ""
        for i in range(len(self.neighbors)):
            interfaces += "wg{} ".format(i)
        return interfaces

    def get_veth_interfaces(self):
        interfaces = ""
        for i in self.neighbors:
            interfaces += "veth-{}-{} ".format(self.id, i)
        return interfaces


class Connection:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def canonicalize(self):
        if self.a.id > self.b.id:
            t = self.b
            self.b = self.a
            self.a = t

def prep_netns(id):
    exec_or_exit("ip netns exec netlab-{} sysctl -w net.ipv4.ip_forward=1".format(id))
    exec_or_exit("ip netns exec netlab-{} sysctl -w net.ipv6.conf.all.forwarding=1".format(id))
    exec_or_exit("ip netns exec netlab-{} ip link set up lo".format(id))


def start_babel(node):
    exec_or_exit(
            (
                "ip netns exec netlab-{id} {babeld_path} " +
                "-I babeld-n{id}.pid " +
                "-d 1 " +
                "-r " +
                "-L babeld-n{id}.log " +
                "-H 1 " +
                "-F {price} " +
                "-a 0 " +
                "-G 8080 " +
                '-C "default update-interval 1" ' +
                "-w lo"
            ).format(babeld_path=BABELD, ifaces=node.get_interfaces(), id=node.id, price=node.fwd_price),
            blocking=False
        )


def start_bounty(id):
    os.system(
        '(RUST_BACKTRACE=full ip netns exec netlab-{id} {bounty} & echo $! > bounty-n{id}.pid) | grep -Ev "<unknown>|mio" > bounty-n{id}.log &'.format(
            id=id, bounty=BOUNTY_HUNTER))


def get_rita_defaults():
    return toml.load(open("../settings/default.toml"))


def get_rita_exit_defaults():
    return toml.load(open("../settings/default_exit.toml"))


def save_rita_settings(id, x):
    toml.dump(x, open("rita-settings-n{}.toml".format(id), "w"))


def start_rita(id):
    settings = get_rita_defaults()
    settings["network"]["own_ip"] = "fd::{}".format(id)
    settings["network"]["wg_private_key_path"] = "{pwd}/private-key-{id}".format(id=id, pwd=dname)
    save_rita_settings(id, settings)
    time.sleep(0.1)
    os.system(
        '(RUST_BACKTRACE=full RUST_LOG=trace ip netns exec netlab-{id} {rita} --config rita-settings-n{id}.toml --default rita-settings-n{id}.toml --platform linux'
        ' 2>&1 & echo $! > rita-n{id}.pid) | '
        'grep -Ev "<unknown>|mio|tokio_core|hyper" > rita-n{id}.log &'.format(id=id, rita=RITA,
                                                                              pwd=dname)
        )


def start_rita_exit(id):
    settings = get_rita_exit_defaults()
    settings["network"]["own_ip"] = "fd::{}".format(id)
    settings["network"]["wg_private_key_path"] = "{pwd}/private-key-{id}".format(id=id, pwd=dname)
    save_rita_settings(id, settings)
    time.sleep(0.1)
    os.system(
        '(RUST_BACKTRACE=full RUST_LOG=trace ip netns exec netlab-{id} {rita} --config rita-settings-n{id}.toml --default rita-settings-n{id}.toml'
        ' 2>&1 & echo $! > rita-n{id}.pid) | '
        'grep -Ev "<unknown>|mio|tokio_core|hyper" > rita-n{id}.log &'.format(id=id, rita=RITA_EXIT,
                                                                              pwd=dname)
        )


def assert_test(x, description):
    if x:
        print(colored(" + ", "green") + "{} Succeeded".format(description))
    else:
        sys.stderr.write(colored(" + ", "red") + "{} Failed\n".format(description))
        global tests_passes
        tests_passes = False


class World:
    def __init__(self):
        self.nodes = {}
        self.connections = {}
        self.bounty = None
        self.exit = None
        self.external = None

    def add_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node

    def add_exit_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node
        self.exit = node.id

    def add_external_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node
        self.external = node.id

    def add_connection(self, connection):
        connection.canonicalize()
        self.connections[(connection.a.id, connection.b.id)] = connection
        connection.a.add_neighbor(connection.b.id)
        connection.b.add_neighbor(connection.a.id)

    def set_bounty(self, bounty_id):
        self.bounty = bounty_id

    def to_ip(self, node):
        if self.exit == node.id:
            return "172.168.1.254"
        else:
            return "fd::{}".format(node.id)

    def create(self):
        cleanup()

        assert self.bounty
        nodes = {}
        for id in self.nodes:
            nodes[str(id)] = {"ip": "fd::{}".format(id)}

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
        proc = subprocess.Popen([NETWORK_LAB], stdin=subprocess.PIPE, universal_newlines=True)
        proc.stdin.write(network_string)
        proc.stdin.close()

        proc.wait()

        print("network-lab completed")

        for id in self.nodes:
            prep_netns(id)

        print("namespaces prepped")

        print("starting babel")

        for id, node in self.nodes.items():
            start_babel(node)

        print("babel started")

        print("starting bounty hunter")
        start_bounty(self.bounty)
        print("bounty hunter started")

        time.sleep(1)

        print("starting rita")
        for id in self.nodes:
            if id == self.exit:
                start_rita_exit(id)
            elif id == self.external:
                pass
            else:
                start_rita(id)
            time.sleep(0.5 + random.random() / 2) # wait 0.5s - 1s
        print("rita started")

    def test_reach(self, node_from, node_to):
        ping = subprocess.Popen(
            ["ip", "netns", "exec", "netlab-{}".format(node_from.id), PING6,
             "fd::{}".format(node_to.id),
             "-c", "1"], stdout=subprocess.PIPE)
        output = ping.stdout.read().decode("utf-8")
        return "1 packets transmitted, 1 received, 0% packet loss" in output

    def test_reach_all(self):
        for i in self.nodes.values():
            for j in self.nodes.values():
                assert_test(self.test_reach(i, j),
                            "Reachability from node {} to {}".format(i.id, j.id))

    def get_balances(self):
        s = 1
        n = 0
        m = 0
        balances = {}

        while s != 0 and n < 100:
            status = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(self.bounty), "curl", "-s", "-g", "-6",
                 "[::1]:8888/list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            status.wait()
            output = status.stdout.read().decode("utf-8")
            status = json.loads(output)
            balances = {}
            s = 0
            m = 0
            for i in status:
                balances[int(i["ip"].replace("fd::", ""))] = int(i["balance"])
                s += int(i["balance"])
                m += abs(int(i["balance"]))
            n += 1
            time.sleep(0.5)
            print("time {}, value {}".format(n, s))

        print("tried {} times".format(n))
        print("sum = {}, magnitude = {}, error = {}".format(s, m, abs(s) / m))
        assert_test(s == 0 and m != 0, "Conservation of balance")
        return balances

    def gen_traffic(self, from_node, to_node, bytes):
        if from_node.id == self.exit:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-s", "-V"])
            time.sleep(0.1)
            client = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-c",
                 self.to_ip(from_node), "-V", "-n", str(bytes), "-Z", "-R"])

        else:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-s", "-V"])
            time.sleep(0.1)
            client = subprocess.Popen(
                ["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-c",
                 self.to_ip(to_node), "-V", "-n", str(bytes), "-Z"])

        client.wait()
        time.sleep(0.1)
        server.send_signal(signal.SIGINT)
        server.wait()

    def test_traffic(self, from_node, to_node, results):
        print("Test traffic...")
        t1 = self.get_balances()
        self.gen_traffic(from_node, to_node, 1e8)
        time.sleep(30)

        t2 = self.get_balances()
        print("balance change from {}->{}:".format(from_node.id, to_node.id))
        diff = traffic_diff(t1, t2)
        print(diff)

        for node_id, balance in results.items():
            assert_test(fuzzy_traffic(diff[node_id], balance * 1e8),
                        "Balance of {}".format(node_id))


def traffic_diff(a, b):
    print(a, b)
    assert set(a.keys()) == set(b.keys())
    return {key: b[key] - a.get(key, 0) for key in b.keys()}


def fuzzy_traffic(a, b):
    return b - 5e8 - abs(a) * 0.1 < a < b + 5e8 + abs(a) * 0.1


def check_log_contains(f, x):
    if x in open(f).read():
        return True
    else:
        return False


if __name__ == "__main__":
    a = Node(1, 10)
    b = Node(2, 25)
    c = Node(3, 60)
    d = Node(4, 10)
    e = Node(5, 0)
    f = Node(6, 50)
    g = Node(7, 10)
    # h = Node(8, 0)

    world = World()
    world.add_node(a)
    world.add_node(b)
    world.add_node(c)
    world.add_node(d)
    world.add_exit_node(e)
    world.add_node(f)
    world.add_node(g)
    # world.add_external_node(h)

    world.add_connection(Connection(a, f))
    world.add_connection(Connection(f, g))
    world.add_connection(Connection(c, g))
    world.add_connection(Connection(b, c))
    world.add_connection(Connection(b, f))
    world.add_connection(Connection(b, d))
    world.add_connection(Connection(e, g))
    # world.add_connection(Connection(e, h))

    world.set_bounty(3)  # TODO: Who should be the bounty hunter?

    world.create()

    print("Waiting for network to stabilize")
    time.sleep(CONVERGENCE_DELAY)

    print("Test reachabibility...")

    world.test_reach_all()

    world.test_traffic(c, f, {
        1: 0,
        2: 0,
        3: -10 * 1.05,
        4: 0,
        5: 0,
        6: 0 * 1.05,
        7: 10 * 1.05
    })

    world.test_traffic(d, a, {
        1: 0 * 1.05,
        2: 25 * 1.05,
        3: 0,
        4: -75 * 1.05,
        5: 0,
        6: 50 * 1.05,
        7: 0
    })

    world.test_traffic(a, c, {
        1: -60 * 1.05,
        2: 0,
        3: 0,
        4: 0,
        5: 0,
        6: 50 * 1.05,
        7: 10 * 1.05
    })

    world.test_traffic(d, e, {
        1: 0,
        2: 25 * 1.1,
        3: 0,
        4: -135 * 1.1,
        5: 50 * 1.1,
        6: 50 * 1.1,
        7: 10 * 1.1
    })

    world.test_traffic(e, d, {
        1: 0,
        2: 25 * 1.1,
        3: 0,
        4: -135 * 1.1,
        5: 50 * 1.1,
        6: 50 * 1.1,
        7: 10 * 1.1
    })

    world.test_traffic(c, e, {
        1: 0,
        2: 0,
        3: -60 * 1.1,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: 10 * 1.1
    })

    world.test_traffic(e, c, {
        1: 0,
        2: 0,
        3: -60 * 1.1,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: 10 * 1.1
    })

    world.test_traffic(g, e, {
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: -50 * 1.1
    })

    world.test_traffic(e, g, {
        1: 0,
        2: 0,
        3: 0,
        4: 0,
        5: 50 * 1.1,
        6: 0,
        7: -50 * 1.1
    })

    print("Check that tunnels have not been suspended")

    assert_test(not check_log_contains("rita-n1.log", "debt is below close threshold"), "Suspension of A")
    assert_test(not check_log_contains("rita-n2.log", "debt is below close threshold"), "Suspension of B")
    assert_test(not check_log_contains("rita-n3.log", "debt is below close threshold"), "Suspension of C")
    assert_test(not check_log_contains("rita-n4.log", "debt is below close threshold"), "Suspension of D")
    assert_test(not check_log_contains("rita-n6.log", "debt is below close threshold"), "Suspension of F")
    assert_test(not check_log_contains("rita-n7.log", "debt is below close threshold"), "Suspension of G")

    if len(sys.argv) > 1 and sys.argv[1] == "leave-running":
        pass
    else:
        teardown()

    print("done... exiting")

    if tests_passes:
        print("All tests passed!!")
        exit(0)
    else:
        print("Tests have failed :(")
        exit(1)
