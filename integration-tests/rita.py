#!/usr/bin/python3
import json
import os
import subprocess
import time
import sys
from termcolor import colored
import signal
import toml

network_lab = os.path.join(os.path.dirname(__file__), "deps/network-lab/network-lab.sh")
babeld = os.path.join(os.path.dirname(__file__), "deps/babeld/babeld")
rita = os.path.join(os.path.dirname(__file__), "../target/debug/rita")
rita_exit = os.path.join(os.path.dirname(__file__), "../target/debug/rita_exit")
bounty = os.path.join(os.path.dirname(__file__), "../target/debug/bounty_hunter")
ping6 = os.getenv('PING6', "ping6")

tests_passes = True

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

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

def get_wg_private_key():
    proc = subprocess.Popen(["wg", "genkey"], stdout=subprocess.PIPE)
    key = proc.stdout.read()
    print(key[0:44])
    return key[0:44].decode("utf-8")

def get_wg_public_key(private_key):
    proc = subprocess.Popen(["wg", "pubkey"], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    proc.stdin.write(private_key.encode('utf-8'))
    proc.stdin.close()
    key = proc.stdout.read()
    print(key[0:44])
    return key[0:44].decode("utf-8")

def prep_netns(id):
    os.system("ip netns exec netlab-{} sysctl -w net.ipv4.ip_forward=1".format(id))
    os.system("ip netns exec netlab-{} sysctl -w net.ipv6.conf.all.forwarding=1".format(id))
    os.system("ip netns exec netlab-{} ip link set up lo".format(id))


def start_babel(node):
    os.system("ip netns exec netlab-{id} {0} -I babeld-n{id}.pid -d1 -L babeld-n{id}.log -h 1 -P {price} -G 8080 -w dummy &".
              format(babeld, node.get_interfaces(), id=node.id, price=node.fwd_price))

def create_dummy(id):
    os.system('ip netns exec netlab-{} brctl addbr dummy'.format(id))
    os.system('ip netns exec netlab-{} ip link set up dummy'.format(id))

def start_bounty(id):
    os.system('(RUST_BACKTRACE=full ip netns exec netlab-{id} {bounty} & echo $! > bounty-n{id}.pid) | grep -Ev "<unknown>|mio" > bounty-n{id}.log &'.format(id=id, bounty=bounty))


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
    settings["network"]["wg_private_key"] = get_wg_private_key()
    settings["network"]["wg_public_key"] = get_wg_public_key(settings["network"]["wg_private_key"])
    save_rita_settings(id, settings)
    time.sleep(0.1)
    os.system('(RUST_BACKTRACE=full RUST_LOG=trace ip netns exec netlab-{id} {rita} --config rita-settings-n{id}.toml --default rita-settings-n{id}.toml'
              ' 2>&1 & echo $! > rita-n{id}.pid) | '
              'grep -Ev "<unknown>|mio" > rita-n{id}.log &'.format(id=id, rita=rita, pwd=dname))


def start_rita_exit(id):
    settings = get_rita_exit_defaults()
    settings["network"]["own_ip"] = "fd::{}".format(id)
    settings["network"]["wg_private_key_path"] = "{pwd}/private-key-{id}".format(id=id, pwd=dname)
    settings["network"]["wg_private_key"] = get_wg_private_key()
    settings["network"]["wg_public_key"] = get_wg_public_key(settings["network"]["wg_private_key"])
    save_rita_settings(id, settings)
    time.sleep(0.1)
    os.system('(RUST_BACKTRACE=full RUST_LOG=trace ip netns exec netlab-{id} {rita} --config rita-settings-n{id}.toml --default rita-settings-n{id}.toml'
              ' 2>&1 & echo $! > rita-n{id}.pid) | '
              'grep -Ev "<unknown>|mio" > rita-n{id}.log &'.format(id=id, rita=rita_exit, pwd=dname))


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

    def add_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node

    def add_exit_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node
        self.exit = node.id

    def add_connection(self, connection):
        connection.canonicalize()
        self.connections[(connection.a.id, connection.b.id)] = connection
        connection.a.add_neighbor(connection.b.id)
        connection.b.add_neighbor(connection.a.id)

    def set_bounty(self, bounty_id):
        self.bounty = bounty_id

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
                "->": "loss random 0%",
                "<-": "loss random 0%"
            })

        network = {"nodes": nodes, "edges": edges}

        network_string = json.dumps(network)

        print("network topology: {}".format(network))

        print(network_lab)
        proc = subprocess.Popen([network_lab], stdin=subprocess.PIPE, universal_newlines=True)
        proc.stdin.write(network_string)
        proc.stdin.close()

        proc.wait()

        print("network-lab completed")

        for id in self.nodes:
            prep_netns(id)

        print("namespaces prepped")

        print("starting babel")

        for id, node in self.nodes.items():
            create_dummy(id)
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
            else:
                start_rita(id)
            time.sleep(0.2)
        print("rita started")

    @staticmethod
    def test_reach(id_from, id_to):
        ping = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(id_from), ping6, "fd::{}".format(id_to), "-c", "1"], stdout=subprocess.PIPE)
        output = ping.stdout.read().decode("utf-8")
        return "1 packets transmitted, 1 received, 0% packet loss" in output

    def test_reach_all(self):
        for i in self.nodes:
            for j in self.nodes:
                assert_test(self.test_reach(i, j), "Reachability from node {} to {}".format(i, j))
                assert_test(self.test_reach(j, i), "Reachability from node {} to {}".format(j, i))

    def get_balances(self):
        s = 1
        n = 0
        m = 0
        balances = {}

        while s != 0 and n < 100:
            status = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(self.bounty), "curl", "-s", "-g", "-6", "[::1]:8888/list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
        print("sum = {}, magnitude = {}, error = {}".format(s, m, abs(s)/m))
        assert_test(s == 0 and m != 0, "Conservation of balance")
        return balances

    def gen_traffic(self, from_node, to_node, bytes):
        server = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-s", "-V"])
        time.sleep(0.1)
        client = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-c", "fd::{}".format(to_node.id), "-V", "-n", str(bytes), "-Z"])
        client.wait()
        time.sleep(0.1)
        server.send_signal(signal.SIGINT)
        server.wait()


def traffic_diff(a, b):
    assert set(a.keys()) == set(b.keys())
    return {key: b[key] - a.get(key, 0) for key in b.keys()}

def fuzzy_traffic(a, b):
    return b - 5e9 < a < b + 5e9


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
    e = Node(5, 10)
    f = Node(6, 50)
    g = Node(7, 10)

    world = World()
    world.add_node(a)
    world.add_node(b)
    world.add_node(c)
    world.add_node(d)
    world.add_exit_node(e)
    world.add_node(f)
    world.add_node(g)

    world.add_connection(Connection(a, f))
    world.add_connection(Connection(f, g))
    world.add_connection(Connection(c, g))
    world.add_connection(Connection(b, c))
    world.add_connection(Connection(b, f))
    world.add_connection(Connection(b, d))
    world.add_connection(Connection(e, g))

    world.set_bounty(3)  # TODO: Who should be the bounty hunter?

    world.create()

    print("Waiting for network to stabilize")
    time.sleep(40)

    print("Test reachabibility...")
    world.test_reach_all()
    time.sleep(12)

    print("Test traffic...")
    t1 = world.get_balances()
    time.sleep(20)
    world.gen_traffic(d, a, 1000000000)
    time.sleep(20)

    t2 = world.get_balances()
    print("balance change from d->a:")
    diff = traffic_diff(t1, t2)
    print(diff)

    assert_test(fuzzy_traffic(diff[1], 10e9), "Balance of A")
    assert_test(fuzzy_traffic(diff[2], 25e9), "Balance of B")
    assert_test(fuzzy_traffic(diff[3], 0), "Balance of C")
    assert_test(fuzzy_traffic(diff[4], -85e9), "Balance of D")
    assert_test(fuzzy_traffic(diff[6], 50e9), "Balance of F")
    assert_test(fuzzy_traffic(diff[7], 0), "Balance of G")

    t2 = world.get_balances()

    time.sleep(22)
    world.gen_traffic(a, c, 1000000000)
    time.sleep(20)

    t3 = world.get_balances()
    print("balance change from a->c:")
    diff = traffic_diff(t2, t3)
    print(diff)

    assert_test(fuzzy_traffic(diff[1], -120e9), "Balance of A")
    assert_test(fuzzy_traffic(diff[2], 0), "Balance of B")
    assert_test(fuzzy_traffic(diff[3], 60e9), "Balance of C")
    assert_test(fuzzy_traffic(diff[4], 0), "Balance of D")
    assert_test(fuzzy_traffic(diff[6], 50e9), "Balance of F")
    assert_test(fuzzy_traffic(diff[7], 10e9), "Balance of G")

    t3 = world.get_balances()

    time.sleep(20)
    world.gen_traffic(c, f, 1000000000)
    time.sleep(20)

    t4 = world.get_balances()
    print("balance change from c->f:")
    diff = traffic_diff(t3, t4)
    print(diff)

    assert_test(fuzzy_traffic(diff[1], 0), "Balance of A")
    assert_test(fuzzy_traffic(diff[2], 0), "Balance of B")
    assert_test(fuzzy_traffic(diff[3], -60e9), "Balance of C")
    assert_test(fuzzy_traffic(diff[4], 0), "Balance of D")
    assert_test(fuzzy_traffic(diff[6], 50e9), "Balance of F")
    assert_test(fuzzy_traffic(diff[7], 10e9), "Balance of G")

    print("Check that tunnels have not been suspended")

    # assert_test(not check_log_contains("rita-n1.log", "Suspending Tunnel"), "Suspension of A")
    # assert_test(not check_log_contains("rita-n2.log", "Suspending Tunnel"), "Suspension of B")
    # assert_test(not check_log_contains("rita-n3.log", "Suspending Tunnel"), "Suspension of C")
    # assert_test(not check_log_contains("rita-n4.log", "Suspending Tunnel"), "Suspension of D")
    # assert_test(not check_log_contains("rita-n6.log", "Suspending Tunnel"), "Suspension of F")
    # assert_test(not check_log_contains("rita-n7.log", "Suspending Tunnel"), "Suspension of G")

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
