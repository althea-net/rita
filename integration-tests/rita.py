#!/usr/bin/python3
import json
import os
import subprocess
import time
import sys
from termcolor import colored
import signal

network_lab = os.path.join(os.path.dirname(__file__), "deps/network-lab/network-lab.sh")
babeld = os.path.join(os.path.dirname(__file__), "deps/babeld/babeld")
rita = os.path.join(os.path.dirname(__file__), "../target/debug/rita")
bounty = os.path.join(os.path.dirname(__file__), "../target/debug/bounty_hunter")
ping6 = os.getenv('PING6', "ping6")

tests_passes = True


def cleanup():
    os.system("rm -rf *.log *.pid")
    os.system("killall babeld rita bounty_hunter nc")  # TODO: This is very inconsiderate


def teardown():
    os.system("rm -rf *.pid")
    os.system("killall babeld rita bounty_hunter nc")  # TODO: This is very inconsiderate


class Node:
    def __init__(self, id, fwd_price):
        self.id = id
        self.fwd_price = fwd_price
        self.neighbours = []

    def add_neighbour(self, id):
        if id not in self.neighbours:
            self.neighbours.append(id)

    def get_interfaces(self):
        interfaces = ""
        for i in self.neighbours:
            interfaces += "br-{}-{} ".format(self.id, i)
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
    os.system("ip netns exec netlab-{} sysctl -w net.ipv4.ip_forward=1".format(id))
    os.system("ip netns exec netlab-{} sysctl -w net.ipv6.conf.all.forwarding=1".format(id))
    os.system("ip netns exec netlab-{} ip link set up lo".format(id))


def start_babel(node):
    os.system("ip netns exec netlab-{id} {0} -I babeld-n{id}.pid -d 1 -L babeld-n{id}.log -h 1 -P 5 -w {1} -G 8080 &".
              format(babeld, node.get_interfaces(), id=node.id))


def create_bridge(a, b):
    os.system('ip netns exec netlab-{} brctl addbr "br-{}-{}"'.format(a, a, b))
    os.system('ip netns exec netlab-{} brctl addif "br-{}-{}" "veth-{}-{}"'.format(a, a, b, a, b))
    os.system('ip netns exec netlab-{} ip link set up "br-{}-{}"'.format(a, a, b))
    os.system('ip netns exec netlab-{} ip addr add 2001::{} dev "br-{}-{}"'.format(a, a, a, b))


def start_bounty(id):
    os.system("RUST_BACKTRACE=full ip netns exec netlab-{id} {bounty} > bounty-n{id}.log & echo $! > bounty-n{id}.pid".format(id=id, bounty=bounty))


def start_rita(id):
    os.system("RUST_BACKTRACE=full ip netns exec netlab-{id} {rita} --ip 2001::{id} > rita-n{id}.log & echo $! > rita-n{id}.pid".format(id=id, rita=rita))


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

    def add_node(self, node):
        assert node.id not in self.nodes
        self.nodes[node.id] = node

    def add_connection(self, connection):
        connection.canonicalize()
        self.connections[(connection.a.id, connection.b.id)] = connection
        connection.a.add_neighbour(connection.b.id)
        connection.b.add_neighbour(connection.a.id)

    def set_bounty(self, bounty_id):
        self.bounty = bounty_id

    def create(self):
        cleanup()

        assert self.bounty
        nodes = {}
        for id in self.nodes:
            nodes[str(id)] = {"ip": "2001::{}".format(id)}

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

        print("creating bridge interfaces")

        for conn in self.connections:
            create_bridge(conn[0], conn[1])
            create_bridge(conn[1], conn[0])

        print("bridge interface created")

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
            start_rita(id)
        print("rita started")

    @staticmethod
    def test_reach(id_from, id_to):
        ping = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(id_from), ping6, "2001::{}".format(id_to), "-c", "1"], stdout=subprocess.PIPE)
        output = ping.stdout.read().decode("utf-8")
        return "1 packets transmitted, 1 received, 0% packet loss" in output

    def test_reach_all(self):
        for a, b in self.connections:
            assert_test(self.test_reach(a, b), "Reachability from node {} to {}".format(a, b))
            assert_test(self.test_reach(b, a), "Reachability from node {} to {}".format(a, b))

    def get_balances(self):
        status = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(self.bounty), "curl", "-s", "[::1]:8888/list"], stdout=subprocess.PIPE)
        status = json.loads(status.stdout.read().decode("utf-8"))
        balances = {}
        s = 0
        m = 0
        for i in status:
            balances[int(i["ip"].replace("2001::", ""))] = int(i["balance"])
            s += int(i["balance"])
            m += abs(int(i["balance"]))
        print("sum = {}, magnitude = {}, error = {}".format(s, m, abs(s)/m))
        return balances

    def gen_traffic(self, from_node, to_node, bytes):
        server = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(to_node.id), "iperf3", "-s", "-V"])
        time.sleep(0.1)
        client = subprocess.Popen(["ip", "netns", "exec", "netlab-{}".format(from_node.id), "iperf3", "-c", "2001::{}".format(to_node.id), "-V", "-n", str(bytes), "-Z"])
        client.wait()
        server.send_signal(signal.SIGINT)
        server.wait()


if __name__ == "__main__":
    a = Node(1, 10)  # TODO: Currently unspecified
    b = Node(2, 25)
    c = Node(3, 60)
    d = Node(4, 10)  # TODO: Currently unspecified
    # e = Node(5, 10)  # TODO: Does not exist in diagram
    f = Node(6, 50)
    g = Node(7, 10)

    world = World()
    world.add_node(a)
    world.add_node(b)
    world.add_node(c)
    world.add_node(d)
    # world.add_node(e)
    world.add_node(f)
    world.add_node(g)

    world.add_connection(Connection(a, f))
    world.add_connection(Connection(f, g))
    world.add_connection(Connection(c, g))
    world.add_connection(Connection(b, c))
    world.add_connection(Connection(b, f))
    world.add_connection(Connection(b, d))

    world.set_bounty(3)  # TODO: Who should be the bounty hunter?

    world.create()

    print("Waiting for network to stabilize")
    time.sleep(22)

    print("Test reachabibility...")
    world.test_reach_all()

    print("Test traffic...")
    world.gen_traffic(d, a, 10000000)
    world.gen_traffic(a, c, 10000000)
    world.gen_traffic(c, f, 10000000)
    time.sleep(5)
    print(world.get_balances())

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
