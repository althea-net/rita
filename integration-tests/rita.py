#!/usr/bin/python3
import json
import os
import subprocess

network_lab = os.path.join(os.path.dirname(__file__), "deps/network-lab/network-lab.sh")
babeld = os.path.join(os.path.dirname(__file__), "babeld/babeld")
rita = os.path.join(os.path.dirname(__file__), "../target/debug/rita")
bounty = os.path.join(os.path.dirname(__file__), "../target/debug/bounty_hunter")


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
    os.system("RUST_BACKTRACE=1 ip netns exec netlab-{id} {bounty} > bounty-n{id}.log & echo $! > bounty-n{id}.pid".format(id=id, bounty=bounty))


def start_rita(id):
    os.system("RUST_BACKTRACE=1 ip netns exec netlab-{id} {rita} --ip 2001::{id} > rita-n{id}.log & echo $! > rita-n{id}.pid".format(id=id, rita=rita))


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

        print("starting rita")
        for id in self.nodes:
            start_rita(id)
        print("rita started")

        print("done... exiting")


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
