#!/usr/bin/python3
import json


class Node:
    def __init__(self, id, fwd_price):
        self.id = id
        self.fwd_price = fwd_price


class Connection:
    def __init__(self, a, b):
        self.a = a
        self.b = b

    def canonicalize(self):
        if self.a.id > self.b.id:
            t = self.b
            self.b = self.a
            self.a = t


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

        return json.dumps(network)


if __name__ == "__main__":
    a = Node(0, 10)  # TODO: Currently unspecified
    b = Node(1, 25)
    c = Node(2, 60)
    d = Node(3, 10)  # TODO: Currently unspecified
    e = Node(4, 10)  # TODO: Does not exist in diagram
    f = Node(5, 50)
    g = Node(6, 10)

    world = World()
    world.add_node(a)
    world.add_node(b)
    world.add_node(c)
    world.add_node(d)
    world.add_node(e)
    world.add_node(f)
    world.add_node(g)

    world.add_connection(Connection(a, f))
    world.add_connection(Connection(f, g))
    world.add_connection(Connection(c, g))
    world.add_connection(Connection(b, c))
    world.add_connection(Connection(b, f))
    world.add_connection(Connection(b, d))

    world.bounty = a

    print(world.create())