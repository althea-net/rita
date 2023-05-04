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

from utils import num_to_ip
from utils import num_to_linklocal_ip


class Node:
    def __init__(self, id, local_fee, COMPAT_LAYOUT, COMPAT_LAYOUTS):
        self.id = id
        self.local_fee = local_fee
        self.neighbors = []
        self.revision = COMPAT_LAYOUTS[COMPAT_LAYOUT][self.id - 1]

    def add_neighbor(self, id):
        if id not in self.neighbors:
            self.neighbors.append(id)

    def get_interfaces(self):
        interfaces = ""
        for i in range(len(self.neighbors)):
            interfaces += "wg{} ".format(i)
        return interfaces

    def get_veth_interfaces(self):
        interfaces = []
        for i in self.neighbors:
            interfaces.append("veth-{}-{}".format(self.id, i))
        return interfaces

    def has_route(self, dest, price, next_hop, backlog=100000, verbose=False):
        """
        This function takes :data:`self` and returns ``True`` if a specified
        route is installed in the last :data:`backlog` characters of the node's
        Babel log file.

        :param Node dest: Who the route goes to
        :param int price: What the route costs
        :param Node next_hop_ip: Who's the next hop
        :param int backlog: How big chunk from the end to use for dump matching

        :rtype bool: Whether the requested route was found
        """
        buf = None
        fname = 'babeld-n{}.log'.format(self.id)
        with open(fname, 'r') as f:

            flen = f.seek(0, 2)  # Go to the end
            f.seek((flen - backlog) if backlog < flen else 0)
            buf = f.read()

        last_dump_pat = re.compile(r'.*(My id .*)', re.S | re.M)
        last_dump_match = last_dump_pat.match(buf)
        if last_dump_match is None:
            if verbose:
                print('Could not find the last dump ({}) in {}'
                      .format(last_dump_pat, fname),
                      file=sys.stderr)
            return False

        last_dump = last_dump_match.group(1)
        route_pat = re.compile(r'{d}.*price {p}.*fee {f}.*neigh {nh}.*(installed)|(feasible)'
                               .format(
                                   d=num_to_ip(dest.id),
                                   p=price,
                                   f=self.local_fee,
                                   nh=num_to_linklocal_ip(next_hop.id)
                               ))

        if route_pat.search(last_dump) is None:
            if verbose:
                print('{} not found in {}:\n{}'.format(route_pat, fname,
                                                       last_dump),
                      file=sys.stderr)
            return False

        return True
