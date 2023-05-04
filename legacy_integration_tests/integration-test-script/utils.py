import email
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


def get_rita_defaults():
    return toml.load(open("../settings/test.toml"))


def get_rita_exit_defaults():
    return toml.load(open("../settings/test_exit.toml"))


def save_rita_settings(id, x):
    file = open("rita-settings-n{}.toml".format(id), "w")
    toml.dump(x, file)
    file.flush()
    os.fsync(file)
    file.close()
    os.system("sync")
    pass


def get_rita_settings(id):
    return toml.load(open("rita-settings-n{}.toml".format(id)))


def switch_binaries(node_id, VERBOSE, RITA, RITA_EXIT, COMPAT_LAYOUT, COMPAT_LAYOUTS, RITA_A, RITA_EXIT_A, RITA_B, RITA_EXIT_B):
    """
    Switch the Rita and exit Rita binaries assigned to node with ID
    :data:`node_id`.

    :param int node_id: Node ID for which we're changing binaries
    """
    if VERBOSE:
        print(("Previous binary paths:\nRITA:\t\t{}\nRITA_EXIT:\t{}\n").format(
            RITA, RITA_EXIT))

    release = COMPAT_LAYOUTS[COMPAT_LAYOUT][node_id - 1]

    if release == 'a':
        if VERBOSE:
            print("Using A for node {}...".format(node_id))
        RITA = RITA_A
        RITA_EXIT = RITA_EXIT_A
    elif release == 'b':
        if VERBOSE:
            print("Using B for node {}...".format(node_id))
        RITA = RITA_B
        RITA_EXIT = RITA_EXIT_B
    else:
        print("Unknown revision kind \"{}\" for node {}".format(release, node_id))
        sys.exit(1)

    if VERBOSE:
        print(("New binary paths:\nRITA:\t\t{}\nRITA_EXIT:\t{}\n").format(
            RITA, RITA_EXIT))

    return (RITA, RITA_EXIT)


def register_to_exit(node):
    os.system(("ip netns exec netlab-{} curl -XPOST " +
               "127.0.0.1:4877/exits/exit_a/register").format(node.id))


def email_verif(node):
    email_text = read_email(node)

    code = re.search(r"\[([0-9]+)\]", email_text).group(1)

    print("Email code for node {} is {}".format(node.id, code))

    exec_or_exit(("ip netns exec netlab-{} curl -XPOST " +
                  "127.0.0.1:4877/exits/exit_a/verify/{}").format(node.id, code))
    exec_or_exit(("ip netns exec netlab-{} curl " +
                  "127.0.0.1:4877/settings").format(node.id))


def read_email(node):
    id = node.id
    # TODO: this is O(n^2)
    for mail in os.listdir("mail"):
        with open(os.path.join("mail", mail)) as mail_file_handle:

            mail = email.message_from_file(mail_file_handle)
            to_value = mail.get("To")
            if to_value == "{}@example.com".format(id):
                message = mail.get_payload()
                if "low balance" in message:
                    continue
                return message
    raise Exception("cannot find email for node {}".format(id))


def assert_test(x, description, verbose=True, global_fail=True):
    if verbose:
        if x:
            print(colored(" + ", "green") + "{} Succeeded".format(description))
        else:
            sys.stderr.write(colored(" + ", "red") +
                             "{} Failed\n".format(description))

    if global_fail and not x:
        TEST_PASSES = False
    return x


def exec_no_exit(command, blocking=True, delay=0.01):
    """
    Executes a command and ignores it's output.

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
        except KeyError:  # The error code doesn't have a canonical name
            errname = '<unknown>'
        print('Command "{c}" failed: "{strerr}" (code {rv})'.format(
            c=command,
            # strerror handles unknown errors gracefuly
            strerr=os.strerror(retval),
            rv=errname,
            file=sys.stderr
        )
        )


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
        except KeyError:  # The error code doesn't have a canonical name
            errname = '<unknown>'
        print('Command "{c}" failed: "{strerr}" (code {rv})'.format(
            c=command,
            # strerror handles unknown errors gracefuly
            strerr=os.strerror(retval),
            rv=errname,
            file=sys.stderr
        )
        )
        sys.exit(retval)


def cleanup():
    os.system("rm -rf *.db *.log *.pid private-key* mail")
    os.system("mkdir mail")
    os.system("sync")
    # TODO: This is very inconsiderate
    os.system("killall babeld rita rita_exit iperf")


def teardown():
    os.system("rm -rf *.pid private-key*")
    os.system("sync")
    # TODO: This is very inconsiderate
    os.system("killall babeld rita rita_exit iperf")


def prep_netns(id):
    exec_or_exit(
        "ip netns exec netlab-{} sysctl -w net.ipv4.ip_forward=1".format(id))
    exec_or_exit(
        "ip netns exec netlab-{} sysctl -w net.ipv6.conf.all.forwarding=1".format(id))
    exec_or_exit("ip netns exec netlab-{} ip link set up lo".format(id))


def traffic_diff(a, b):
    print(a, b)
    return {key: b[key] - a.get(key, 0) for key in b.keys()}


def fuzzy_traffic(a, b, VERBOSE):
    retval = b - 5e8 - abs(a) * 0.1 < a < b + 5e8 + abs(a) * 0.1
    if VERBOSE is not None:
        print('fuzzy_traffic({a}, {b}) is {retval}'.format(a=a, b=b,
                                                           retval=retval))
        print(('Expression: {b} - 5e8 - abs({a}) * 0.1 < {a} < {b} + 5e8 + ' +
               'abs({a}) * 0.1').format(a=a, b=b))

    return retval


def check_log_contains(f, x):
    if x in open(f).read():
        return True
    else:
        return False


def start_babel(node, log, scale, BABELD):
    hello_interval = 1
    update_interval = 1
    if scale:
        hello_interval = 1
        update_interval = 1
    exec_or_exit(
        (
            "ip netns exec netlab-{id} {babeld_path} " +
            "-I babeld-n{id}.pid " +
            "-d {log} " +
            "-r " +
            "-L babeld-n{id}.log " +
            "-H {hello_interval} " +
            "-G 6872 " +
            '-C "default enable-timestamps true" ' +
            '-C "default update-interval {update_interval}" ' +
            "-w lo"
        ).format(babeld_path=BABELD, ifaces=node.get_interfaces(), id=node.id, log=log, hello_interval=hello_interval, update_interval=update_interval),
        blocking=False
    )


def start_rita(node, dname, log, RITA, EXIT_SETTINGS):
    id = node.id
    settings = get_rita_defaults()

    settings["network"]["mesh_ip"] = "fd00::{}".format(id)

    settings["network"]["wg_private_key_path"] = "{pwd}/private-key-{id}".format(
        id=id, pwd=dname)
    settings["network"]["peer_interfaces"] = node.get_veth_interfaces()
    settings["payment"]["local_fee"] = node.local_fee
    settings["metric_factor"] = 0  # We explicitly want to disregard quality
    save_rita_settings(id, settings)
    time.sleep(0.2)
    os.system(
        '(RUST_BACKTRACE=full RUST_LOG={log} ip netns exec netlab-{id} {rita} --config=rita-settings-n{id}.toml --platform=linux'
        ' 2>&1 & echo $! > rita-n{id}.pid) | '
        'grep -Ev "<unknown>|mio|tokio_core|tokio_reactor|hyper" > rita-n{id}.log &'.format(id=id, rita=RITA,
                                                                                            pwd=dname, log=log)
    )
    time.sleep(1)

    email = "{}@example.com".format(id)

    # this works in travis if your looking for it
    # else:
    #     time.sleep(1)
    #     os.system("ip netns exec netlab-{id} curl -XPOST 127.0.0.1:4877/settings -H 'Content-Type: application/json' -i -d '{data}'"
    #           .format(id=id, data=json.dumps({"exit_client": EXIT_SETTINGS})))
    #     time.sleep(1)
    #     os.system("ip netns exec netlab-{id} curl -XPOST 127.0.0.1:4877/email -H 'Content-Type: application/json' -i -d '{data}'"
    #           .format(id=id, data=email)
    os.system("ip netns exec netlab-{id} curl --retry 5 --retry-connrefused -m 60 -XPOST 127.0.0.1:4877/settings -H 'Content-Type: application/json' -i -d '{data}'"
              .format(id=id, data=json.dumps({"exit_client": EXIT_SETTINGS})))
    os.system("ip netns exec netlab-{id} curl --retry 5 --retry-connrefused -m 60 -XPOST 127.0.0.1:4877/email -H 'Content-Type: application/json' -i -d '{data}'"
              .format(id=id, data=email))


def start_rita_exit(node, dname, RITA_EXIT):
    id = node.id
    settings = get_rita_exit_defaults()

    settings["network"]["mesh_ip"] = "fd00::{}".format(id)

    settings["network"]["wg_private_key_path"] = "{pwd}/private-key-{id}".format(
        id=id, pwd=dname)
    settings["network"]["peer_interfaces"] = node.get_veth_interfaces()
    settings["payment"]["local_fee"] = node.local_fee
    settings["metric_factor"] = 0  # We explicity want to disregard quality
    save_rita_settings(id, settings)
    time.sleep(0.2)
    os.system(
        '(RUST_BACKTRACE=full RUST_LOG=TRACE ip netns exec netlab-{id} {rita} --config=rita-settings-n{id}.toml'
        ' 2>&1 & echo $! > rita-n{id}.pid) | '
        'grep -Ev "<unknown>|mio|tokio_core|tokio_reactor|hyper" > rita-n{id}.log &'.format(id=id, rita=RITA_EXIT,
                                                                                            pwd=dname)
    )


def ip_to_num(ip):
    if ip in "fd00::aabb":
        return 0
    else:
        return int(ip.replace("fd00::", ""))


def num_to_ip(num):
    if num == 0:
        return "fd00::aabb"
    else:
        return "fd00::{}".format(num)


def num_to_linklocal_ip(num):
    if num == 0:
        return "fe80::"
    else:
        return "fe80::{}".format(num)


def fuzzy_match(numA, numB):
    # ignore small debts
    if abs(numA) < 1000000 and abs(numB) < 1000000:
        return True
    # signs must match
    if numA > 0 and numB < 0 or numA > 0 and numB < 0:
        return False
    # 10%
    allowed_delta = 0.10
    high = 1 + allowed_delta
    low = 1 - allowed_delta

    if numA/numB > low and numA/numB < high:
        return True
    else:
        return False


def fuzzy_traffic_match(numA, numB):
    """A matching scheme with error margins for Rita traffic, allows up to 5% lower or in the case of
    the paying party over-estimating (packet loss) it allows more"""
    # ignore small debts
    if abs(numA) < 1000000 and abs(numB) < 1000000:
        return True
    # signs must not match
    if numA > 0 and numB > 0 or numA < 0 and numB < 0:
        return False
    if numA >= 0:
        pos = numA
        neg = numB
    if numB >= 0:
        pos = numB
        neg = numA
    pos_abs = abs(pos)
    neg_abs = abs(neg)
    # 5%
    allowed_delta = 0.05
    high = 1 + allowed_delta
    low = 1 - allowed_delta

    # debt has been undercounted, the payer has a debt value less than
    # 95% of the node being paid
    undercounting = pos_abs < (neg_abs * low)
    # overcounting, this is not an error, but it is worth warning about
    # this should only happen if there is packet loss
    overcounting = pos_abs > (neg_abs * high)
    if overcounting:
        print("Payer is overpaying by {}%, this is correct if there was significant packet loss".format(
            pos_abs/neg_abs))
    if undercounting:
        return False
    return True
