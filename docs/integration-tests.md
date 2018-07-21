# Introduction
The tests in `althea_rs` are primarily focused around verifying correctness of
  Rita - Althea's main daemon. All non-unit tests are located in the `integration-tests/` subdirectory. Unit tests are handled using the standard `tests` module approach - you can read more about it [here](https://doc.rust-lang.org/rust-by-example/testing/unit_testing.html).

# Unit tests
The unit tests should be the easiest for anyone to get working. Since
`althea_rs` uses Cargo workspaces it is necessary to specify the `--all` flag so
that all member crates get tested. Also, because of some of our dependencies, we
need to run the tests single-threaded.
```shell
$ RUST_TEST_THREADS=1 cargo test --all
```

# Integration test suite
Integration tests account for the biggest chunk of our CI testing. They're done
using two scripts - `rita.sh` and `rita.py`. The shell script takes care of
fetching and building dependencies as well as `althea_rs`, while `rita.py` does
the actual verification of Rita's network management and accounting using a
virtual mesh based on [network
namespaces](https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/) connected with [veth interfaces](http://man7.org/linux/man-pages/man4/veth.4.html).

## The integration test mesh topology
```plain
        4
        |
        |
        2---3
        |   |
        |   |
    1---6---7---5 <- Node 5 runs the `rita_exit` exit daemon
```

## Running
Enter your local `althea_rs` repo and run:
```shell
$ cd integration-tests; ./rita.sh
```
The script should ask you to enter a password for sudo to install Python
dependencies; network namespace operations are also privileged. After you put in
your password the testing will begin and exit normally or with an error
depending on the result.

## What exactly do we test for?
First, `rita.py` will set up the network namespaces using a
[fork](https://github.com/kingoflolz/network-lab) of
[`network-lab`](https://github.com/sudomesh/network-lab). Then, it'll wait and
probe Babel for convergence within a configurable time period (See
`CONVERGENCE_DELAY` [here](#configuration) and in `rita.py`). Once the
test mesh has converged in a timely manner, `rita.py` proceeds to check if each
node's instance of Rita is paying its peers on time in different scenarios.

## Configuration
All `rita.sh` and `rita.py` configuration is done using environment variables.
Here's what they are and what they do:
- `rita.sh`
  - `BABELD_DIR` - The location to pull Babel into
  - `NETLAB_PATH` - The location of the network-lab script to use
  - `REMOTE_A` - Where to download release A from
  - `REVISION_A` - Where to check out release A
  - `DIR_A` - Where to clone `REMOTE_A` into
  - `REMOTE_B` - Where to download release B from
  - `REVISION_B` - Where to check out release B
  - `DIR_B` - Where to clone `REMOTE_B` into
  - `NO_PULL` - If set assume both releases were already pulled into `DIR_A` and
    `DIR_B` (great for quick rebuilds without starting from scratch or when your
    bandwidth is limited)
  - `COMPAT_LAYOUT` - Choose the node -> release map for the test mesh. Setting
    this variable to one of the layouts in `COMPAT_LAYOUTS` in `rita.py` enables
    backwards-compatibility test mode which will download Both A/B releases. If
    not set, it builds and tests the current `althea_rs` repo
- `rita.py`
  - `RITA_A`, `RITA_EXIT_A` - Release A binaries (`rita` and
    `rita_exit`), falls back to defaults, which are our
`althea_rs`'s binaries
  - `RITA_B`, `RITA_EXIT_B` - Same but for release B
  - `COMPAT_LAYOUT` - The node -> release map to apply on the test mesh
  - `BACKOFF_FACTOR` - The factor by which the next convergence poll delay is
    multiplied; this is to decrease the interference of accessing the Babel
    config socket with convergence
  - `CONVERGENCE_DELAY` - How long (in seconds) we're going to wait for the test
    mesh to converge. If it takes longer, `rita.py` fails
  - `DEBUG` - If set enables debug mode which pauses the script just after
    convergence for manual mesh examination
  - `INITIAL_POLL_INTERVAL` - How long (initially) are we going to wait until
    the next convergence poll?
  - `PING6` - Which IPv6 ping are we going to use? (Great for distros which use
    `ping -6` and not `ping6`)
  - `VERBOSE` - If set, print more information to the standard output; set by
    default in CI

## Backwards compatibility test mode
The test scripts enable us to use a special backwards compatibility mode in
which we can test two arbitrary `althea_rs` releases - A (the new one) and B (the
old one).

The minimum backwards-compat command would be:
```shell
$ COMPAT_LAYOUT=old_exit ./rita.sh
```

You can change the remotes and revisions used using the `*_A` and `*_B`
variables listed above, which default to building the `master` and `release` branches of
`althea-mesh/althea_rs`, respectively.

## Backwards compatibility test layouts
- `old_exit` - The exit is assigned release B while all the other nodes sport
  release A
- `new_exit` - The opposite of `old_exit`
- `random` - Assigns releases randomly

You can add your own layouts to the `COMPAT_LAYOUTS` dictionary in `rita.py`.

## Limitations
The backwards-compat tests are prone to discarding two perfectly working
releases if we choose to change the way we read data off Rita, i.e. the "Rita to
Rita" APIs might be compatible or even the same between the releases while e.g.
a different log entry format might cause the parsing code in `rita.py` to break.

# Cross compilation testing
`althea_rs` has a history of getting broken by new dependencies which aren't
always cross compilation friendly. Because of that, we've created a script that
will fetch a prebuilt OpenWRT toolchain tarball and build `althea_rs` against
it. You can run it with
```shell
$ ./cross-build.sh
```
inside the `integration-tests` directory.
