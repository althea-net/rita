use crate::{
    payments_althea::get_althea_evm_priv,
    payments_eth::{eth_chain_id, get_eth_miner_key, get_miner_address, ONE_ETH, WEB3_TIMEOUT},
    setup_utils::{
        namespaces::{get_nsfd, Namespace, NamespaceInfo, NodeType, RouteHop},
        rita::InstanceData,
    },
};
use actix_rt::time::sleep;
use actix_rt::System;
use althea_kernel_interface::run_command;
use althea_proto::cosmos_sdk_proto::cosmos::gov::v1beta1::VoteOption;
use althea_proto::{
    canto::erc20::v1::RegisterCoinProposal,
    cosmos_sdk_proto::cosmos::bank::v1beta1::{
        query_client::QueryClient, Metadata, QueryDenomMetadataRequest,
    },
};
use althea_types::{
    regions::Regions, ContactType, Denom, ExitIdentity, Identity, SystemChain, WgKey,
};
use babel_monitor::{open_babel_stream, parse_routes, structs::Route};
use clarity::PrivateKey as ClarityPrivkey;
use clarity::{Address, Transaction, Uint256};
use deep_space::{Address as AltheaAddress, Coin, Contact, CosmosPrivateKey, PrivateKey};
use exit_trust_root_lib::client_db::{add_exit_admin, add_exits_to_registration_list};
use futures::future::join_all;
use ipnetwork::IpNetwork;
use lazy_static;
use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
};
use phonenumber::PhoneNumber;
use rita_common::{
    debt_keeper::GetDebtsResult,
    payment_validator::{ALTHEA_CHAIN_PREFIX, ALTHEA_CONTACT_TIMEOUT},
};
use settings::{
    client::RitaClientSettings,
    exit::{ExitNetworkSettings, RitaExitSettingsStruct},
    localization::LocalizationSettings,
    logging::LoggingSettings,
    network::NetworkSettings,
    operator::ExitOperatorSettings,
    payment::PaymentSettings,
};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
    process::Command,
    str::from_utf8,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv4Addr},
};
use web30::{client::Web3, jsonrpc::error::Web3Error, types::SendTxOption};

/// Wait this long for network convergence
const REACHABILITY_TEST_TIMEOUT: Duration = Duration::from_secs(180);
/// How long the reacability test should wait in between tests
const REACHABILITY_TEST_CHECK_SPEED: Duration = Duration::from_secs(5);
/// Pay thresh used in payment tests, 3c in wei
pub const TEST_PAY_THRESH: u64 = 30_000_000_000_000_000u64;

pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

pub const NODE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 1));

pub const STAKING_TOKEN: &str = "aalthea";
pub const MIN_GLOBAL_FEE_AMOUNT: u128 = 10;
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
/// The maximum difference between routers in the debts test, keep in mind that
/// due to race conditions this has to be decently large to avoid false positives
/// as debts will only be exactly the same once the speedtest has completed and
/// both sides have had time to handle their accounting loops, you'll observe that
/// accuracy is the worst immediately following the iperf3 and then trends to 100% accurate
pub const DEBT_ACCURACY_THRES: u8 = 20;
pub const REGISTRATION_SERVER_KEY: &str =
    "0x34d97aaf58b1a81d3ed3068a870d8093c6341cf5d1ef7e6efa03fe7f7fc2c3a8";

lazy_static! {
    pub static ref TEST_EXIT_DETAILS: HashMap<String, ExitInfo> = {
        let mut details = HashMap::new();
        let instance_4_name = "test_4".to_string();

        let instance_4 = Identity {
            mesh_ip: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 4)),
            wg_public_key: "bvM10HW73yePrxdtCQQ4U20W5ogogdiZtUihrPc/oGY="
                .parse()
                .unwrap(),
            eth_address: "0xc615875cba92d1cc472b9cffae25d56ca800f728688fc7faab601652b636183d"
                .parse::<clarity::PrivateKey>()
                .unwrap()
                .to_address(),
            nickname: None,
        };

        let exit_4 = ExitInfo {
            exit_id: instance_4,
            wg_priv_key: "OGzbcm6czrjOEAViK7ZzlWM8mtjCxp7UPbuLS/dATV4="
                .parse()
                .unwrap(),
            subnet: Ipv6Addr::new(0xfbad, 200, 0, 0, 0, 0, 0, 0),
            eth_private_key: "0xc615875cba92d1cc472b9cffae25d56ca800f728688fc7faab601652b636183d"
                .parse()
                .unwrap(),
        };

        let instance_5_name = "test_5".to_string();
        let instance_5 = Identity {
            mesh_ip: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),

            wg_public_key: "R8F6IhDvy6PwcENEFQEBZXEY2fi6jEvmPTVvleR1IUw="
                .parse()
                .unwrap(),
            eth_address: "0x09307a1687fe3ea745fb46f97612aa3d1ded864c4e7e7617f984fd7296d0f6fa"
                .parse::<clarity::PrivateKey>()
                .unwrap()
                .to_address(),
            nickname: None,
        };
        let exit_5 = ExitInfo {
            exit_id: instance_5,
            wg_priv_key: "SEBve3ERCYCriBEfNFnWbED5OwWo/Ylppg1KEt0HZnA="
                .parse()
                .unwrap(),
            subnet: Ipv6Addr::new(0xfbad, 400, 0, 0, 0, 0, 0, 0),
            eth_private_key: "0x09307a1687fe3ea745fb46f97612aa3d1ded864c4e7e7617f984fd7296d0f6fa"
                .parse::<clarity::PrivateKey>()
                .unwrap(),
        };
        details.insert(instance_4_name, exit_4);
        details.insert(instance_5_name, exit_5);

        details
    };
}

pub struct ExitInfo {
    pub exit_id: Identity,
    // Params used in exit spawn
    pub wg_priv_key: WgKey,
    pub subnet: Ipv6Addr,
    pub eth_private_key: clarity::PrivateKey,
}

pub fn get_althea_grpc() -> String {
    format!("http://{}:9090", NODE_IP)
}

pub fn get_eth_node() -> String {
    format!("http://{}:8545", NODE_IP)
}

pub fn get_test_runner_magic_phone() -> PhoneNumber {
    "+17040000000".parse().unwrap()
}

pub async fn deploy_contracts() -> Address {
    let contact = Contact::new(
        &get_althea_grpc(),
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    // prevents the node deployer from failing (rarely) when the chain has not
    // yet produced the next block after submitting each eth address
    contact.wait_for_next_block(TOTAL_TIMEOUT).await.unwrap();

    let location_a = "/althea_rs/solidity/contract-deployer.ts";
    let location_b = "solidity/contract-deployer.ts";
    let location = if std::path::Path::new(location_a).exists() {
        location_a
    } else if std::path::Path::new(location_b).exists() {
        location_b
    } else {
        panic!("Could not find contract deployer file!")
    };

    let res = Command::new("npx")
        .args([
            "ts-node",
            location,
            &format!("--eth-privkey={}", REGISTRATION_SERVER_KEY),
            &format!("--eth-node={}", get_eth_node()),
        ])
        .output()
        .expect("Failed to deploy contracts!");

    error!(
        "Contract deploy stderr: {}",
        from_utf8(&res.stderr).unwrap()
    );
    let contract_addr = from_utf8(&res.stdout).unwrap();
    info!("Contract is: {}", contract_addr);
    let mut res = contract_addr.split(' ').next_back().unwrap().to_string();
    res.pop();
    res.parse().unwrap()
}

/// Test pingability waiting and failing if it is not successful
pub fn test_reach_all(nsinfo: NamespaceInfo) {
    let start = Instant::now();
    while !test_reach_all_async(nsinfo.clone()) {
        if Instant::now() - start > REACHABILITY_TEST_TIMEOUT {
            panic!("Failed to ping all destinations! Did not converge")
        }
        thread::sleep(REACHABILITY_TEST_CHECK_SPEED)
    }
    info!("All nodes are rechable via ping!");
}

/// test pingability between namespaces on babel routes, returns true if all pings are successful
pub fn test_reach_all_async(nsinfo: NamespaceInfo) -> bool {
    for i in nsinfo.clone().names {
        for j in nsinfo.clone().names {
            if !test_reach(i.clone(), j.clone()) {
                // ping failed
                error!("Ping for {:?} to {:?} failed, retrying...", i, j);
                return false;
            }
        }
    }
    true
}

/// Returns true if the ping is successful
fn test_reach(from: Namespace, to: Namespace) -> bool {
    // todo replace with oping
    // ip netns exec n-1 ping6 fd00::2
    let ip = format!("fd00::{}", to.id);
    let errormsg = format!(
        "Could not run ping6 from {} to {}",
        from.get_name(),
        to.get_name()
    );
    let output = run_command(
        "ip",
        &["netns", "exec", &from.get_name(), "ping6", &ip, "-c", "1"],
    )
    .expect(&errormsg);
    trace!(
        "ping output: {output:?} end status is {}",
        output.status.success()
    );
    output.status.success()
}

/// Tests routes, waiting until they are all found and panicing if that does not happen
pub fn test_routes(nsinfo: NamespaceInfo, expected: HashMap<Namespace, RouteHop>) {
    let start = Instant::now();
    while !test_routes_async(nsinfo.clone(), expected.clone()) {
        if Instant::now() - start > REACHABILITY_TEST_TIMEOUT {
            panic!("Failed to locate all Babel routes, network did not converge!")
        }
        thread::sleep(REACHABILITY_TEST_CHECK_SPEED)
    }
    info!("All routes found, network converged!");
}

/// check the presence of all optimal routes, returns false if there is a route missing
pub fn test_routes_async(nsinfo: NamespaceInfo, expected: HashMap<Namespace, RouteHop>) -> bool {
    // add ALL routes for each namespace into a map to search through for the next portion
    let mut routesmap = HashMap::new();
    for ns in nsinfo.clone().names {
        // create a thread in the babel namespace, ask it about routes, then join to bring that
        // data back to this thread in the default namespace
        let rita_handler = thread::spawn(move || {
            let nspath = format!("/var/run/netns/{}", ns.get_name());
            let nsfd = open(nspath.as_str(), OFlag::O_RDONLY, Mode::empty())
                .unwrap_or_else(|_| panic!("Could not open netns file: {}", nspath));
            setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
            let babel_port = settings::get_rita_common().network.babel_port;

            if let Ok(mut stream) = open_babel_stream(babel_port, Duration::from_secs(4)) {
                if let Ok(babel_routes) = parse_routes(&mut stream) {
                    routesmap.insert(ns.get_name(), babel_routes);
                    routesmap
                } else {
                    routesmap
                }
            } else {
                routesmap
            }
        });
        routesmap = rita_handler.join().unwrap();
    }
    for ns1 in nsinfo.clone().names {
        for ns2 in &nsinfo.names {
            if &ns1 == ns2 {
                continue;
            }

            let routes = routesmap.get(&ns1.get_name()).unwrap();
            //within routes there must be a route that matches the expected price between the dest (fd00::id) and the expected next hop (fe80::id)

            if !try_route(&expected, routes, ns1.clone(), ns2.clone()) {
                warn!(
                    "No route found for {:?}, {:?}, retrying...",
                    ns1.get_name(),
                    ns2.get_name()
                );
                trace!(
                    "We where expecting {:?} and found {:#?}",
                    expected.get(&ns1).unwrap(),
                    routes
                );
                return false;
            }
        }
    }
    true
}

pub fn test_all_internet_connectivity(namespaces: NamespaceInfo) {
    for ns in namespaces.names {
        let start = Instant::now();
        loop {
            let out = run_command(
                "ip",
                &[
                    "netns",
                    "exec",
                    &ns.get_name(),
                    "ping",
                    &NODE_IP.to_string(),
                    "-c",
                    "1",
                ],
            )
            .unwrap();
            let output_string = from_utf8(&out.stdout).unwrap();
            if output_string.contains("1 received") {
                info!("Ping test passed for {}!", ns.get_name());
                break;
            } else {
                if Instant::now() - start > Duration::from_secs(60) {
                    panic!("{} does not have internet connectivity", ns.get_name());
                }
                error!(
                    "Ping failed for {} with {}, trying again",
                    ns.get_name(),
                    output_string
                );
                thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

/// Look for an installed route given our expected list between ns1 and ns2
fn try_route(
    expected: &HashMap<Namespace, RouteHop>,
    routes: &Vec<Route>,
    ns1: Namespace,
    ns2: Namespace,
) -> bool {
    let expected_data = expected
        .get(&ns1)
        .unwrap()
        .destination
        .get(&ns2.id)
        .unwrap();
    let expected_cost = expected_data.clone().price;
    let ns2_id: u16 = ns2.id;
    let dest_ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, ns2_id));
    for r in routes {
        if let IpNetwork::V6(ref ip) = r.prefix {
            if ip.ip() == dest_ip && (r.price != expected_cost || r.fee != expected_cost) {
                error!(
                    "Failed to route match expected price {} found {} or fee {} found {}",
                    expected_cost, r.price, expected_cost, r.fee
                );
            }

            if ip.ip() == dest_ip && r.price == expected_cost && r.fee == ns1.cost {
                return true;
            } else {
                continue;
            }
        }
    }

    false
}

pub const TEST_EXIT_NAME: &str = "test";
/// The root ip is the ip all exits share in a cluster where the client goes and grabs the list of other exits to roam to
pub const EXIT_ROOT_IP: IpAddr =
    IpAddr::V6(Ipv6Addr::new(0xfd00, 200, 199, 198, 197, 196, 195, 194));
// this masks public ipv6 ips in the test env and is being used to test assignment
pub const EXIT_SUBNET: Ipv6Addr = Ipv6Addr::new(0xfbad, 200, 0, 0, 0, 0, 0, 0);
pub const EXIT_ROOT_SERVER_URL: &str = "http://10.0.0.1:4050";

pub fn get_exit_root_private_key() -> ClarityPrivkey {
    get_eth_miner_key()
}

/// Gets the default client and exit settings
pub fn get_default_settings(
    namespaces: NamespaceInfo,
    exit_db_contract: Address,
) -> (RitaClientSettings, RitaExitSettingsStruct, Address) {
    let mut exit_servers = HashMap::new();
    let exit_root_addr = get_exit_root_private_key().to_address();
    info!("Exit root address is {:?}", exit_root_addr);
    let exit = RitaExitSettingsStruct {
        workers: 2,
        remote_log: false,
        description: "Test environment exit instance".to_string(),
        payment: PaymentSettings::default(),
        localization: LocalizationSettings::default(),
        network: NetworkSettings::default(),
        exit_network: ExitNetworkSettings::test_default(),
        allowed_countries: HashSet::new(),
        log: LoggingSettings::default(),
        operator: ExitOperatorSettings::default(),
        exit_root_url: EXIT_ROOT_SERVER_URL.to_owned(),
    };
    let client = RitaClientSettings::default();

    let mut exit_mesh_ips = HashSet::new();
    for ns in namespaces.names {
        if let NodeType::Exit { instance_name } = ns.node_type.clone() {
            exit_mesh_ips.insert(get_ip_from_namespace(ns));
            let exit_id = TEST_EXIT_DETAILS.get(&instance_name).unwrap();

            let mut payment_types = HashSet::new();
            payment_types.insert(SystemChain::AltheaL1);
            payment_types.insert(SystemChain::Xdai);

            exit_servers.insert(
                exit_id.exit_id.mesh_ip,
                ExitIdentity {
                    mesh_ip: exit_id.exit_id.mesh_ip,
                    wg_key: exit_id.exit_id.wg_public_key,
                    eth_addr: exit_id.exit_id.eth_address,
                    registration_port: exit.exit_network.exit_hello_port,
                    wg_exit_listen_port: exit.exit_network.wg_tunnel_port,
                    allowed_regions: HashSet::new(),
                    payment_types,
                },
            );
        }
    }

    let mut exit = exit.clone();
    let mut client = client.clone();
    client.payment.contact_info = Some(
        ContactType::Both {
            number: get_test_runner_magic_phone(),
            email: "fake@fake.com".parse().unwrap(),
            sequence_number: Some(0),
        }
        .into(),
    );

    let key: ClarityPrivkey = REGISTRATION_SERVER_KEY.parse().unwrap();
    client.exit_client.allowed_exit_list_signers = vec![key.to_address()];
    client.exit_client.exit_db_smart_contract = exit_db_contract;

    // first node is passed through to the host machine for testing second node is used
    // for testnet queries
    exit.payment.althea_grpc_list = vec![get_althea_grpc()];
    exit.payment.eth_node_list = vec![get_eth_node()];
    client.payment.althea_grpc_list = vec![get_althea_grpc()];
    client.payment.eth_node_list = vec![get_eth_node()];
    (client, exit, exit_root_addr)
}

pub fn althea_system_chain_client(settings: RitaClientSettings) -> RitaClientSettings {
    let mut settings = settings;
    settings.payment.system_chain = SystemChain::AltheaL1;
    settings.payment.payment_threshold = TEST_PAY_THRESH.into();
    let denom = Denom {
        denom: "uUSDC".to_string(),
        decimal: 1_000_000u64,
    };
    settings.payment.althea_l1_payment_denom = denom.clone();
    settings.payment.althea_l1_accepted_denoms = vec![denom];
    settings
}

pub fn althea_system_chain_exit(settings: RitaExitSettingsStruct) -> RitaExitSettingsStruct {
    let mut settings = settings;
    settings.payment.system_chain = SystemChain::AltheaL1;

    // set pay thres to a smaller value
    settings.payment.payment_threshold = TEST_PAY_THRESH.into();
    let denom = Denom {
        denom: "uUSDC".to_string(),
        decimal: 1_000_000u64,
    };
    settings.payment.althea_l1_payment_denom = denom.clone();
    settings.payment.althea_l1_accepted_denoms = vec![denom];
    settings
}

// Calls the register to exit rpc function within the provided namespace
pub async fn register_to_exit(namespace_name: String) -> bool {
    // thread safe lock that allows us to pass data between the router thread and this thread
    // one copy of the reference is sent into the closure and the other is kept in this scope.
    let response: Arc<RwLock<Option<bool>>> = Arc::new(RwLock::new(None));
    let response_local = response.clone();
    let namespace_local = namespace_name.clone();
    const TIMEOUT: Duration = Duration::from_secs(15);

    let _ = thread::spawn(move || {
        // set the host of this thread to the ns
        let nsfd = get_nsfd(namespace_name);
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
        let runner = System::new();
        runner.block_on(async move {
            let client = awc::Client::default();
            let start = Instant::now();
            // this thread tries forever until timeout, then it updates the response lock
            // so the outer thread can see the result
            while start.elapsed() < TIMEOUT {
                let req = client
                    .post("http://localhost:4877/exit/register")
                    .send()
                    .await
                    .expect("Failed to make request to rita RPC");

                if !req.status().is_success() {
                    warn!("Failed to register to exit, retrying...");
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }

                let req = client
                    .post("http://localhost:4877/exit/verify/1111".to_string())
                    .send()
                    .await
                    .expect("Failed to make request to rita RPC");

                if !req.status().is_success() {
                    warn!("Failed to register verify exit, retrying...");
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }

                // we mark the success flag
                *response.write().unwrap() = Some(true);
                return;
            }
            error!("Failed to register to exit, timeout reached!");
            // if we reach here we have failed to register
            *response.write().unwrap() = Some(false);
        })
    });

    // wait for the child thread to finish performing it's query, with our own
    // timeout in case the inner thread gets lost/stuck
    let start = Instant::now();
    while response_local.read().unwrap().is_none() {
        info!("Waiting for a rpc response from {}", namespace_local);
        sleep(Duration::from_millis(100)).await;
        if start.elapsed() > TIMEOUT * 2 {
            panic!("Timeout waiting for response from {}", namespace_local);
        }
    }
    let code = response_local.read().unwrap().unwrap();
    code
}

/// This allows the tester to exit cleanly then it gets a ctrl-c message
/// allowing you to reuse a test env and save a lot of setup
pub fn set_sigterm() {
    //Setup a SIGTERM hadler
    ctrlc::set_handler(move || {
        info!("received Ctrl+C!");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");
}

/// Run an iperf to generate from between two namespaces. data represents the string
/// representation to pass into iperf. For example '10G' or '15M'
/// When to is None, traffic is generated to the internet/exit
pub fn generate_traffic(from: Namespace, to: Option<Namespace>, data: String) {
    let ip = match &to {
        Some(a) => format!("fd00::{}", a.id),
        None => NODE_IP.to_string(),
    };

    // setup server
    info!(
        "Going to setup server, spawning new thread from {:?} to {:?}",
        from, to
    );
    thread::spawn(move || {
        info!("In new thread about to start iperf server");
        let output = if let Some(ns) = to {
            run_command(
                "ip",
                &["netns", "exec", &ns.get_name(), "iperf3", "-s", "-1"],
            )
            .expect("Could not setup iperf server")
        } else {
            run_command("iperf3", &["-s", "-1"]).expect("Could not setup iperf server")
        };

        let stderr = from_utf8(&output.stderr).expect("Why is this failing");
        let std_output = from_utf8(&output.stdout).expect("could not get output for client setup!");
        if !std_output.is_empty() {
            info!("Server out: {}", std_output);
        } else {
            panic!(
                "Iperf server failed to generate traffic with status {} and stderr {}",
                output.status, stderr
            );
        }
    });

    // iperf client
    info!("Going to setup client");
    let ticker = Instant::now();
    loop {
        let output = run_command(
            "ip",
            &[
                "netns",
                "exec",
                &from.get_name(),
                "iperf3",
                "-c",
                &ip,
                "-n",
                &data,
            ],
        )
        .expect("Could not setup iperf client");

        let stderr = from_utf8(&output.stderr).expect("Why is this failing");
        let std_output = from_utf8(&output.stdout).expect("could not get output for client setup!");
        if !std_output.is_empty() {
            info!("Client out: {}", std_output);
            break;
        } else if stderr.contains("Connection refused") || stderr.contains("Bad file descriptor") {
            info!("server not set up yet");
            thread::sleep(Duration::from_millis(100));
        } else {
            panic!(
                "Iperf failed to generate traffic with status {} and stderr {}",
                output.status, stderr
            );
        }
        if Instant::now() - ticker > Duration::from_secs(20) {
            panic!("Traffic loop has been running for too long");
        }
    }
}

pub fn get_ip_from_namespace(node: Namespace) -> String {
    format!("fd00::{}", node.id)
}

/// Given a vec of nodes, query their endpoint for node debts. for_node is optional in case of none, we simply
/// return the debts for all nodes for a given node.
pub async fn query_debts(
    nodes: Vec<Namespace>,
    for_nodes: Option<Vec<Namespace>>,
) -> HashMap<Namespace, Vec<GetDebtsResult>> {
    // When for node is none, get all debts for a node
    let for_node_ips = match for_nodes {
        Some(a) => {
            let mut map = HashSet::new();
            for node in a {
                map.insert(get_ip_from_namespace(node));
            }
            map
        }
        None => HashSet::new(),
    };

    let mut ret_map = HashMap::new();

    for node in nodes {
        let response: Arc<RwLock<Option<Vec<GetDebtsResult>>>> = Arc::new(RwLock::new(None));
        let response_local = response.clone();
        let node_name: String = node.get_name();

        let _ = thread::spawn(move || {
            info!("Starting inner thraed");
            // set the host of this thread to the ns
            let nsfd = get_nsfd(node_name);
            setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
            let runner = System::new();
            runner.block_on(async move {
                let client = awc::Client::default();
                let mut req = client
                    .get("http://localhost:4877/debts".to_string())
                    .send()
                    .await
                    .expect("Failed to make request to rita RPC");
                let res = match req.json().await {
                    Err(e) => panic!("Why is get debts failing: {}", e),
                    Ok(a) => a,
                };
                *response.write().unwrap() = Some(res);
            })
        });

        // wait for the child thread to finish performing it's query
        const TIMEOUT: Duration = Duration::from_secs(30);
        let start = Instant::now();
        while response_local.read().unwrap().is_none() {
            info!(
                "Waiting for a rpc response from {}",
                node.clone().get_name()
            );
            sleep(Duration::from_millis(100)).await;
            if Instant::now() - start > TIMEOUT {
                panic!(
                    "Timeout waiting for response from {}",
                    node.clone().get_name()
                );
            }
        }

        let list = response_local.read().unwrap().clone().unwrap();

        let mut ret = vec![];
        if !for_node_ips.is_empty() {
            for e in list.clone() {
                if for_node_ips.contains(&e.identity.mesh_ip.to_string()) {
                    ret.push(e.clone())
                }
            }
        } else {
            ret = list;
        }

        ret_map.insert(node, ret);
    }
    ret_map
}

#[derive(Debug, Clone)]
pub struct ValidatorKeys {
    /// The validator key used by this validator to actually sign and produce blocks
    pub validator_key: CosmosPrivateKey,
    // The mnemonic phrase used to generate validator_key
    pub validator_phrase: String,
}
// Simple arguments to create a proposal with
pub struct RegisterCoinProposalParams {
    pub coin_metadata: Metadata,

    pub proposal_title: String,
    pub proposal_desc: String,
}

pub fn get_deposit() -> Coin {
    Coin {
        denom: STAKING_TOKEN.to_string(),
        amount: 1_000_000_000u64.into(),
    }
}

pub fn get_fee(denom: Option<String>) -> Coin {
    match denom {
        None => Coin {
            denom: STAKING_TOKEN.to_string(),
            amount: MIN_GLOBAL_FEE_AMOUNT.into(),
        },
        Some(denom) => Coin {
            denom,
            amount: MIN_GLOBAL_FEE_AMOUNT.into(),
        },
    }
}

pub async fn vote_yes_with_retry(
    contact: &Contact,
    proposal_id: u64,
    key: impl PrivateKey,
    timeout: Duration,
) {
    const MAX_VOTES: u64 = 5;
    let mut counter = 0;
    let mut res = contact
        .vote_on_gov_proposal(
            proposal_id,
            VoteOption::Yes,
            get_fee(None),
            key.clone(),
            Some(timeout),
        )
        .await;
    while let Err(e) = res {
        info!("Vote failed with {:?}", e);
        contact.wait_for_next_block(TOTAL_TIMEOUT).await.unwrap();
        res = contact
            .vote_on_gov_proposal(
                proposal_id,
                VoteOption::Yes,
                get_fee(None),
                key.clone(),
                Some(timeout),
            )
            .await;
        counter += 1;
        if counter > MAX_VOTES {
            error!(
                "Vote for proposal has failed more than {} times, error {:?}",
                MAX_VOTES, e
            );
            panic!("failed to vote{}", e);
        }
    }
    let res = res.unwrap();
    info!(
        "Voting yes on governance proposal costing {} gas",
        res.gas_used()
    );
}

pub async fn vote_yes_on_proposals(
    contact: &Contact,
    keys: &[ValidatorKeys],
    timeout: Option<Duration>,
) {
    let duration = match timeout {
        Some(dur) => dur,
        None => OPERATION_TIMEOUT,
    };
    // Vote yes on all proposals with all validators
    let proposals = contact
        .get_governance_proposals_in_voting_period()
        .await
        .unwrap();
    trace!("Found proposals: {:?}", proposals.proposals);
    let mut futs = Vec::new();
    for proposal in proposals.proposals {
        for key in keys.iter() {
            let res =
                vote_yes_with_retry(contact, proposal.proposal_id, key.validator_key, duration);
            futs.push(res);
        }
    }
    // vote on the proposal in parallel, reducing the number of blocks we wait for all
    // the tx's to get in.
    join_all(futs).await;
}

pub async fn wait_for_proposals_to_execute(contact: &Contact) {
    let start = Instant::now();
    loop {
        let proposals = contact
            .get_governance_proposals_in_voting_period()
            .await
            .unwrap();
        if Instant::now() - start > TOTAL_TIMEOUT {
            panic!("Gov proposal did not execute")
        } else if proposals.proposals.is_empty() {
            return;
        }
        sleep(Duration::from_secs(5)).await;
    }
}

pub async fn execute_register_coin_proposal(
    contact: &Contact,
    keys: &[ValidatorKeys],
    timeout: Option<Duration>,
    coin_params: RegisterCoinProposalParams,
    // true if we should wait for the proposal to execute
    wait: bool,
) {
    let duration = match timeout {
        Some(dur) => dur,
        None => OPERATION_TIMEOUT,
    };

    let proposal = RegisterCoinProposal {
        title: coin_params.proposal_title,
        description: coin_params.proposal_desc,
        metadata: Some(coin_params.coin_metadata),
    };
    let res = contact
        .submit_register_coin_proposal(
            proposal,
            get_deposit(),
            get_fee(None),
            keys[0].validator_key,
            Some(duration),
        )
        .await
        .unwrap();
    info!("Gov proposal executed with {:?}", res.raw_log());

    vote_yes_on_proposals(contact, keys, None).await;
    if wait {
        wait_for_proposals_to_execute(contact).await;
    }
}

fn parse_phrases(filename: &str) -> (Vec<CosmosPrivateKey>, Vec<String>) {
    let file = File::open(filename).expect("Failed to find phrases");
    let reader = BufReader::new(file);
    let mut ret_keys = Vec::new();
    let mut ret_phrases = Vec::new();

    for line in reader.lines() {
        let phrase = line.expect("Error reading phrase file!");
        if phrase.is_empty()
            || phrase.contains("write this mnemonic phrase")
            || phrase.contains("recover your account if")
        {
            continue;
        }
        let key = CosmosPrivateKey::from_phrase(&phrase, "").expect("Bad phrase!");
        ret_keys.push(key);
        ret_phrases.push(phrase);
    }
    (ret_keys, ret_phrases)
}

pub fn parse_validator_keys() -> (Vec<CosmosPrivateKey>, Vec<String>) {
    let filename = "/validator-phrases";
    info!("Reading mnemonics from {}", filename);
    parse_phrases(filename)
}

pub fn get_keys() -> Vec<ValidatorKeys> {
    let (cosmos_keys, cosmos_phrases) = parse_validator_keys();
    let mut ret = Vec::new();
    for (c_key, c_phrase) in cosmos_keys.into_iter().zip(cosmos_phrases) {
        ret.push(ValidatorKeys {
            validator_key: c_key,
            validator_phrase: c_phrase,
        })
    }
    ret
}

pub async fn register_erc20_usdc_token(wait: bool) {
    let althea_contact = Contact::new(
        &get_althea_grpc(),
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();
    //register uUSDC as a ERC20
    let mut bank_qc = QueryClient::connect(althea_contact.get_url())
        .await
        .expect("Unable to connect to bank query client");
    let metadata = bank_qc
        .denom_metadata(QueryDenomMetadataRequest {
            denom: "uUSDC".to_string(),
        })
        .await
        .expect("Unable to query denom metadata")
        .into_inner()
        .metadata
        .expect("No metadata for erc20 coin");

    let coin_params = RegisterCoinProposalParams {
        coin_metadata: metadata.clone(),
        proposal_desc: "Register Coin Proposal Description".to_string(),
        proposal_title: "Register Coin Proposal Title".to_string(),
    };
    execute_register_coin_proposal(
        &althea_contact,
        &get_keys(),
        Some(TOTAL_TIMEOUT),
        coin_params,
        wait,
    )
    .await;
}

pub async fn send_althea_tokens(addresses: Vec<AltheaAddress>) {
    // Create a contact object and get our balance
    let althea_contact = Contact::new(
        &get_althea_grpc(),
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();

    for router_address in addresses {
        let althea_coin = Coin {
            amount: 50000000000u64.into(),
            denom: "aalthea".to_string(),
        };

        let tx2 = althea_contact
            .send_microtx(
                althea_coin,
                None,
                router_address,
                Some(Duration::from_secs(30)),
                None,
                get_althea_evm_priv(),
            )
            .await;
        if tx2.is_err() {
            panic!("{:?}", tx2)
        }
        //Send each router 50 usdc
        let coin = Coin {
            amount: 50000000u64.into(),
            denom: "uUSDC".to_string(),
        };
        let tx = althea_contact
            .send_microtx(
                coin.clone(),
                None,
                router_address,
                Some(Duration::from_secs(30)),
                None,
                get_althea_evm_priv(),
            )
            .await;
        if tx.is_err() {
            panic!("{:?}", tx)
        }
    }
}

pub async fn print_althea_balances(addresses: Vec<AltheaAddress>, denom: String) -> Vec<Coin> {
    let althea_contact = Contact::new(
        &get_althea_grpc(),
        ALTHEA_CONTACT_TIMEOUT,
        ALTHEA_CHAIN_PREFIX,
    )
    .unwrap();

    let mut ret = vec![];
    for router_address in addresses {
        // Whats our usdc balance?
        match althea_contact
            .get_balance(router_address, denom.clone())
            .await
        {
            Ok(a) => ret.push(a.unwrap()),
            Err(e) => {
                panic!(
                    "Unable to get balance for wallet {:?} with {:?}",
                    router_address, e
                );
            }
        };
    }
    ret
}

// Relies on nodes to be named using fd00::5, fd00::25 etc
pub fn get_node_id_from_ip(ip: IpAddr) -> u16 {
    let exit_4 = IpAddr::V6(Ipv6Addr::new(0xfd00, 200, 199, 198, 197, 196, 195, 194));
    let exit_5 = IpAddr::V6(Ipv6Addr::new(0xfd00, 400, 399, 398, 397, 396, 395, 394));

    if ip == exit_4 {
        return 4;
    }
    if ip == exit_5 {
        return 5;
    }
    let addr = ip.to_string();
    addr.split("::").last().unwrap().parse().unwrap()
}

pub const HIGH_GAS_PRICE: u64 = 1_000_000_000u64;

/// This function efficiently distributes ETH to a large number of provided Ethereum addresses
/// the real problem here is that you can't do more than one send operation at a time from a
/// single address without your sequence getting out of whack. By manually setting the nonce
/// here we can quickly send thousands of transactions in only a few blocks
pub async fn send_eth_bulk(amount: Uint256, destinations: &[clarity::Address], web3: &Web3) {
    let mut nonce = web3
        .eth_get_transaction_count(get_miner_address())
        .await
        .unwrap();
    let mut transactions = Vec::new();
    for address in destinations {
        let t = Transaction::Eip1559 {
            chain_id: eth_chain_id(),
            to: *address,
            nonce,
            max_fee_per_gas: HIGH_GAS_PRICE.into(),
            max_priority_fee_per_gas: 0u8.into(),
            gas_limit: 24000u64.into(),
            value: amount,
            data: Vec::new(),
            signature: None,
            access_list: Vec::new(),
        };
        let t = t.sign(&get_eth_miner_key(), None);
        transactions.push(t);
        nonce += 1u64.into();
    }
    let mut txids = Vec::new();
    for tx in transactions.iter() {
        let txid = web3.send_prepared_transaction(tx.clone()).await;
        info!("{:?}", txid);
        txids.push(txid);
    }
    wait_for_txids(txids, web3).await;
}

pub const TX_TIMEOUT: Duration = Duration::from_secs(60);

/// utility function that waits for a large number of txids to enter a block
pub async fn wait_for_txids(txids: Vec<Result<Uint256, Web3Error>>, web3: &Web3) {
    let mut wait_for_txid = Vec::new();
    for txid in txids {
        let wait = web3.wait_for_transaction(txid.unwrap(), TX_TIMEOUT, None);
        wait_for_txid.push(wait);
    }
    join_all(wait_for_txid).await;
}

/// Given a from_node and query_node, verify the from_nodes debt entry for a set of given conditions
pub async fn validate_debt_entry(
    from_node: Namespace,
    forward_node: Namespace,
    func: &dyn Fn(GetDebtsResult) -> bool,
) {
    let loop_init = Instant::now();
    loop {
        info!("Querying debts");
        let res = query_debts(vec![from_node.clone()], Some(vec![forward_node.clone()])).await;
        info!("Recieved Debt values {:?}", res);
        let debts = res.get(&from_node).unwrap()[0].clone();

        // validate received debt
        if func(debts.clone()) {
            break;
        } else {
            // If we continue to fail conditions after 90 secs, we failed test
            if Instant::now() - loop_init > Duration::from_secs(90) {
                assert!(func(debts));
            }
            warn!("Debts not ready, waiting for 5 secs");
            thread::sleep(Duration::from_secs(5));
        }
    }

    // we passed the condition, sleep for 10 sec and verify that the condition still holds
    // This is useful in the case where extra payments are being made when they shouldnt be
    info!("Condition passed, waiting for 10 seconds and checking again");
    thread::sleep(Duration::from_secs(10));
    let res = query_debts(vec![from_node.clone()], Some(vec![forward_node.clone()])).await;
    info!("Recieved Debt values {:?}", res);
    let debts = res.get(&from_node).unwrap()[0].clone();
    assert!(func(debts));
}

pub async fn register_all_namespaces_to_exit(namespaces: NamespaceInfo) {
    for r in namespaces.names.clone() {
        if let NodeType::Client { exit_name, .. } = r.node_type.clone() {
            let res = register_to_exit(r.get_name()).await;
            if !res {
                panic!("Failed to register {} to exit with {}", r.get_name(), res);
            } else {
                info!("{} registered to exit {}", r.get_name(), exit_name);
            }
        }
    }
}

pub async fn populate_routers_eth(rita_identities: InstanceData, exit_root_addr: Address) {
    // Exits need to have funds to request a registered client list, which is needed for proper setup
    info!("Topup exits with funds");
    let web3 = Web3::new(&get_eth_node(), WEB3_TIMEOUT);
    let mut to_top_up = Vec::new();
    for c in rita_identities.client_identities {
        to_top_up.push(c.eth_address);
    }
    for e in rita_identities.exit_identities {
        to_top_up.push(e.eth_address)
    }
    to_top_up.push(exit_root_addr);

    info!("Sending 50 eth to all routers and exit root server");
    send_eth_bulk((ONE_ETH * 50).into(), &to_top_up, &web3).await;
}

pub async fn add_exits_contract_exit_list(
    db_addr: Address,
    exit_settings: ExitNetworkSettings,
    rita_identities: InstanceData,
) {
    let web3 = Web3::new(&get_eth_node(), WEB3_TIMEOUT);
    let miner_private_key: clarity::PrivateKey = REGISTRATION_SERVER_KEY.parse().unwrap();
    let miner_pub_key = miner_private_key.to_address();

    add_exit_admin(
        &web3,
        db_addr,
        miner_pub_key,
        miner_private_key,
        Some(TX_TIMEOUT),
        vec![],
    )
    .await
    .unwrap();

    let nonce = web3.eth_get_transaction_count(miner_pub_key).await.unwrap();

    for (i, id) in rita_identities.exit_identities.iter().enumerate() {
        let exit_id = ExitIdentity {
            mesh_ip: id.mesh_ip,
            wg_key: id.wg_public_key,
            eth_addr: id.eth_address,
            registration_port: exit_settings.exit_hello_port,
            wg_exit_listen_port: exit_settings.wg_tunnel_port,
            allowed_regions: {
                let mut ret = HashSet::new();
                ret.insert(Regions::UnitedStates);
                ret
            },
            payment_types: {
                let mut ret = HashSet::new();
                ret.insert(SystemChain::AltheaL1);
                ret.insert(SystemChain::Ethereum);
                ret.insert(SystemChain::Xdai);
                ret
            },
        };

        info!("Adding exit {:?} to contract exit list", exit_id);
        add_exits_to_registration_list(
            &web3,
            vec![exit_id],
            db_addr,
            miner_private_key,
            None,
            vec![
                SendTxOption::GasLimitMultiplier(5.0),
                SendTxOption::Nonce(nonce + i.into()),
            ],
        )
        .await
        .unwrap();
    }
}
