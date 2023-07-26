use crate::{
    payments_althea::get_althea_evm_priv,
    setup_utils::namespaces::{get_nsfd, Namespace, NamespaceInfo, NodeType, RouteHop},
};
use actix_rt::time::sleep;
use actix_rt::System;
use althea_kernel_interface::KI;
use althea_proto::cosmos_sdk_proto::cosmos::gov::v1beta1::VoteOption;
use althea_proto::{
    canto::erc20::v1::RegisterCoinProposal,
    cosmos_sdk_proto::cosmos::bank::v1beta1::{
        query_client::QueryClient, Metadata, QueryDenomMetadataRequest,
    },
};
use althea_types::{ContactType, Denom, SystemChain};
use awc::http::StatusCode;
use babel_monitor::{open_babel_stream, parse_routes, structs::Route};
use deep_space::{Address as AltheaAddress, Coin, Contact, CosmosPrivateKey, PrivateKey};
use futures::future::join_all;
use ipnetwork::{IpNetwork, Ipv6Network};
use log::{error, info, trace, warn};
use nix::{
    fcntl::{open, OFlag},
    sched::{setns, CloneFlags},
    sys::stat::Mode,
};
use rita_common::{
    debt_keeper::GetDebtsResult,
    payment_validator::{ALTHEA_CHAIN_PREFIX, ALTHEA_CONTACT_TIMEOUT},
};
use settings::{client::RitaClientSettings, exit::RitaExitSettingsStruct};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
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

/// Wait this long for network convergence
const REACHABILITY_TEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the reacability test should wait in between tests
const REACHABILITY_TEST_CHECK_SPEED: Duration = Duration::from_secs(5);
/// Pay thresh used in payment tests
pub const TEST_PAY_THRESH: u64 = 1_000_000_000u64;

pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

pub const NODE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(7, 7, 7, 2));

pub const STAKING_TOKEN: &str = "aalthea";
pub const MIN_GLOBAL_FEE_AMOUNT: u128 = 10;
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEBT_ACCURACY_THRES: u8 = 15;

pub fn get_althea_grpc() -> String {
    format!("http://{}:9091", NODE_IP)
}

pub fn get_eth_node() -> String {
    format!("http://{}:8545", NODE_IP)
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

/// test pingability between namespaces on babel routes
pub fn test_reach_all_async(nsinfo: NamespaceInfo) -> bool {
    for i in nsinfo.clone().names {
        for j in nsinfo.clone().names {
            if test_reach(i.clone(), j) {
                // ping failed
                return false;
            }
        }
    }
    true
}

fn test_reach(from: Namespace, to: Namespace) -> bool {
    // todo replace with oping
    // ip netns exec n-1 ping6 fd00::2
    let ip = format!("fd00::{}", to.id);
    let errormsg = format!(
        "Could not run ping6 from {} to {}",
        from.get_name(),
        to.get_name()
    );
    let output = KI
        .run_command(
            "ip",
            &["netns", "exec", &from.get_name(), "ping6", &ip, "-c", "1"],
        )
        .expect(&errormsg);
    let output = from_utf8(&output.stdout).expect("could not get output for ping6!");
    trace!("ping output: {output:?} end");
    output.contains("1 packets transmitted, 1 received, 0% packet loss")
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
                return false;
            }
        }
    }
    true
}

pub fn test_all_internet_connectivity(namespaces: NamespaceInfo) {
    for ns in namespaces.names {
        let out = KI
            .run_command(
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
        if !String::from_utf8(out.stdout)
            .unwrap()
            .contains("1 received")
        {
            panic!("{} does not have internet connectivity", ns.get_name());
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

/// Gets the default client and exit settings handling the pre-launch exchange of exit into and its insertion into
/// the
pub fn get_default_settings() -> (RitaClientSettings, RitaExitSettingsStruct) {
    let mut exit = RitaExitSettingsStruct::new("/althea_rs/settings/test_exit.toml").unwrap();

    // exit should allow instant registration by any requester
    exit.verif_settings = None;
    exit.network.mesh_ip = Some(EXIT_ROOT_IP);
    exit.exit_network.subnet = Some(IpNetwork::V6(Ipv6Network::new(EXIT_SUBNET, 40).unwrap()));

    let mut client = RitaClientSettings::new("/althea_rs/settings/test.toml").unwrap();

    client.exit_client.contact_info = Some(
        ContactType::Both {
            number: "+11111111".parse().unwrap(),
            email: "fake@fake.com".parse().unwrap(),
            sequence_number: Some(0),
        }
        .into(),
    );
    client.exit_client.current_exit = Some(TEST_EXIT_NAME.to_string());
    client.exit_client.exits.insert(
        TEST_EXIT_NAME.to_string(),
        settings::client::ExitServer {
            root_ip: EXIT_ROOT_IP,
            subnet: None,
            eth_address: exit.payment.eth_address.unwrap(),
            wg_public_key: exit.exit_network.wg_public_key,
            registration_port: exit.exit_network.exit_hello_port,
            description: exit.description.clone(),
            info: althea_types::ExitState::New,
        },
    );

    // first node is passed through to the host machine for testing second node is used
    // for testnet queries
    exit.payment.althea_grpc_list = vec![get_althea_grpc()];
    exit.payment.eth_node_list = vec![get_eth_node()];
    client.payment.althea_grpc_list = vec![get_althea_grpc()];
    client.payment.eth_node_list = vec![get_eth_node()];

    (client, exit)
}

pub fn althea_system_chain_client(settings: RitaClientSettings) -> RitaClientSettings {
    let mut settings = settings;
    settings.payment.system_chain = SystemChain::Althea;
    settings.payment.payment_threshold = TEST_PAY_THRESH.into();
    let mut accept_de = HashMap::new();
    accept_de.insert(
        "usdc".to_string(),
        Denom {
            denom: "uUSDC".to_string(),
            decimal: 1_000_000u64,
        },
    );
    settings.payment.accepted_denoms = Some(accept_de);
    settings
}

pub fn althea_system_chain_exit(settings: RitaExitSettingsStruct) -> RitaExitSettingsStruct {
    let mut settings = settings;
    settings.payment.system_chain = SystemChain::Althea;

    // set pay thres to a smaller value
    settings.payment.payment_threshold = TEST_PAY_THRESH.into();
    let mut accept_de = HashMap::new();
    accept_de.insert(
        "usdc".to_string(),
        Denom {
            denom: "uUSDC".to_string(),
            decimal: 1_000_000u64,
        },
    );
    settings.payment.accepted_denoms = Some(accept_de);
    settings
}

// Calls the register to exit rpc function within the provided namespace
pub async fn register_to_exit(namespace_name: String) -> StatusCode {
    // thread safe lock that allows us to pass data between the router thread and this thread
    // one copy of the reference is sent into the closure and the other is kept in this scope.
    let response: Arc<RwLock<Option<StatusCode>>> = Arc::new(RwLock::new(None));
    let response_local = response.clone();
    let namespace_local = namespace_name.clone();

    let _ = thread::spawn(move || {
        // set the host of this thread to the ns
        let nsfd = get_nsfd(namespace_name);
        setns(nsfd, CloneFlags::CLONE_NEWNET).expect("Couldn't set network namespace");
        let runner = System::new();
        runner.block_on(async move {
            let client = awc::Client::default();
            let req = client
                .post(format!(
                    "http://localhost:4877/exits/{}/register",
                    TEST_EXIT_NAME
                ))
                .send()
                .await
                .expect("Failed to make request to rita RPC");
            *response.write().unwrap() = Some(req.status());
        })
    });

    // wait for the child thread to finish performing it's query
    while response_local.read().unwrap().is_none() {
        info!("Waiting for a rpc response from {}", namespace_local);
        sleep(Duration::from_millis(100)).await;
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
/// When to is None, traffic is generated to the internet
pub fn generate_traffic(from: Namespace, to: Option<Namespace>, data: String) {
    let ip = match &to {
        Some(a) => format!("fd00::{}", a.id),
        None => NODE_IP.to_string(),
    };

    // setup server
    info!("Going to setup server, spawning new thread");
    thread::spawn(move || {
        if let Some(ns) = to {
            let _output = KI
                .run_command(
                    "ip",
                    &["netns", "exec", &ns.get_name(), "iperf3", "-s", "-1"],
                )
                .expect("Could not setup iperf server");
        } else {
            let _output = KI
                .run_command("iperf3", &["-s", "-1"])
                .expect("Could not setup iperf server");
        }
    });

    // iperf client
    info!("Going to setup client");
    let ticker = Instant::now();
    loop {
        let output = KI
            .run_command(
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
            info!("Client out: {}", format!("{}", std_output));
            break;
        } else if stderr.contains("Connection refused") {
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
    match node.node_type {
        NodeType::Exit => EXIT_ROOT_IP.to_string(),
        _ => format!("fd00::{}", node.id),
    }
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
        let node_name = node.get_name();

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
        while response_local.read().unwrap().is_none() {
            info!(
                "Waiting for a rpc response from {}",
                node.clone().get_name()
            );
            sleep(Duration::from_millis(100)).await;
        }
        sleep(Duration::from_millis(100)).await;
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
        res.gas_used
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
    info!("Gov proposal executed with {:?}", res.raw_log);

    vote_yes_on_proposals(contact, keys, None).await;
    wait_for_proposals_to_execute(contact).await;
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

pub async fn register_erc20_usdc_token() {
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
    match ip {
        EXIT_ROOT_IP => 4,
        _ => {
            let addr = ip.to_string();
            addr.split("::").last().unwrap().parse().unwrap()
        }
    }
}
