//! This is the primary actor loop for rita-exit, where periodic tasks are spawned and Actors are
//! tied together with message calls.
//!
//! In this loop the exit checks it's database for registered users and deploys the endpoint for
//! their exit tunnel the execution model for all of this is pretty whacky thanks to Actix quirks
//! we have the usual actors, these actors process Async events, but we have database queries by
//! Diesel that are sync so we create a special futures executor thread that runs only a single blocking
//! future. Since it's another thread
//!
//! Two threads are generated by this, one actual worker thread and a watchdog restarting thread that only
//! wakes up to restart the inner thread if anything goes wrong.

use crate::database::{
    enforce_exit_clients, setup_clients, teardown_inactive_clients, validate_clients_region,
    ExitClientSetupStates,
};
use crate::traffic_watcher::watch_exit_traffic;
use crate::{network_endpoints::*, ClientListAnIpAssignmentMap, RitaExitError};
use actix::System as AsyncSystem;
use actix_web::{web, App, HttpServer};
use althea_kernel_interface::exit_server_tunnel::{one_time_exit_setup, setup_nat, setup_snat};
use althea_kernel_interface::netfilter::{init_filter_chain, masquerade_nat_setup};
use althea_kernel_interface::setup_wg_if::create_blank_wg_interface;
use althea_kernel_interface::wg_iface_counter::WgUsage;
use althea_kernel_interface::ExitClient;
use althea_types::regions::Regions;
use althea_types::{Identity, SignedExitServerList, WgKey};
use babel_monitor::{open_babel_stream, parse_routes};
use clarity::Address;
use exit_trust_root::client_db::get_all_registered_clients;
use ipnetwork::{Ipv4Network, Ipv6Network};
use rita_common::debt_keeper::DebtAction;
use rita_common::rita_loop::get_web3_server;
use settings::exit::{ExitIpv4RoutingSettings, EXIT_LIST_PORT};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use std::time::Instant;

// the speed in seconds for the exit loop
pub const EXIT_LOOP_SPEED: u64 = 5;
pub const EXIT_LOOP_SPEED_DURATION: Duration = Duration::from_secs(EXIT_LOOP_SPEED);
pub const EXIT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

/// Name of the primary exit interface through which user traffic is decrypted to be forwarded out to the internet
pub const EXIT_INTERFACE: &str = "wg_exit";

/// Cache of rita exit state to track across ticks
#[derive(Clone, Debug)]
pub struct RitaExitData {
    /// a cache of what tunnels we had setup last round, used to prevent extra setup ops
    wg_clients: HashSet<ExitClient>,
    /// a list of client debts from the last round, to prevent extra enforcement ops
    debt_actions: HashSet<(Identity, DebtAction)>,
    /// if we have successfully setup the wg exit tunnel in the past, if false we have never
    /// setup exit clients and should crash if we fail to do so, otherwise we are preventing
    /// proper failover
    successful_setup: bool,
    /// A blacklist of clients that we fail geoip verification for. We tear down these routes
    geoip_blacklist: Vec<Identity>,
    /// A list of geoip info that we have already requested since startup, to reduce api usage
    geoip_cache: HashMap<IpAddr, Regions>,
    // ip assignments for clients, represented as a locked map so that we can tell clients what ip's they where
    // assigned in the actix worker threads which also has a copy of this lock
    client_list_and_ip_assignments: Arc<RwLock<ClientListAnIpAssignmentMap>>,
    /// A cache of the last usage of the wg tunnels, this must be maintained from when the tunnel for a specific
    /// client is created to when it is destroyed/recreated otherwise overbilling will occur
    usage_history: HashMap<WgKey, WgUsage>,
}

impl RitaExitData {
    pub fn new(client_list_and_ip_assignments: Arc<RwLock<ClientListAnIpAssignmentMap>>) -> Self {
        RitaExitData {
            wg_clients: HashSet::new(),
            debt_actions: HashSet::new(),
            successful_setup: false,
            geoip_blacklist: Vec::new(),
            geoip_cache: HashMap::new(),
            client_list_and_ip_assignments,
            usage_history: HashMap::new(),
        }
    }

    pub fn is_client_registered(&self, client: Identity) -> bool {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .is_client_registered(client)
    }

    pub fn get_ipv6_assignments(&self) -> HashMap<Ipv6Network, Identity> {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_ipv6_assignments()
    }

    pub fn get_ipv4_nat_mode(&self) -> ExitIpv4RoutingSettings {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_ipv4_nat_mode()
            .clone()
    }

    pub fn get_internal_ip_assignments(&self) -> HashMap<Ipv4Addr, Identity> {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_internal_ip_assignments()
    }

    pub fn id_to_exit_client(&self, id: Identity) -> Result<ExitClient, Box<RitaExitError>> {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .id_to_exit_client(id)
    }

    pub fn get_or_add_client_internal_ip(
        &self,
        their_record: Identity,
    ) -> Result<Ipv4Addr, Box<RitaExitError>> {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .get_or_add_client_internal_ip(their_record)
    }

    pub fn get_or_add_client_external_ip(
        &self,
        their_record: Identity,
    ) -> Result<Option<Ipv4Addr>, Box<RitaExitError>> {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .get_or_add_client_external_ip(their_record)
    }

    pub fn get_or_add_client_ipv6(
        &self,
        their_record: Identity,
    ) -> Result<Option<Ipv6Network>, Box<RitaExitError>> {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .get_or_add_client_ipv6(their_record)
    }

    pub fn get_setup_states(&self) -> ExitClientSetupStates {
        ExitClientSetupStates {
            old_clients: self.wg_clients.clone(),
        }
    }

    pub fn set_setup_states(&mut self, states: ExitClientSetupStates) {
        self.wg_clients = states.old_clients;
    }

    pub fn get_all_registered_clients(&self) -> HashSet<Identity> {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_registered_clients()
    }

    pub fn set_registered_clients(&mut self, clients: HashSet<Identity>) {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .set_registered_clients(clients);
    }

    pub fn get_geoip_blacklist(&self) -> Vec<Identity> {
        self.geoip_blacklist.clone()
    }

    pub fn get_debt_actions(&self) -> HashSet<(Identity, DebtAction)> {
        self.debt_actions.clone()
    }

    pub fn set_debt_actions(&mut self, debt_actions: HashSet<(Identity, DebtAction)>) {
        self.debt_actions = debt_actions;
    }

    pub fn get_inactive_list(&self) -> HashMap<Identity, Instant> {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_inactive_list()
    }

    pub fn set_inactive_list(&mut self, inactive_list: HashMap<Identity, Instant>) {
        self.client_list_and_ip_assignments
            .write()
            .unwrap()
            .set_inactive_list(inactive_list);
    }

    pub fn get_external_ip_assignments(&self) -> HashMap<Ipv4Addr, HashSet<Identity>> {
        self.client_list_and_ip_assignments
            .read()
            .unwrap()
            .get_external_ip_assignments()
            .clone()
    }
}

/// Starts the rita exit billing thread, this thread deals with blocking db
/// calls and performs various tasks required for billing. If this thread crashes
/// due to consistenty requirements the whole application should be restarted
/// this will cause the wg tunnels to get torn down and rebuilt, putting things back into
/// a consistent state
pub async fn start_rita_exit_loop(client_and_ip_info: Arc<RwLock<ClientListAnIpAssignmentMap>>) {
    setup_exit_wg_tunnel();

    let mut rita_exit_cache = RitaExitData::new(client_and_ip_info.clone());
    loop {
        let start = Instant::now();

        let (reg_clients_list, inactive_list) = update_client_list(
            rita_exit_cache.get_all_registered_clients(),
            rita_exit_cache.get_inactive_list(),
        )
        .await;
        // Internal exit cache that store state across multiple ticks
        rita_exit_cache.set_registered_clients(reg_clients_list);
        rita_exit_cache.set_inactive_list(inactive_list);

        let rita_exit = settings::get_rita_exit();
        let babel_port = rita_exit.network.babel_port;

        let start_bill_benchmark = Instant::now();
        // watch and bill for traffic
        bill(
            babel_port,
            start,
            rita_exit_cache.get_all_registered_clients(),
            rita_exit_cache.usage_history.clone(),
        );
        info!(
            "Finished Rita billing in {}ms",
            start_bill_benchmark.elapsed().as_millis()
        );

        info!("About to setup clients");
        let start_setup_benchmark = Instant::now();
        // Create and update client tunnels
        // is clone doing what I think it will here? TODO look up how the lock moves when cloned
        match setup_clients(&mut rita_exit_cache) {
            Ok(_) => {
                rita_exit_cache.successful_setup = true;
            }
            Err(e) => error!("Setup clients failed with {:?}", e),
        }
        info!(
            "Finished Rita setting up clients in {}ms",
            start_setup_benchmark.elapsed().as_millis()
        );

        teardown_inactive_clients(&mut rita_exit_cache);

        // Make sure no one we are setting up is geoip unauthorized
        let start_region_benchmark = Instant::now();
        info!("about to check regions");
        let clients_list = rita_exit_cache.get_all_registered_clients();
        if let Some(list) = check_regions(
            &mut rita_exit_cache.geoip_cache,
            start,
            clients_list.iter().cloned().collect(),
        )
        .await
        {
            rita_exit_cache.geoip_blacklist = list;
        }
        info!(
            "Finished Rita checking region in {}ms",
            start_region_benchmark.elapsed().as_millis()
        );
        info!("About to enforce exit clients");
        // handle enforcement on client tunnels by querying debt keeper
        // this consumes client list
        let start_enforce_benchmark = Instant::now();
        match enforce_exit_clients(&mut rita_exit_cache) {
            Ok(_) => {}
            Err(e) => warn!("Failed to enforce exit clients with {:?}", e,),
        }
        info!(
            "Finished Rita enforcement in {}ms ",
            start_enforce_benchmark.elapsed().as_millis()
        );
        info!(
            "Finished Rita exit loop in {}ms, all vars should be dropped",
            start.elapsed().as_millis(),
        );

        thread::sleep(EXIT_LOOP_SPEED_DURATION);
    }
}

/// Updates the client list, if this is not successful the old client list is used
async fn update_client_list(
    reg_clients_list: HashSet<Identity>,
    mut inactive_list: HashMap<Identity, Instant>,
) -> (HashSet<Identity>, HashMap<Identity, Instant>) {
    let payment_settings = settings::get_rita_common().payment;
    let contract_address = settings::get_rita_exit()
        .exit_network
        .registered_users_contract_addr;
    let our_address = payment_settings.eth_address.expect("No address!");
    let full_node = get_web3_server();
    let web3 = web30::client::Web3::new(&full_node, Duration::from_secs(5));

    let get_clients_benchmark = Instant::now();
    match get_all_registered_clients(&web3, our_address, contract_address).await {
        Ok(list) => {
            info!(
                "Finished Rita get clients, got {:?} clients in {}ms",
                list.len(),
                get_clients_benchmark.elapsed().as_millis()
            );
            // now compare the new list to the old list: if we are missing clients from the old list add those clients
            // to a separate list to keep track of when they went offline
            let lost_clients: Vec<Identity> = reg_clients_list.difference(&list).cloned().collect();
            let gained_clients: Vec<Identity> =
                list.difference(&reg_clients_list).cloned().collect();
            // if the inactive list contains a client that has come back online, remove them
            for client in gained_clients.iter() {
                if inactive_list.contains_key(client) {
                    inactive_list.remove(client);
                }
            }

            // if the lost clients don't exist in the inactive list, add them at the current time
            for client in lost_clients.iter() {
                if !inactive_list.contains_key(client) {
                    inactive_list.insert(*client, Instant::now());
                }
            }

            (list, inactive_list)
        }
        Err(e) => {
            error!(
                "Failed to get registered clients this this round, using last successful {:?}",
                e
            );
            (reg_clients_list, inactive_list)
        }
    }
}

fn bill(
    babel_port: u16,
    start: Instant,
    ids: HashSet<Identity>,
    usage_history: HashMap<WgKey, WgUsage>,
) {
    trace!("about to try opening babel stream");

    match open_babel_stream(babel_port, EXIT_LOOP_TIMEOUT) {
        Ok(mut stream) => match parse_routes(&mut stream) {
            Ok(routes) => {
                trace!("Sending traffic watcher message?");
                if let Err(e) =
                    watch_exit_traffic(usage_history, &routes, ids.iter().cloned().collect())
                {
                    error!(
                        "Watch exit traffic failed with {}, in {} millis",
                        e,
                        start.elapsed().as_millis()
                    );
                } else {
                    info!(
                        "Watch exit traffic completed successfully in {} millis",
                        start.elapsed().as_millis()
                    );
                }
            }
            Err(e) => {
                error!(
                    "Watch exit traffic failed with: {} in {} millis",
                    e,
                    start.elapsed().as_millis()
                );
            }
        },
        Err(e) => {
            error!(
                "Watch exit traffic failed with: {} in {} millis",
                e,
                start.elapsed().as_millis()
            );
        }
    }
}

/// Run a region validation and return a list of blacklisted clients. This list is later used
/// in setup clients to teardown blacklisted client tunnels
async fn check_regions(
    geoip_cache: &mut HashMap<IpAddr, Regions>,
    start: Instant,
    clients_list: Vec<Identity>,
) -> Option<Vec<Identity>> {
    let val = settings::get_rita_exit().allowed_countries.is_empty();
    if !val {
        let res = validate_clients_region(geoip_cache, clients_list).await;
        match res {
            Err(e) => {
                warn!(
                    "Failed to validate client region with {:?} {}ms since start",
                    e,
                    start.elapsed().as_millis()
                );
                return None;
            }
            Ok(blacklist) => {
                info!(
                    "validate client region completed successfully {}ms since loop start",
                    start.elapsed().as_millis()
                );
                return Some(blacklist);
            }
        }
    }
    None
}

fn setup_exit_wg_tunnel() {
    info!("Setting up Rita Exit tunnel");
    // Setup wg_exit
    if let Err(e) = create_blank_wg_interface(EXIT_INTERFACE) {
        warn!("new exit setup returned {}", e)
    }

    let exit_settings = settings::get_rita_exit();

    let local_ip = exit_settings.exit_network.internal_ipv4.internal_ip();
    let netmask = exit_settings.exit_network.internal_ipv4.prefix();
    let mesh_ip = exit_settings
        .network
        .mesh_ip
        .expect("Expected a mesh ip for this exit");
    let enforcement_enabled = exit_settings.exit_network.enable_enforcement;
    let external_v6 = exit_settings
        .exit_network
        .ipv6_routing
        .map(|a| a.spit_ip_prefix());

    // Setup wg_exit. Local address added is same as that used by wg_exit
    one_time_exit_setup(
        Some((local_ip.into(), netmask)),
        external_v6,
        mesh_ip,
        EXIT_INTERFACE,
        enforcement_enabled,
    )
    .expect("Failed to setup wg_exit_v2!");

    setup_nat(
        &settings::get_rita_exit().network.external_nic.unwrap(),
        EXIT_INTERFACE,
        external_v6,
    )
    .unwrap();

    // additional setup that is exit mode specific
    match exit_settings.exit_network.ipv4_routing {
        ExitIpv4RoutingSettings::SNAT { subnet, .. } => {
            // for snat mode we must claim the second ip in the subnet as the exit ip
            // TODO: these should be getters on the exit settings
            // we need to set up the second address as the exit to forward out to the first
            let (first, second, last) = reserved_ips(subnet);
            setup_snat(
                second,
                subnet.prefix(),
                &settings::get_rita_exit().network.external_nic.unwrap(),
            )
            .unwrap();
        }
        ExitIpv4RoutingSettings::MASQUERADENAT => {
            masquerade_nat_setup(&settings::get_rita_exit().network.external_nic.unwrap()).unwrap();
        }
        ExitIpv4RoutingSettings::CGNAT {
            subnet: _,
            static_assignments: _,
        } => {
            //todo
        }
    }

    info!("Finished setting up Rita Exit tunnels");
}

/// first, second, and last ips in the given subnet are reserved for the network upstream, the exit, and the broadcast
/// address and cannot be assigned to clients. this function returns those ips
fn reserved_ips(subnet: Ipv4Network) -> (Ipv4Addr, Ipv4Addr, Ipv4Addr) {
    let first = subnet.nth(1).unwrap();
    let second = subnet.nth(2).unwrap();
    let size = subnet.size();
    let last = subnet.nth(size - 1).unwrap();
    (first, second, last)
}

/// Starts the rita exit endpoints, passing the ip assignments and registered clients lists, these are shared via cross-thread lock
/// with the main rita exit loop.
pub fn start_rita_exit_endpoints(ip_assignments: Arc<RwLock<ClientListAnIpAssignmentMap>>) {
    let web_data = web::Data::new(ip_assignments);
    thread::spawn(move || {
        let runner = AsyncSystem::new();
        runner.block_on(async move {
            let _res = HttpServer::new(move || {
                App::new()
                    .route("/secure_setup", web::post().to(secure_setup_request))
                    .route("/secure_status", web::post().to(secure_status_request))
                    .route("/client_debt", web::post().to(get_client_debt))
                    .route("/time", web::get().to(get_exit_timestamp_http))
                    .app_data(web_data.clone())
            })
            .bind(format!(
                "[::0]:{}",
                settings::get_rita_exit().exit_network.exit_hello_port
            ))
            .unwrap()
            .shutdown_timeout(0)
            .run()
            .await;
        });
    });
}

/// the exit list gets its own server on hardcoded multihomed IP. Clients will always go to the nearest
/// instance of this IP due to the way babel handles multihoming. Due to race conditions we don't explicitly
/// bind to the IP for this listener, we instead bind to all available IPs. As we make tunnels kernel interface
/// will add the ip to each wg tunnel and then babel will handle the rest.
pub fn start_rita_exit_list_endpoint() {
    let exit_contract_data_cache: Arc<RwLock<HashMap<Address, SignedExitServerList>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let web_data = web::Data::new(exit_contract_data_cache.clone());
    thread::spawn(move || {
        let runner = AsyncSystem::new();
        runner.block_on(async move {
            let _res = HttpServer::new(move || {
                App::new()
                    .route("/exit_list", web::post().to(get_exit_list))
                    .app_data(web_data.clone())
            })
            .bind(format!("[::0]:{}", EXIT_LIST_PORT,))
            .unwrap()
            .shutdown_timeout(0)
            .run()
            .await;
        });
    });
}
