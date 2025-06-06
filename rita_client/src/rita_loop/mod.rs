//! This is the primary actor loop for rita-client, where periodic tasks are spawned and Actors are
//! tied together with message calls.
//!
//! This loop manages exit signup based on the settings configuration state and deploys an exit vpn
//! tunnel if the signup was successful on the selected exit.

use crate::exit_manager::ExitManager;
use crate::heartbeat::send_heartbeat_loop;
use crate::heartbeat::HEARTBEAT_SERVER_KEY;
use crate::operator_fee_manager::tick_operator_payments;
use actix::System as AsyncSystem;
use althea_kernel_interface::dns::get_resolv_servers;
use althea_kernel_interface::ip_addr::is_iface_up;
use althea_kernel_interface::ip_route::manual_peers_route;
use althea_kernel_interface::is_openwrt::is_openwrt;
use althea_kernel_interface::manipulate_uci::get_uci_var;
use althea_kernel_interface::manipulate_uci::openwrt_reset_dnsmasq;
use althea_kernel_interface::manipulate_uci::set_uci_list;
use althea_kernel_interface::manipulate_uci::set_uci_var;
use althea_kernel_interface::manipulate_uci::uci_commit;
use althea_kernel_interface::netns::check_integration_test_netns;
use althea_kernel_interface::run_command;
use althea_kernel_interface::KernelInterfaceError;
use althea_types::ExitState;
use antenna_forwarding_client::start_antenna_forwarding_proxy;
use rita_common::dashboard::interfaces::get_interfaces;
use rita_common::dashboard::interfaces::InterfaceMode;
use rita_common::tunnel_manager::tm_get_neighbors;
use rita_common::usage_tracker::get_current_hour;
use rita_common::usage_tracker::get_last_saved_usage_hour;
use settings::RitaSettings;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};

// the speed in seconds for the client loop
pub const CLIENT_LOOP_SPEED: Duration = Duration::from_secs(30);
pub const CLIENT_LOOP_TIMEOUT: Duration = Duration::from_secs(4);

lazy_static! {
    /// see the comment on check_for_gateway_client_billing_corner_case()
    /// to identify why this variable is needed. In short it identifies
    /// a specific billing corner case.
    static ref IS_GATEWAY_CLIENT: Arc<RwLock<HashMap<u32, bool>>> = Arc::new(RwLock::new(HashMap::new()));
}

pub fn is_gateway_client() -> bool {
    let netns = check_integration_test_netns();
    IS_GATEWAY_CLIENT
        .read()
        .unwrap()
        .clone()
        .get(&netns)
        .cloned()
        .unwrap_or(false)
}

pub fn set_gateway_client(input: bool) {
    let netns = check_integration_test_netns();
    let gw_lock = &mut *IS_GATEWAY_CLIENT.write().unwrap();

    // Clippy notation
    if let std::collections::hash_map::Entry::Vacant(e) = gw_lock.entry(netns) {
        e.insert(input);
    } else {
        let gw_bool = gw_lock.get_mut(&netns).unwrap();
        *gw_bool = input;
    }
}

/// Rita loop thread spawning function, this function contains all the rita client functions
/// with the exception of exit operations which have their own loop
pub fn start_rita_client_loop(exit_state_ref: Arc<RwLock<ExitManager>>) {
    let mut last_restart = Instant::now();

    // outer thread is a watchdog inner thread is the runner
    thread::spawn(move || {
        // this will always be an error, so it's really just a loop statement
        // with some fancy destructuring
        while let Err(e) = {
            let exit_state_ref = exit_state_ref.clone();
            thread::spawn(move || {
                loop {
                    let start = Instant::now();
                    trace!("Client tick!");

                    manage_gateway();
                    info!(
                        "Rita Client loop manage gateway in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    manage_babeld_logs();
                    info!(
                        "Rita Client loop manage babeld in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    check_for_gateway_client_billing_corner_case(exit_state_ref.clone());
                    info!(
                        "Rita Client loop corner case in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    // if you have additional async functions to run please add them here
                    // in order to reuse the runner
                    let runner = AsyncSystem::new();
                    runner.block_on(async move {
                        // sends an operator payment if enough time has elapsed
                        tick_operator_payments().await;
                        info!(
                            "Rita Client loop operator payments completed in {}s {}ms",
                            start.elapsed().as_secs(),
                            start.elapsed().subsec_millis()
                        );
                    });

                    info!(
                        "Rita Client loop completed in {}s {}ms",
                        start.elapsed().as_secs(),
                        start.elapsed().subsec_millis()
                    );

                    thread::sleep(CLIENT_LOOP_SPEED);
                }
            })
            .join()
        } {
            error!("Rita client loop thread paniced! Respawning {:?}", e);
            if Instant::now() - last_restart < Duration::from_secs(60) {
                error!("Restarting too quickly, rebooting instead!");
                let _res = run_command("reboot", &[]);
            }
            last_restart = Instant::now();
        }
    });
}

pub fn start_rita_client_loops() -> Arc<RwLock<ExitManager>> {
    info!("Starting Rita Client loops");

    // shared exit state data between the threads, this is read only everywhere except
    // the exit manager loop, and register endpoints, ideally the exit manager would get the only read write copy
    // but that's not possible with the current stdlib
    let exit_state: Arc<RwLock<ExitManager>> = Arc::new(RwLock::new(ExitManager::new()));

    crate::exit_manager::exit_loop::start_exit_manager_loop(exit_state.clone());
    crate::rita_loop::start_rita_client_loop(exit_state.clone());
    crate::self_rescue::start_rita_client_rescue_loop();
    crate::operator_update::ops_websocket::start_websocket_operator_update_loop(Some(
        exit_state.clone(),
    ));
    send_heartbeat_loop(exit_state.clone());
    exit_state
}

/// There is a complicated corner case where the gateway is a client and a relay to
/// the same exit, this will produce incorrect billing data as we need to reconcile the
/// relay bills (under the exit relay id) and the client bills (under the exit id) versus
/// the exit who just has the single billing id for the client and is combining debts
/// This function grabs neighbors and determines if we have a neighbor with the same mesh ip
/// and eth address as our selected exit, if we do we trigger the special case handling
fn check_for_gateway_client_billing_corner_case(exit_state_ref: Arc<RwLock<ExitManager>>) {
    let res = tm_get_neighbors();
    let em = exit_state_ref.read().unwrap();
    let exit_reg_state = em.get_exit_registration_state();
    let current_exit = em.get_current_exit();

    let neighbors = res;
    if let ExitState::Registered { .. } = exit_reg_state {
        for neigh in neighbors {
            info!("Neighbor is {:?}", neigh);
            // we have a neighbor who is also our selected exit!
            // wg_key excluded due to multihomed exits having a different one
            let exit = match current_exit {
                Some(ref e) => e,
                None => {
                    set_gateway_client(false);
                    return;
                }
            };
            if neigh.identity.global.mesh_ip == exit.mesh_ip
                && neigh.identity.global.eth_address == exit.eth_addr
            {
                info!("We are a gateway client");
                set_gateway_client(true);
                return;
            }
        }
        info!("We are NOT a gateway client");
        set_gateway_client(false);
    }
}

pub fn start_antenna_forwarder(settings: RitaSettings) {
    let url: &str;
    if cfg!(feature = "dev_env") {
        url = "7.7.7.7:33300";
    } else if cfg!(feature = "operator_debug") {
        url = "192.168.10.2:33334";
    } else {
        url = "operator.althea.net:33334";
    }

    let our_id = settings.get_identity().unwrap();
    let network = settings.network;
    let interfaces = network.peer_interfaces.clone();
    start_antenna_forwarding_proxy(
        url.to_string(),
        our_id,
        *HEARTBEAT_SERVER_KEY.read().unwrap(),
        network.wg_public_key.unwrap(),
        network.wg_private_key.unwrap(),
        interfaces,
    );
}

/// Manages gateway functionality and maintains the gateway parameter, this is different from the gateway
/// identification in rita_client because this must function even if we aren't registered for an exit it's also
/// very prone to being true when the device has a wan port but no actual wan connection.
fn manage_gateway() {
    // Resolves the gateway client corner case
    // Background info here https://forum.altheamesh.com/t/the-gateway-client-corner-case/35
    // the is_up detection is mostly useless because these ports reside on switches which mark
    // all ports as up all the time.
    if let Some(external_nic) = settings::get_rita_common().network.external_nic {
        if is_iface_up(&external_nic).unwrap_or(false) {
            if let Ok(interfaces) = get_interfaces() {
                // This is used to insert a route for each dns server in /etc/resolv.conf to override
                // the wg_exit default route, this is needed for bootstrapping as a gateway can not
                // resolve the exit ip addresses in order to perform peer discovery without these rules
                // in LTE cases we never want to do this but we do need other gateway behavior so we setup
                // this check
                if let Some(mode) = interfaces.get(&external_nic) {
                    if matches!(mode, InterfaceMode::Wan | InterfaceMode::StaticWan { .. }) {
                        let mut common = settings::get_rita_common();
                        match get_resolv_servers() {
                            Ok(s) => {
                                for ip in s.iter() {
                                    trace!("Resolv route {:?}", ip);

                                    manual_peers_route(ip, &mut common.network.last_default_route)
                                        .unwrap();
                                }
                                settings::set_rita_common(common);
                            }
                            Err(e) => warn!("Failed to add DNS routes with {:?}", e),
                        }
                    }
                }
            }
        }
    }
}

/// This function truncates babeld.log and sends them over to graylog to prevent memory getting full
fn manage_babeld_logs() {
    trace!("Running babel log truncation loop");

    let log_file = "/tmp/log/babeld.log";
    let path = Path::new(log_file);
    let mut file = match File::open(path) {
        Ok(a) => a,
        Err(e) => {
            warn!("Unable to truncate babel logs: {:?}", e);
            return;
        }
    };

    // Read file and log data
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => {
            for line in buf.lines() {
                info!("{} {}", log_file, line);
            }
        }
        Err(e) => {
            warn!("Unable to truncate babel logs: {:?}", e);
        }
    }

    // our current file handle does not have write permissions, so we open a new
    // one in 'truncate' mode which means it clears out the entire file on open
    let mut options = OpenOptions::new();
    let path = Path::new(log_file);
    match options.write(true).truncate(true).open(path) {
        Ok(_) => {
            // now that the file has been truncated we need to take our read only file
            // handle and rewind it's internal pointer to the start otherwise we'll be
            // trying to read at an offset longer than the file
            match file.rewind() {
                Ok(_) => trace!("Log truncate {} successful!", log_file),
                Err(e) => {
                    error!("Failed to truncate {} with {:?}", log_file, e)
                }
            }
        }
        Err(e) => error!("Failed to truncate {} logs with {:?}", log_file, e),
    }
}

/// This code handles updating the dns servers for a router, modifying /etc/resolv.conf to ensure it forwards to
/// the exit local dns server and also modificing /etc/config/dhcp to ensure we advertise the althea router itself (192.168.10.1)
/// as a dns resolver
pub fn update_dns_conf() {
    let exit_internal_ip: IpAddr = Ipv4Addr::from([172, 168, 0, 254]).into();
    let resolv_path = "/etc/resolv.conf";
    let updated_config = format!("nameserver {}\nnameserver 1.0.0.1\nnameserver 8.8.8.8\nnameserver 74.82.42.42\nnameserver 149.112.112.10\nnameserver 64.6.65.6", exit_internal_ip);
    // read line by line instead
    match File::open(resolv_path) {
        Ok(file) => {
            let reader = BufReader::new(file);
            let mut found = false;
            for line in reader.lines() {
                let s = line.unwrap_or("".to_string());
                if s.trim() == format!("nameserver {}", exit_internal_ip) {
                    info!("Found nameserver {exit_internal_ip}, no update to resolv.conf");
                    found = true;
                }
            }

            if !found {
                // if we get here we haven't found the nameserver and need to add it
                match fs::write(resolv_path, updated_config) {
                    Ok(_) => info!("Updating resolv.conf"),
                    Err(e) => error!("Could not update resolv.conf with {:?}", e),
                };
            }
        }
        Err(_e) => {
            match fs::write(resolv_path, updated_config) {
                Ok(_) => info!("Updating resolv.conf"),
                Err(e) => error!("Could not update resolv.conf with {:?}", e),
            };
        }
    };

    // if we are on openwrt we can automatically configure the dhcp server, otherwise the user is on their own to santiy check their config
    if is_openwrt() {
        // the goal of this code is to make sure that the router is the only dns server offered during the dhcp negotiation process
        // not every device will take this dns server and use it, but many do, and some use it exclusively so it has to be correct

        const DHCP_DNS_LIST_KEY: &str = "dhcp.@dnsmasq[0].server";

        // this config value is the list of servers dnsmasq uses for resolving client requests
        // if it does not start with the exit internal nameserver add it. An empty value is acceptable
        // since dnsmasq simply uses resolv.conf servers which we update above in that case.
        match parse_list_to_ip(get_uci_var(DHCP_DNS_LIST_KEY)) {
            Ok(dns_server_list) => {
                // an empty list uses the system resolver, this is acceptable since we just set the system resolver to
                // point at the exit internal ip above
                if let Some(first_server_list_entry) = dns_server_list.first() {
                    if *first_server_list_entry != exit_internal_ip {
                        let mut dns_server_list = dns_server_list;
                        dns_server_list.insert(0, exit_internal_ip);
                        overwrite_dns_server_and_restart_dhcp(DHCP_DNS_LIST_KEY, dns_server_list)
                    }
                }
            }
            Err(e) => error!("Failed to get dns server list? {:?}", e),
        }

        // check to make sure DHCP is using the correct resolv.conf file
        ensure_dhcp_resolvfile();
    }
}

fn overwrite_dns_server_and_restart_dhcp(key: &str, ips: Vec<IpAddr>) {
    // does the conversion from Vec<Stringt> to &[&str]
    let ips: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
    let slice_of_strs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
    let reference_to_slice: &[&str] = &slice_of_strs;

    let res = set_uci_list(key, reference_to_slice);

    if let Err(e) = res {
        error!("Failed to set dhcp server list via uci {:?}", e);
        return;
    }
    let res = uci_commit(key);
    if let Err(e) = res {
        error!("Failed to set dhcp server list via uci {:?}", e);
        return;
    }
    let res = openwrt_reset_dnsmasq();
    if let Err(e) = res {
        error!("Failed to restart dhcp config with {:?}", e);
    }
}

/// Ensures that DHCP is using the correct resolv.conf file
fn ensure_dhcp_resolvfile() {
    const DHCP_RESOLV_FILE_KEY: &str = "dhcp.@dnsmasq[0].resolvfile";
    const DHCP_RESOLV_FILE_VALUE: &str = "/etc/resolv.conf";

    match get_uci_var(DHCP_RESOLV_FILE_KEY) {
        Ok(resolv_file) => {
            if resolv_file != DHCP_RESOLV_FILE_VALUE {
                let res = set_uci_var(DHCP_RESOLV_FILE_KEY, DHCP_RESOLV_FILE_VALUE);
                if let Err(e) = res {
                    error!("Failed to set dhcp resolvfile {:?}", e);
                    return;
                }
                let res = uci_commit(DHCP_RESOLV_FILE_KEY);
                if let Err(e) = res {
                    error!("Failed to set dhcp resolvfile {:?}", e);
                    return;
                }
                let res = openwrt_reset_dnsmasq();
                if let Err(e) = res {
                    error!("Failed to restart dhcp config with {:?}", e);
                }
            }
        }
        Err(e) => error!("Failed to get dhcp resolvfile {:?}", e),
    }
}

fn parse_list_to_ip(
    input: Result<String, KernelInterfaceError>,
) -> Result<Vec<IpAddr>, KernelInterfaceError> {
    let input = input?;
    let mut ret = Vec::new();
    for line in input.split_ascii_whitespace() {
        let ip: IpAddr = line.parse()?;
        ret.push(ip);
    }
    Ok(ret)
}

pub fn update_system_time() {
    let current_hour = get_current_hour().unwrap_or(0);
    let last_saved = get_last_saved_usage_hour();
    if last_saved > current_hour {
        info!(
            "Updating system time to our last saved hour: {}",
            last_saved
        );
        let seconds = last_saved * 3600;
        let formatted_seconds = format!("@{}", seconds);
        match run_command("date", &["-s", &formatted_seconds]) {
            Ok(_) => info!("System time updated!"),
            Err(e) => error!("{}", e),
        }
    }
}
