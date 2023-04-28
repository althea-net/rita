use super::{KernelInterface, KernelInterfaceError};
use crate::open_tunnel::to_wg_local;
use althea_types::WgKey;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use KernelInterfaceError as Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ExitClient {
    pub internal_ip: IpAddr,
    pub internet_ipv6_list: Vec<IpNetwork>,
    pub public_key: WgKey,
    pub mesh_ip: IpAddr,
    pub port: u16,
}

impl dyn KernelInterface {
    // This function sets up the exit config and returns the updated list of tc filter handles
    pub fn set_exit_wg_config(
        &self,
        clients: &HashSet<ExitClient>,
        listen_port: u16,
        private_key_path: &str,
        if_name: &str,
        ipv6_filter_handles: HashSet<(String, u32)>,
    ) -> Result<HashSet<(String, u32)>, Error> {
        let command = "wg".to_string();

        let mut args = vec![
            "set".into(),
            if_name.into(),
            "listen-port".into(),
            format!("{listen_port}"),
            "private-key".into(),
            private_key_path.to_string(),
        ];

        let mut client_pubkeys = HashSet::new();

        for c in clients.iter() {
            // For the allowed IPs, we appends the clients internal ip as well
            // as the client ipv6 assigned list and add this to wireguards allowed ips
            // internet_ipv6_list is already in the form of "<subnet1>,<subnet2>.."
            let i_ipv6 = &c.internet_ipv6_list;
            let mut allowed_ips = c.internal_ip.to_string().to_owned();
            if !i_ipv6.is_empty() {
                for ip_net in i_ipv6 {
                    allowed_ips.push(',');
                    allowed_ips.push_str(&ip_net.to_string());
                }
            }

            args.push("peer".into());
            args.push(format!("{}", c.public_key));
            args.push("endpoint".into());
            args.push(format!("[{}]:{}", c.mesh_ip, c.port));
            args.push("allowed-ips".into());
            args.push(allowed_ips);

            client_pubkeys.insert(c.public_key);
        }

        let arg_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        self.run_command(&command, &arg_str[..])?;

        let wg_peers = self.get_peers(if_name)?;
        info!("{} has {} peers", if_name, wg_peers.len());
        for i in wg_peers {
            if !client_pubkeys.contains(&i) {
                warn!("Removing no longer authorized peer {}", i);
                self.run_command("wg", &["set", if_name, "peer", &format!("{i}"), "remove"])?;
            }
        }

        // setup traffic classes for enforcement with flow id's derived from the ip
        // only get the flows list once
        let mut mut_handles = ipv6_filter_handles;
        let flows = self.get_flows(if_name)?;
        for c in clients.iter() {
            // Add ipv4 flows
            let ipv4;
            match c.internal_ip {
                IpAddr::V4(addr) => {
                    ipv4 = addr;
                    if !self.has_flow_bulk(addr, &flows) {
                        self.create_flow_by_ip(if_name, addr)?;
                    }
                }
                _ => panic!("Could not derive ipv4 addr for client! Corrupt DB!"),
            }

            // Add ipv6 flows
            for ip_net in c.internet_ipv6_list.iter() {
                if !self.has_flow_bulk_ipv6(ipv4, if_name, &mut mut_handles) {
                    self.create_flow_by_ipv6(if_name, *ip_net, ipv4)?;
                    // Add this ipv6 handle to TcDatastore
                    let class_id = self.get_class_id(ipv4);
                    let to_add = (if_name.to_string(), class_id);
                    mut_handles.insert(to_add);
                }
            }
        }

        Ok(mut_handles)
    }

    /// This function sets up the ip6table rules required to forward data from the internet to a client router
    /// a rule forwarding traffic from wg_exit or wg_exit_v2 to external nic has been added in one_time_exit_setup()
    /// This function adds the requred rule from external nic to either wg_exit or wg_exit_v2
    /// 1.) Check the existance of the required rule
    /// 2.) If not there, it either has an outdated rule or no rule. In that case we simply delete all rules for the particular subnet
    /// 3.) Add the required rule
    pub fn setup_client_rules(
        &self,
        client_ipv6_list: String,
        client_mesh: String,
        interface: &str,
        external_nic: String,
    ) -> Result<(), KernelInterfaceError> {
        if client_ipv6_list.is_empty() {
            return Ok(());
        }

        let ipv6_list: Vec<&str> = client_ipv6_list.split(',').collect();

        for ip in ipv6_list {
            // Verfiy its a valid subnet
            if let Ok(ip_net) = ip.parse::<IpNetwork>() {
                // Check if required rule exists
                if self.check_iptable_rule(
                    "ip6tables",
                    &[
                        "-C",
                        "FORWARD",
                        "-d",
                        &ip_net.to_string(),
                        "-i",
                        &external_nic,
                        "-o",
                        interface,
                        "-j",
                        "ACCEPT",
                    ],
                )? {
                    // This rule already exists, continue to client subnet
                    continue;
                } else {
                    // Correct rule doesnt exist, either outdated rule exists or no rule exists. Either way, we del this rule on all interfaces and add a new one
                    self.add_iptables_rule(
                        "ip6tables",
                        &[
                            "-D",
                            "FORWARD",
                            "-d",
                            &ip_net.to_string(),
                            "-i",
                            &external_nic,
                            "-o",
                            "wg_exit",
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                    self.add_iptables_rule(
                        "ip6tables",
                        &[
                            "-D",
                            "FORWARD",
                            "-d",
                            &ip_net.to_string(),
                            "-i",
                            &external_nic,
                            "-o",
                            "wg_exit_v2",
                            "-j",
                            "ACCEPT",
                        ],
                    )?;

                    // Add new correct rule
                    self.add_iptables_rule(
                        "ip6tables",
                        &[
                            "-A",
                            "FORWARD",
                            "-d",
                            &ip_net.to_string(),
                            "-i",
                            &external_nic,
                            "-o",
                            interface,
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                }
            } else {
                error!("IPV6 Error: Invalid client database state. Client with mesh ip: {:?} has invalid database ipv6 list: {:?}", client_mesh, client_ipv6_list);
            }
        }

        Ok(())
    }

    /// This function adds a route for each client subnet to the ipv6 routing table
    /// through wg_exit
    pub fn setup_client_routes(
        &self,
        client_ipv6_list: String,
        client_mesh: String,
        client_internal_ip: String,
        interface: &str,
    ) {
        let mut interface_cloned = interface.to_string();
        interface_cloned.push(' ');
        // Setup ipv4 route
        // 1.) Select all ipv4 routes with 'client_internal_ip'. This gives us all routes with wg_exit and wg_exit_v2 for the ip
        //     THere should be only one route
        // 2.) Does the route contain 'interface'? Yes? we continue
        // 3.) No? That means either no route exists or there is a route with the other interface name
        // 4.) Delete route, add new route with the correct interface
        let output = self.run_command("ip", &["route", "show", &client_internal_ip]);
        if let Ok(output) = output {
            let route = String::from_utf8(output.stdout).unwrap();
            if !route.contains(&interface_cloned) {
                if let Err(e) = self.run_command("ip", &["route", "del", &client_internal_ip]) {
                    error!("Unable to delete old IPV4 route with {}", e);
                };

                if let Err(e) = self.run_command(
                    "ip",
                    &["route", "add", &client_internal_ip, "dev", interface],
                ) {
                    error!("IPV4 route setup failed with {}", e);
                };
            }
        } else {
            error!("Ip route show failed? Continuing to setup ipv6");
        }

        // Setup ipv6 routes
        // 1.) Find all v6 routes with ip. There should be at most one, either on wg_exit or wg_exit_v2
        // 2.) Check if that route contains 'interface' Yes? route is already setup, we continue
        // 3.) No? It means no route exists or route exists on wrong interface.
        // 4.) We delete route and add the new route on correct interface
        // 5.) Continue this for each ip in the database for the client

        if client_ipv6_list.is_empty() {
            return;
        }

        let ipv6_list: Vec<&str> = client_ipv6_list.split(',').collect();

        for ip in ipv6_list {
            // Verfiy its a valid subnet
            if let Ok(ip_net) = ip.parse::<IpNetwork>() {
                // Look for existing routes
                let output =
                    match self.run_command("ip", &["-6", "route", "show", &ip_net.to_string()]) {
                        Ok(a) => a,
                        Err(e) => {
                            error!("ip -6 route show failed with {:?}", e);
                            return;
                        }
                    };
                let existing_routes = String::from_utf8(output.stdout).unwrap();
                if !existing_routes.contains(&interface_cloned) {
                    if let Err(e) =
                        self.run_command("ip", &["-6", "route", "del", &ip_net.to_string()])
                    {
                        error!("Unable to delete old IPV6 route with {}", e);
                    };

                    if let Err(e) = self.run_command(
                        "ip",
                        &["-6", "route", "add", &ip_net.to_string(), "dev", interface],
                    ) {
                        error!("IPV6 route setup failed with {}", e);
                    };
                }
            } else {
                error!("IPV6 Error: Invalid client database state. Client with mesh ip: {:?} has invalid database ipv6 list: {:?}", client_mesh, client_ipv6_list);
            }
        }
    }

    /// Performs the one time startup tasks for the rita_exit clients loop
    pub fn one_time_exit_setup(
        &self,
        local_ip: &IpAddr,
        netmask: u8,
        exit_mesh: IpAddr,
        external_nic: String,
        interface: &str,
    ) -> Result<(), Error> {
        let _output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{local_ip}/{netmask}"),
                "dev",
                interface,
            ],
        )?;

        // Set up link local mesh ip in wg_exit as fe80 + rest of mesh ip of exit
        let local_link = to_wg_local(&exit_mesh);

        let _output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{local_link}/64"),
                "dev",
                interface,
            ],
        )?;

        // Add iptable routes between wg_exit and eth0
        if self
            .add_iptables_rule(
                "ip6tables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    interface,
                    "-o",
                    &external_nic,
                    "-j",
                    "ACCEPT",
                ],
            )
            .is_err()
        {
            error!(
                "IPV6 ERROR: uanble to set ip6table rules: {:?} to ex_nic",
                interface
            );
        }

        let output = self.run_command("ip", &["link", "set", "dev", interface, "mtu", "1500"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        let output = self.run_command("ip", &["link", "set", "dev", interface, "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        // this creates the root classful htb limit for which we will make
        // subclasses to enforce payment
        if !self.has_limit(interface)? {
            info!(
                "Setting up root HTB qdisc for interface: {:?}, this should only run once",
                interface
            );
            self.create_root_classful_limit(interface)
                .expect("Failed to setup root HTB qdisc!");
        }

        Ok(())
    }

    pub fn setup_nat(&self, external_interface: &str, interface: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                external_interface,
                "-j",
                "MASQUERADE",
            ],
        )?;

        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-o",
                external_interface,
                "-i",
                interface,
                "-j",
                "ACCEPT",
            ],
        )?;

        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-o",
                interface,
                "-i",
                external_interface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )?;

        Ok(())
    }
}

#[test]
fn test_iproute_parsing() {
    let str = "fbad::/64,feee::/64";

    if str.is_empty() {
        return;
    }

    let ipv6_list: Vec<&str> = str.split(',').collect();

    for ip in ipv6_list {
        // Verfiy its a valid subnet
        if let Ok(ip_net) = ip.parse::<IpNetwork>() {
            println!("debugging: {ip_net:?}")
        }
    }
}
