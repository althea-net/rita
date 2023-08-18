use super::{KernelInterface, KernelInterfaceError};
use crate::open_tunnel::to_wg_local;
use althea_types::WgKey;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use KernelInterfaceError as Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ExitClient {
    pub internal_ip: IpAddr,
    pub internet_ipv6: Option<IpNetwork>,
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
    ) -> Result<(), Error> {
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
            // as the client ipv6 assigned ip and add this to wireguards allowed ips
            // internet_ipv6 is already in the form of "<subnet1>,<subnet2>.."
            let i_ipv6 = &c.internet_ipv6;
            let mut allowed_ips = c.internal_ip.to_string().to_owned();
            if let Some(i_ipv6) = i_ipv6 {
                allowed_ips.push(',');
                allowed_ips.push_str(&i_ipv6.to_string());
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

        Ok(())
    }

    /// This function adds a route for each client ipv4 subnet to the routing table
    /// this works on the premise of smallest prefix first routing meaning that we can assign
    /// ip route 172.168.0.1/16 to wg_exit_v2 and then individually add /32 routes to wg_exit_v1
    /// and this will produce the same routing outcomes with many less routes than adding individual routes
    /// on both
    pub fn setup_individual_client_routes(
        &self,
        client_internal_ip: IpAddr,
        exit_internal_v4: IpAddr,
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
        let output = self
            .run_command("ip", &["route", "show", &client_internal_ip.to_string()])
            .expect("Fix command");
        let route = String::from_utf8(output.stdout).unwrap();
        if !route.contains(&interface_cloned) {
            self.run_command("ip", &["route", "del", &client_internal_ip.to_string()])
                .expect("Fix command");

            self.run_command(
                "ip",
                &[
                    "route",
                    "add",
                    &client_internal_ip.to_string(),
                    "dev",
                    interface,
                    "src",
                    &exit_internal_v4.to_string(),
                ],
            )
            .expect("Fix command");
        }
    }

    /// this function performs the teardown step of setup_indvidual_client_routes, when a router upgrades
    /// to beta20 or later this function checks for and deltes the rules
    pub fn teardown_individual_client_routes(&self, client_internal_ip: IpAddr) {
        let output = self
            .run_command("ip", &["route", "show", &client_internal_ip.to_string()])
            .expect("Fix command");
        let route = String::from_utf8(output.stdout).unwrap();
        if !route.is_empty() {
            self.run_command("ip", &["route", "del", &client_internal_ip.to_string()])
                .expect("Fix command");
        }
    }

    /// Performs the one time startup tasks for the rita_exit clients loop
    pub fn one_time_exit_setup(
        &self,
        local_v4: Option<(IpAddr, u8)>,
        external_v6: Option<(IpAddr, u8)>,
        exit_mesh: IpAddr,
        interface: &str,
        enable_enforcement: bool,
    ) -> Result<(), Error> {
        if let Some((local_ip_v4, netmask_v4)) = local_v4 {
            // sanity checking
            assert!(local_ip_v4.is_ipv4());
            assert!(netmask_v4 < 32);

            let _output = self.run_command(
                "ip",
                &[
                    "address",
                    "add",
                    &format!("{local_ip_v4}/{netmask_v4}"),
                    "dev",
                    interface,
                ],
            )?;
        }

        // setup ipv6 if provided2602:FBAD:10::/45
        if let Some((external_ip_v6, netmask_v6)) = external_v6 {
            // sanity checking
            assert!(external_ip_v6.is_ipv6());
            assert!(netmask_v6 < 128);

            let _output = self.run_command(
                "ip",
                &[
                    "address",
                    "add",
                    &format!("{external_ip_v6}/{netmask_v6}"),
                    "dev",
                    interface,
                ],
            )?;
        }

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
        if !self.has_limit(interface)? && enable_enforcement {
            info!(
                "Setting up root HTB qdisc for interface: {:?}, this should only run once",
                interface
            );
            self.create_root_classful_limit(interface)
                .expect("Failed to setup root HTB qdisc!");
        }

        Ok(())
    }

    /// Sets up the natting rules for forwarding ipv4 and ipv6 traffic
    pub fn setup_nat(
        &self,
        external_interface: &str,
        interface: &str,
        external_v6: Option<(IpAddr, u8)>,
    ) -> Result<(), Error> {
        // nat masquerade on exit
        if !self.does_nftables_exist() {
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
        } else {
            self.init_nat_chain(external_interface)?;
        }

        // Add v4 and v6 forward rules wg_exit <-> ex_nic
        if !self.does_nftables_exist() {
            // v4 wg_exit -> ex_nic
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

            // v4 ex_nic -> interface
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

            // Add iptable routes between wg_exit and the external nic
            self.add_iptables_rule(
                "ip6tables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    interface,
                    "-o",
                    external_interface,
                    "-j",
                    "ACCEPT",
                ],
            )?;

            if let Some((external_ip_v6, netmask_v6)) = external_v6 {
                self.add_iptables_rule(
                    "ip6tables",
                    &[
                        "-A",
                        "FORWARD",
                        "-d",
                        &format!("{}/{}", external_ip_v6, netmask_v6),
                        "-i",
                        external_interface,
                        "-o",
                        interface,
                        "-j",
                        "ACCEPT",
                    ],
                )?;
            }
        } else {
            self.insert_nft_exit_forward_rules(interface, external_interface, external_v6)?;
        }

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
