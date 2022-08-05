use crate::open_tunnel::to_wg_local;

use super::{KernelInterface, KernelInterfaceError};
use althea_types::WgKey;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use KernelInterfaceError as Error;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ExitClient {
    pub internal_ip: IpAddr,
    pub internet_ipv6_list: String,
    pub public_key: WgKey,
    pub mesh_ip: IpAddr,
    pub port: u16,
}

impl dyn KernelInterface {
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
            format!("{}", listen_port),
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
                allowed_ips.push(',');
                allowed_ips.push_str(i_ipv6);
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
                self.run_command("wg", &["set", if_name, "peer", &format!("{}", i), "remove"])?;
            }
        }

        // setup traffic classes for enforcement with flow id's derived from the ip
        // only get the flows list once
        let flows = self.get_flows(if_name)?;
        for c in clients.iter() {
            match c.internal_ip {
                IpAddr::V4(addr) => {
                    if !self.has_flow_bulk(addr, &flows) {
                        self.create_flow_by_ip(if_name, addr)?
                    }
                }
                _ => panic!("Could not derive ipv4 addr for client! Corrupt DB!"),
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
        interface: &str,
    ) {
        if client_ipv6_list.is_empty() {
            return;
        }

        // Get all routes on our interface
        let output = self.run_command("ip", &vec!["-6", "route", "show", "dev", interface]).expect("Fix command");
        let existing_routes = String::from_utf8(output.stdout).unwrap();

        // Turn into a vector of Vec<IpRoute>
        //let routes = parse_iproute_string(existing_routes);
        



        let ipv6_list: Vec<&str> = client_ipv6_list.split(',').collect();

        for ip in ipv6_list {
            // Verfiy its a valid subnet
            if let Ok(ip_net) = ip.parse::<IpNetwork>() {
                let _res = self.run_command(
                    "ip",
                    &["-6", "route", "add", &ip_net.to_string(), "dev", interface],
                );
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
                &format!("{}/{}", local_ip, netmask),
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
                &format!("{}/64", local_link),
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

        if self
            .add_iptables_rule(
                "ip6tables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    &external_nic,
                    "-o",
                    interface,
                    "-j",
                    "ACCEPT",
                ],
            )
            .is_err()
        {
            error!(
                "IPV6 ERROR: uanble to set ip6table rules: ex_nic to {:?}",
                interface
            );
        }

        let output = self.run_command("ip", &["link", "set", "dev", interface, "mtu", "1340"])?;
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
            info!("Setting up root HTB qdisc, this should only run once");
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
            println!("debugging: {:?}", ip_net)
        }
    }
}
