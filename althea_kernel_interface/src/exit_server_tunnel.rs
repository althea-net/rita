use crate::open_tunnel::to_wg_local;

use super::{KernelInterface, KernelInterfaceError};
use althea_types::WgKey;
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
    ) -> Result<(), Error> {
        let command = "wg".to_string();

        let mut args = vec![
            "set".into(),
            "wg_exit".into(),
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

        let wg_peers = self.get_peers("wg_exit")?;
        info!("wg_exit has {} peers", wg_peers.len());
        for i in wg_peers {
            if !client_pubkeys.contains(&i) {
                warn!("Removing no longer authorized peer {}", i);
                self.run_command(
                    "wg",
                    &["set", "wg_exit", "peer", &format!("{}", i), "remove"],
                )?;
            }
        }

        // setup traffic classes for enforcement with flow id's derived from the ip
        // only get the flows list once
        let flows = self.get_flows("wg_exit")?;
        for c in clients.iter() {
            match c.internal_ip {
                IpAddr::V4(addr) => {
                    if !self.has_flow_bulk(addr, &flows) {
                        self.create_flow_by_ip("wg_exit", addr)?
                    }
                }
                _ => panic!("Could not derive ipv4 addr for client! Corrupt DB!"),
            }
        }

        Ok(())
    }

    /// Performs the one time startup tasks for the rita_exit clients loop
    pub fn one_time_exit_setup(
        &self,
        local_ip: &IpAddr,
        netmask: u8,
        exit_mesh: IpAddr,
        external_nic: String,
    ) -> Result<(), Error> {
        let _output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{}/{}", local_ip, netmask),
                "dev",
                "wg_exit",
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
                "wg_exit",
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
                    "wg_exit",
                    "-o",
                    &external_nic,
                    "-j",
                    "ACCEPT",
                ],
            )
            .is_err()
        {
            error!("IPV6 ERROR: uanble to set ip6table rules: wg_exit to ex_nic");
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
                    "wg_exit",
                    "-j",
                    "ACCEPT",
                ],
            )
            .is_err()
        {
            error!("IPV6 ERROR: uanble to set ip6table rules: ex_nic to wg_Exit");
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        // this creates the root classful htb limit for which we will make
        // subclasses to enforce payment
        if !self.has_limit("wg_exit")? {
            info!("Setting up root HTB qdisc, this should only run once");
            self.create_root_classful_limit("wg_exit")
                .expect("Failed to setup root HTB qdisc!");
        }

        Ok(())
    }

    pub fn setup_nat(&self, external_interface: &str) -> Result<(), Error> {
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
                "wg_exit",
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
                "wg_exit",
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
