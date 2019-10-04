use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use althea_types::WgKey;

impl dyn KernelInterface {
    pub fn set_client_exit_tunnel_config(
        &self,
        endpoint: SocketAddr,
        pubkey: WgKey,
        private_key_path: String,
        listen_port: u16,
        local_ip: IpAddr,
        netmask: u8,
        rita_hello_port: u16,
    ) -> Result<(), Error> {
        self.run_command(
            "wg",
            &[
                "set",
                "wg_exit",
                "listen-port",
                &listen_port.to_string(),
                "private-key",
                &private_key_path,
                "peer",
                &format!("{}", &pubkey),
                "endpoint",
                &format!("[{}]:{}", endpoint.ip(), endpoint.port()),
                "allowed-ips",
                "0.0.0.0/0",
                "persistent-keepalive",
                "5",
            ],
        )?;

        for i in self.get_peers("wg_exit")? {
            if i != pubkey {
                self.run_command(
                    "wg",
                    &["set", "wg_exit", "peer", &format!("{}", i), "remove"],
                )?;
            }
        }

        // block rita hello port on the exit tunnel
        self.add_iptables_rule(
            "iptables",
            &[
                "-I",
                "OUTPUT",
                "-o",
                "wg_exit",
                "-p",
                "tcp",
                "--dport",
                &format!("{}", rita_hello_port),
                "-j",
                "DROP",
            ],
        )?;

        let prev_ip: Result<Ipv4Addr, Error> = self.get_global_device_ip_v4("wg_exit");

        match prev_ip {
            Ok(prev_ip) => {
                if prev_ip != local_ip {
                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "delete",
                            &format!("{}/{}", prev_ip, netmask),
                            "dev",
                            "wg_exit",
                        ],
                    )?;

                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "add",
                            &format!("{}/{}", local_ip, netmask),
                            "dev",
                            "wg_exit",
                        ],
                    )?;
                }
            }
            Err(e) => {
                warn!("Finding wg exit's current IP returned {}", e);
                self.run_command(
                    "ip",
                    &[
                        "address",
                        "add",
                        &format!("{}/{}", local_ip, netmask),
                        "dev",
                        "wg_exit",
                    ],
                )?;
            }
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            ))
            .into());
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            ))
            .into());
        }

        Ok(())
    }

    pub fn set_route_to_tunnel(&self, gateway: &Ipv4Addr) -> Result<(), Error> {
        match self.run_command("ip", &["route", "del", "default"]) {
            Err(e) => warn!("Failed to delete default route {:?}", e),
            _ => (),
        };

        let output = self.run_command(
            "ip",
            &[
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                "wg_exit",
            ],
        )?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting ip route: {}",
                String::from_utf8(output.stderr)?
            ))
            .into());
        }

        Ok(())
    }

    pub fn add_client_nat_rules(&self, lan_nic: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                "wg_exit",
                "-j",
                "MASQUERADE",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-A", "FORWARD", "-i", &lan_nic, "-o", "wg_exit", "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-A", "FORWARD", "-i", "wg_exit", "-o", &lan_nic, "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu", //should be the same as --set-mss 1300
            ],
        )?;
        //TODO ipv6 support

        Ok(())
    }

    pub fn delete_client_nat_rules(&self, lan_nic: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                "wg_exit",
                "-j",
                "MASQUERADE",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", &lan_nic, "-o", "wg_exit", "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", "wg_exit", "-o", &lan_nic, "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-D",
                "FORWARD",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu", //should be the same as --set-mss 1300
            ],
        )?;

        Ok(())
    }

    pub fn add_light_client_nat_rules(&self, lan_nic: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", &lan_nic, "-o", "wg_exit", "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", "wg_exit", "-o", &lan_nic, "-j", "ACCEPT",
            ],
        )?;
        Ok(())
    }

    pub fn delete_light_client_nat_rules(&self, lan_nic: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", &lan_nic, "-o", "wg_exit", "-j", "ACCEPT",
            ],
        )?;
        self.add_iptables_rule(
            "iptables",
            &[
                "-D", "FORWARD", "-i", "wg_exit", "-o", &lan_nic, "-j", "ACCEPT",
            ],
        )?;
        Ok(())
    }
}
