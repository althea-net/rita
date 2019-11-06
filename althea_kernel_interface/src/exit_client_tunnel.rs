use super::{KernelInterface, KernelInterfaceError};
use althea_types::WgKey;
use failure::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

impl dyn KernelInterface {
    pub fn set_client_exit_tunnel_config(
        &self,
        endpoint: SocketAddr,
        pubkey: WgKey,
        private_key_path: String,
        listen_port: u16,
        local_ip: Ipv4Addr,
        local_ipv6: Option<Ipv6Addr>,
        netmask: u8,
        netmaskv6: Option<u8>,
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

        let prev_ip: Result<Ipv4Addr, Error> = self.get_global_device_ip_v4("wg_exit");
        let prev_ipv6: Result<Ipv6Addr, Error> = self.get_global_device_ip("wg_exit");

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
        match (prev_ipv6, local_ipv6, netmaskv6) {
            (Ok(prev_ipv6), Some(local_ipv6), Some(netmaskv6)) => {
                if prev_ipv6 != local_ipv6 {
                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "delete",
                            &format!("{}/{}", prev_ipv6, netmaskv6),
                            "dev",
                            "wg_exit",
                        ],
                    )?;

                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "add",
                            &format!("{}/{}", local_ipv6, netmaskv6),
                            "dev",
                            "wg_exit",
                        ],
                    )?;
                }
            }
            (Err(e), Some(local_ipv6), Some(netmaskv6)) => {
                warn!("Finding wg exit's current v6 IP returned {}", e);
                self.run_command(
                    "ip",
                    &[
                        "address",
                        "add",
                        &format!("{}/{}", local_ipv6, netmaskv6),
                        "dev",
                        "wg_exit",
                    ],
                )?;
            }
            (_, None, Some(_nm)) => error!("Bad client ipv6 state!"),
            (_, Some(_), None) => error!("Bad client ipv6 state!"),
            (_, None, None) => trace!("No assigned ipv6 address, not setting up"),
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

    pub fn set_route_to_tunnel(
        &self,
        gateway: Ipv4Addr,
        gatewayv6: Option<Ipv6Addr>,
    ) -> Result<(), Error> {
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
        if let Some(gatewayv6) = gatewayv6 {
            let output = self.run_command(
                "ip",
                &[
                    "route",
                    "add",
                    "default",
                    "via",
                    &gatewayv6.to_string(),
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
