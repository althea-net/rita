use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

use std::net::{IpAddr, SocketAddr};

impl KernelInterface {
    pub fn set_client_exit_tunnel_config(
        &self,
        endpoint: SocketAddr,
        pubkey: String,
        private_key_path: String,
        listen_port: u16,
        local_ip: IpAddr,
        netmask: u8,
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
                &pubkey,
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
                self.run_command("wg", &["set", "wg_exit", "peer", &i, "remove"])?;
            }
        }

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

        match self.get_global_device_ip("wg_exit") {
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
                }
            }
            Err(e) => {
                warn!("Finding wg exit's current IP returned {}", e);
            }
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        Ok(())
    }

    pub fn set_route_to_tunnel(&self, gateway: &IpAddr) -> Result<(), Error> {
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
            )).into());
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
}
