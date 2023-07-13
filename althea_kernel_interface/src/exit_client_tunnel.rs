use super::KernelInterface;
use crate::hardware_info::{get_kernel_version, parse_kernel_version};
use crate::{open_tunnel::to_wg_local, KernelInterfaceError as Error};
use althea_types::WgKey;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug)]
pub struct ClientExitTunnelConfig {
    /// The mesh ip of the exit server and it's port
    pub endpoint: SocketAddr,
    /// the public key of the exit
    pub pubkey: WgKey,
    /// our private key which is copied to a file on startup for easy reference
    pub private_key_path: String,
    /// the port that we wil be listening on, the exit will send keep alive messages
    /// to this port to help open the connection
    pub listen_port: u16,
    /// the ip we are using inside of the wg exit tunnel, we need this both to add it
    /// to the tunnel and to be sure we replace it with the new one when switching exits
    pub local_ip: IpAddr,
    /// the netmask the exit assigns addresses out of. We could instead of providing this
    /// insert a route to the exits ip on this subnet but this is the easier solution. Cross
    /// talk does not occur due to firewall rules
    pub netmask: u8,
    /// Used to insert a firewall rule that prevents rita hello packets from going over this
    /// interface, I'm nearly positive this can be safely removed because the implementation of
    /// peer discovery has been changed since it was first needed
    pub rita_hello_port: u16,
    /// This is a user provided bandwidth limit (upload and download) to be enforced
    /// by cake. Traffic is shaped incoming on wg_exit and outgoing on br_lan resulting
    /// in a symmetrical limit of the users choice. Specified in mbit/s
    pub user_specified_speed: Option<usize>,
}

impl dyn KernelInterface {
    pub fn get_kernel_is_v4(&self) -> Result<bool, Error> {
        let (_, system_kernel_version) = parse_kernel_version(get_kernel_version()?)?;
        Ok(system_kernel_version.starts_with("4."))
    }

    pub fn set_client_exit_tunnel_config(
        &self,
        args: ClientExitTunnelConfig,
        local_mesh: Option<IpAddr>,
    ) -> Result<(), Error> {
        self.run_command(
            "wg",
            &[
                "set",
                "wg_exit",
                "listen-port",
                &args.listen_port.to_string(),
                "private-key",
                &args.private_key_path,
                "peer",
                &args.pubkey.to_string(),
                "endpoint",
                &format!("[{}]:{}", args.endpoint.ip(), args.endpoint.port()),
                "allowed-ips",
                "0.0.0.0/0, ::/0",
                "persistent-keepalive",
                "5",
            ],
        )?;

        // we only want one peer on this link, technically that one peer is multihomed
        // via babel, but it has the same key so it's the same 'peer' from wireguard's
        // perspective, if we don't do this we'll end up with multiple exits on the same
        // tunnel
        for i in self.get_peers("wg_exit")? {
            if i != args.pubkey {
                self.run_command("wg", &["set", "wg_exit", "peer", &format!("{i}"), "remove"])?;
            }
        }

        let prev_ip: Result<Ipv4Addr, Error> = self.get_global_device_ip_v4("wg_exit");

        match prev_ip {
            Ok(prev_ip) => {
                if prev_ip != args.local_ip {
                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "delete",
                            &format!("{}/{}", prev_ip, args.netmask),
                            "dev",
                            "wg_exit",
                        ],
                    )?;

                    self.run_command(
                        "ip",
                        &[
                            "address",
                            "add",
                            &format!("{}/{}", args.local_ip, args.netmask),
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
                        &format!("{}/{}", args.local_ip, args.netmask),
                        "dev",
                        "wg_exit",
                    ],
                )?;
            }
        }

        // If wg_exit does not have a link local addr, set one up
        if self.get_link_local_device_ip("wg_exit").is_err() {
            if let Some(mesh) = local_mesh {
                if let Err(e) = self.run_command(
                    "ip",
                    &[
                        "address",
                        "add",
                        &format!("{}/64", to_wg_local(&mesh)),
                        "dev",
                        "wg_exit",
                    ],
                ) {
                    error!("IPV6 ERROR: Unable to set link local for wg_exit: {:?}", e);
                }
            } else {
                error!("IPV6 ERRROR: No mesh ip, unable to set link local for wg_exit");
            }
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        let _res = self.set_codel_shaping("br-lan", args.user_specified_speed);

        Ok(())
    }

    pub fn set_route_to_tunnel(&self, gateway: &IpAddr) -> Result<(), Error> {
        if let Err(e) = self.run_command("ip", &["route", "del", "default"]) {
            warn!("Failed to delete default route {:?}", e);
        }

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
            return Err(Error::RuntimeError(format!(
                "received error setting ip route: {}",
                String::from_utf8(output.stderr)?
            )));
        }

        Ok(())
    }

    pub fn set_ipv6_route_to_tunnel(&self) -> Result<(), Error> {
        // Remove current default route
        if let Err(e) = self.run_command("ip", &["-6", "route", "del", "default"]) {
            warn!("Failed to delete default ip6 route {:?}", e);
        }
        // Set new default route
        let output =
            self.run_command("ip", &["-6", "route", "add", "default", "dev", "wg_exit"])?;
        if !output.stderr.is_empty() {
            error!("IPV6 ERROR: Unable to set ip -6 default route");
            return Err(Error::RuntimeError(format!(
                "received error setting ip -6 route: {}",
                String::from_utf8(output.stderr)?
            )));
        }
        Ok(())
    }

    /// Adds nat rules for lan client, these act within the structure
    /// of the openwrt rules which themselves create a few requirements
    /// (such as saying that zone-lan-forward shoul jump to the accept table)
    /// the nat rule here is very general, note the lack of restriction based
    /// on incoming interface or ip, this is intentional, as it allows
    /// the phone clients over in light_client_manager to function using these
    /// same rules. It may be advisable in the future to split them up into
    /// individual nat entires for each option
    pub fn create_client_nat_rules(&self) -> Result<(), Error> {
        let use_iptables = !self.does_nftables_exist();

        if use_iptables {
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
            self.add_iptables_rule("iptables", &["-A", "zone_lan_forward", "-j", "ACCEPT"])?;
        } else {
            self.init_nat_chain("wg_exit")?;
            self.set_nft_lan_fwd_rule()?;
        }

        // Set mtu
        if use_iptables {
            self.add_iptables_rule(
                "iptables",
                &[
                    "-I",
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

            //ipv6 support
            self.add_iptables_rule(
                "ip6tables",
                &[
                    "-I",
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
        }

        Ok(())
    }

    /// blocks the client nat by inserting a blocker in the start of the special lan forwarding
    /// table created by openwrt.
    pub fn block_client_nat(&self) -> Result<(), Error> {
        if !self.does_nftables_exist() {
            self.add_iptables_rule("iptables", &["-I", "zone_lan_forward", "-j", "REJECT"])?;
        } else {
            self.insert_reject_rule()?;
        }
        Ok(())
    }

    /// Removes the block created by block_client_nat() will fail if not run after that command
    pub fn restore_client_nat(&self) -> Result<(), Error> {
        if !self.does_nftables_exist() {
            self.add_iptables_rule("iptables", &["-D", "zone_lan_forward", "-j", "REJECT"])?;
        } else {
            self.delete_reject_rule()?;
        }
        Ok(())
    }
}
