use std::net::IpAddr;

use crate::KernelInterface;
use crate::KernelInterfaceError;

impl dyn KernelInterface {
    fn create_fwd_rule(&self) -> Result<(), KernelInterfaceError> {
        self.run_command(
            "nft",
            &["insert", "rule", "inet", "fw4", "forward_lan", "accept"],
        )?;

        Ok(())
    }

    fn create_nft_set(&self, set_name: &str) {
        if let Err(e) = self.run_command(
            "nft",
            &[
                "add",
                "set",
                "inet",
                "fw4",
                set_name,
                "{",
                "type",
                "ipv6_addr",
                ".",
                "ifname;",
                "flags",
                "dynamic;",
                "counter;",
                "size",
                "65535;",
                "}",
            ],
        ) {
            error!("Unable to setup counter tables with {:?}", e);
        }
    }

    fn create_nat_table(&self, ex_nic: &str) -> Result<(), KernelInterfaceError> {
        // create the table
        self.run_command("nft", &["create", "table", "ip", "nat"])?;

        // Add a chain to the table
        self.run_command(
            "nft",
            &[
                "create",
                "chain",
                "ip",
                "nat",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        )?;

        // Add rule to chain
        self.run_command(
            "nft",
            &[
                "add",
                "rule",
                "ip",
                "nat",
                "postrouting",
                "oifname",
                ex_nic,
                "masquerade",
            ],
        )?;

        Ok(())
    }

    fn is_lan_fwd_present(&self) -> Result<bool, KernelInterfaceError> {
        let out = self.run_command("nft", &["list", "chain", "inet", "fw4", "forward_lan"])?;
        let out = out.stdout;
        let out = String::from_utf8(out).expect("fix command");
        for line in out.lines() {
            if line.trim() == "accept" {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn get_reject_rule_handle(&self) -> Result<Option<u32>, KernelInterfaceError> {
        let out = self.run_command(
            "nft",
            &["-a", "list", "chain", "inet", "fw4", "forward_lan"],
        )?;
        let out = out.stdout;
        let out = String::from_utf8(out).expect("fix command");
        for line in out.lines() {
            if line.contains("reject") {
                let handle: Vec<&str> = line.split(' ').collect();
                match handle.last() {
                    Some(a) => match (*a).parse() {
                        Ok(b) => return Ok(Some(b)),
                        Err(_) => {
                            return Ok(None);
                        }
                    },
                    None => return Ok(None),
                }
            }
        }
        Ok(None)
    }

    fn is_nat_table_present(&self) -> Result<bool, KernelInterfaceError> {
        let out = self.run_command("nft", &["list", "table", "ip", "nat"])?;
        if out.status.success() {
            return Ok(true);
        }
        Ok(false)
    }

    pub fn insert_reject_rule(&self) -> Result<(), KernelInterfaceError> {
        if self.get_reject_rule_handle()?.is_none() {
            self.run_command(
                "nft",
                &["insert", "rule", "inet", "fw4", "forward_lan", "reject"],
            )?;
        }
        Ok(())
    }

    pub fn delete_reject_rule(&self) -> Result<(), KernelInterfaceError> {
        if let Some(handle) = self.get_reject_rule_handle()? {
            self.run_command(
                "nft",
                &[
                    "delete",
                    "rule",
                    "inet",
                    "fw4",
                    "forward_lan",
                    "handle",
                    &handle.to_string(),
                ],
            )?;
        }
        Ok(())
    }

    pub fn init_nat_chain(&self, ex_nic: &str) -> Result<(), KernelInterfaceError> {
        if !self.is_nat_table_present()? {
            self.create_nat_table(ex_nic)?;
        }
        Ok(())
    }

    pub fn set_nft_lan_fwd_rule(&self) -> Result<(), KernelInterfaceError> {
        if !self.is_lan_fwd_present()? {
            self.create_fwd_rule()?;
        }

        Ok(())
    }

    fn are_nft_exit_forward_rules_present(
        &self,
        interface: &str,
        ex_nic: &str,
    ) -> Result<bool, KernelInterfaceError> {
        let out = self.run_command("nft", &["list", "chain", "inet", "fw4", "forward"])?;
        let out = out.stdout;
        let out = String::from_utf8(out).expect("fix command");
        for line in out.lines() {
            // If one is present, they should all be present
            if line.contains(&format!("iifname {interface} oifname {ex_nic}")) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn insert_nft_exit_forward_rules(
        &self,
        interface: &str,
        ex_nic: &str,
        external_v6: Option<(IpAddr, u8)>,
    ) -> Result<(), KernelInterfaceError> {
        // Packets from wg_exit -> ex_nic. Add this rule for both v4 and v6 traffic
        // nft add rule ip tests forward iifname "wg_exit" oifname "ex_nic" counter accept
        if !self.are_nft_exit_forward_rules_present(interface, ex_nic)? {
            self.run_command(
                "nft",
                &[
                    "add", "rule", "inet", "fw4", "forward", "iifname", interface, "oifname",
                    ex_nic, "counter", "accept",
                ],
            )?;
            // v4 packets from ex_nic -> wg_exit
            // nft add rule ip tests forward iifname "ex_nic" oifname "wg_exit" ct state related,established counter accept
            self.run_command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    "fw4",
                    "forward",
                    "meta",
                    "nfproto",
                    "ipv4",
                    "iifname",
                    ex_nic,
                    "oifname",
                    interface,
                    "ct",
                    "state",
                    "related,established",
                    "counter",
                    "accept",
                ],
            )?;

            // v6 packets from ex_nic -> wg_exit
            if let Some((external_ip_v6, netmask_v6)) = external_v6 {
                self.run_command(
                    "nft",
                    &[
                        "add",
                        "rule",
                        "inet",
                        "fw4",
                        "forward",
                        "iifname",
                        ex_nic,
                        "oifname",
                        interface,
                        "ip",
                        "daddr",
                        &format!("{}/{}", external_ip_v6, netmask_v6),
                        "counter",
                        "accept",
                    ],
                )?;
            }
        }

        Ok(())
    }

    pub fn nft_init_counters(
        &self,
        set_name: &str,
        chain: &str,
        interface: &str,
    ) -> Result<(), KernelInterfaceError> {
        if !self.is_nft_set_present(set_name) {
            // add set
            self.create_nft_set(set_name);
            // add insert chain
            self.create_nft_insert_chain(set_name, chain, interface);
        }
        Ok(())
    }

    fn is_nft_set_present(&self, set_name: &str) -> bool {
        let out = self
            .run_command("nft", &["list", "set", "inet", "fw4", set_name])
            .expect("Fix command!");
        if out.status.success() {
            return true;
        }
        false
    }

    fn create_nft_insert_chain(&self, set_name: &str, chain: &str, interface: &str) {
        // Add rule to match on a set element counter to increment it
        if let Err(e) = self.run_command(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                "fw4",
                chain,
                "ip6",
                "daddr",
                ".",
                "meta",
                interface,
                &("@".to_owned() + set_name),
            ],
        ) {
            error!("Unable to setup counters: {}", e);
        }

        // insert ip6addr . ifname when not present in set
        // sudo nft -e -j insert rule filter input ip daddr . meta iifname != @myset3 set add ip saddr . meta iifname @myset3
        if let Err(e) = self.run_command(
            "nft",
            &vec![
                "insert",
                "rule",
                "inet",
                "fw4",
                chain,
                "ip6",
                "daddr",
                ".",
                "meta",
                interface,
                "!=",
                &("@".to_owned() + set_name),
                "add",
                &("@".to_owned() + set_name),
                "{",
                "ip6",
                "daddr",
                ".",
                "meta",
                interface,
                "counter",
                "}",
            ],
        ) {
            error!("Unable to setup counters: {}", e);
        }
    }
}
