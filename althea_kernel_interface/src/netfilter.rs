use crate::{run_command, KernelInterfaceError};
use std::net::IpAddr;

pub fn does_nftables_exist() -> bool {
    let output = match run_command("nft", &["-v"]) {
        Ok(out) => out,
        Err(e) => {
            error!("Run command is failing with {}", e);
            // Assume there is no nftables
            return false;
        }
    };

    let stdout = match String::from_utf8(output.stdout) {
        Ok(a) => a,
        Err(e) => {
            error!("Cannot parse stdout with {}", e);
            return false;
        }
    };

    stdout.contains("nftables")
}

fn create_fwd_rule() -> Result<(), KernelInterfaceError> {
    run_command(
        "nft",
        &["insert", "rule", "inet", "fw4", "forward_lan", "accept"],
    )?;

    Ok(())
}

fn create_nft_set(set_name: &str) {
    if let Err(e) = run_command(
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

fn create_nat_table(ex_nic: &str) -> Result<(), KernelInterfaceError> {
    // create the table
    run_command("nft", &["create", "table", "ip", "nat"])?;

    // Add a chain to the table
    run_command(
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
    run_command(
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

fn is_lan_fwd_present() -> Result<bool, KernelInterfaceError> {
    let out = run_command("nft", &["list", "chain", "inet", "fw4", "forward_lan"])?;
    let out = out.stdout;
    let out = String::from_utf8(out).expect("fix command");
    for line in out.lines() {
        if line.trim() == "accept" {
            return Ok(true);
        }
    }

    Ok(false)
}

fn get_reject_rule_handle() -> Result<Option<u32>, KernelInterfaceError> {
    let out = run_command(
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

fn is_nat_table_present() -> Result<bool, KernelInterfaceError> {
    let out = run_command("nft", &["list", "table", "ip", "nat"])?;
    if out.status.success() {
        return Ok(true);
    }
    Ok(false)
}

pub fn insert_reject_rule() -> Result<(), KernelInterfaceError> {
    if get_reject_rule_handle()?.is_none() {
        run_command(
            "nft",
            &["insert", "rule", "inet", "fw4", "forward_lan", "reject"],
        )?;
    }
    Ok(())
}

pub fn delete_reject_rule() -> Result<(), KernelInterfaceError> {
    if let Some(handle) = get_reject_rule_handle()? {
        run_command(
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

pub fn init_nat_chain(ex_nic: &str) -> Result<(), KernelInterfaceError> {
    if !is_nat_table_present()? {
        create_nat_table(ex_nic)?;
    }
    Ok(())
}

pub fn set_nft_lan_fwd_rule() -> Result<(), KernelInterfaceError> {
    if !is_lan_fwd_present()? {
        create_fwd_rule()?;
    }

    Ok(())
}

fn are_nft_exit_forward_rules_present(
    interface: &str,
    ex_nic: &str,
) -> Result<bool, KernelInterfaceError> {
    let out = run_command("nft", &["list", "chain", "inet", "fw4", "forward"])?;
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
    interface: &str,
    ex_nic: &str,
    external_v6: Option<(IpAddr, u8)>,
) -> Result<(), KernelInterfaceError> {
    // Packets from wg_exit -> ex_nic. Add this rule for both v4 and v6 traffic
    // nft add rule ip tests forward iifname "wg_exit" oifname "ex_nic" counter accept
    if !are_nft_exit_forward_rules_present(interface, ex_nic)? {
        run_command(
            "nft",
            &[
                "add", "rule", "inet", "fw4", "forward", "iifname", interface, "oifname", ex_nic,
                "counter", "accept",
            ],
        )?;
        // v4 packets from ex_nic -> wg_exit
        // nft add rule ip tests forward iifname "ex_nic" oifname "wg_exit" ct state related,established counter accept
        run_command(
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
            run_command(
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
    set_name: &str,
    chain: &str,
    interface: &str,
) -> Result<(), KernelInterfaceError> {
    if !is_nft_set_present(set_name) {
        // add set
        create_nft_set(set_name);
        // add insert chain
        create_nft_insert_chain(set_name, chain, interface);
    }
    Ok(())
}

fn is_nft_set_present(set_name: &str) -> bool {
    let out = run_command("nft", &["list", "set", "inet", "fw4", set_name]).expect("Fix command!");
    if out.status.success() {
        return true;
    }
    false
}

fn create_nft_insert_chain(set_name: &str, chain: &str, interface: &str) {
    // Add rule to match on a set element counter to increment it
    if let Err(e) = run_command(
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
    if let Err(e) = run_command(
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
