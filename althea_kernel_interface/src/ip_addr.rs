use crate::hardware_info::maybe_get_single_line_string;
use crate::interface_tools::get_ipv6_from_iface;
use crate::open_tunnel::is_link_local;
use crate::run_command;
use crate::KernelInterfaceError as Error;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use std::net::Ipv4Addr;

/// Returns a bool based on device state, "UP" or "DOWN", "UNKNOWN" is
/// interpreted as DOWN
pub fn is_iface_up(dev: &str) -> Option<bool> {
    let path = format!("/sys/class/net/{dev}");
    if let Some(is_up) = maybe_get_single_line_string(&format!("{path}/operstate")) {
        let is_up = is_up.contains("up");
        Some(is_up)
    } else {
        None
    }
}

/// Adds an ipv4 address to a given interface, true is returned when
/// the ip is added, false if it is already there and Error if the interface
/// does not exist or some other error has occured
pub fn add_ipv4(ip: Ipv4Addr, dev: &str) -> Result<bool, Error> {
    let output = run_command("ip", &["addr", "add", &format!("{ip}/32"), "dev", dev])?;
    // Get the first line, check if it has "file exists"
    match String::from_utf8(output.stderr) {
        Ok(stdout) => match stdout.lines().next() {
            Some(line) => {
                if line.contains("File exists") {
                    Ok(false)
                } else {
                    Err(Error::RuntimeError(format!("Error setting ip {line}")))
                }
            }
            None => Ok(true),
        },
        Err(e) => Err(Error::RuntimeError(format!(
            "Could not decode stderr from ip with {e:?}"
        ))),
    }
}

pub fn delete_ipv4(ip: Ipv4Addr, dev: &str) -> Result<(), Error> {
    run_command("ip", &["addr", "del", &format!("{ip}/32"), "dev", dev])?;
    Ok(())
}

/// After receiving an ipv6 addr from the exit, this function adds that ip
/// to br-lan. SLAAC takes this ip and assigns a /64 to hosts that connect
/// to the router
/// We take a /128 of this ipv6 addr and assign it to ourselves in wg_exit as our own ipv6 addr
pub fn setup_ipv6_slaac(router_ipv6_str: IpNetwork) {
    // Get all the v6 addrs on interface
    let v6_addrs = match get_ipv6_from_iface("br-lan") {
        Ok(a) => {
            trace!("Our ip list on brlan looks like {:?}", a);
            a
        }
        Err(e) => {
            error!("IPV6 ERROR: Unable to parse ips from interface br-lan, didnt not setup slaac: {:?}", e);
            return;
        }
    };

    for (addr, netmask) in v6_addrs {
        let net = IpNetwork::new(IpAddr::V6(addr), netmask)
            .expect("Why did we get an invalid addr from kernel?");
        // slaac addr is already set
        if net == router_ipv6_str {
            break;
        }

        // Remove all previously set ipv6 addrs
        if !is_link_local(IpAddr::V6(addr)) {
            if let Err(e) = run_command("ip", &["addr", "del", &net.to_string(), "dev", "br-lan"]) {
                error!(
                    "IPV6 Error: Why are not able to delete the addr {:?} Error {:?}",
                    net, e
                );
            }
        }
    }

    // Add the new ipv6 addr
    if let Err(e) = run_command(
        "ip",
        &["addr", "add", &router_ipv6_str.to_string(), "dev", "br-lan"],
    ) {
        error!(
            "IPV6 ERROR: WHy are we unalbe to add the new subnet {:?} Error: {:?}",
            router_ipv6_str, e
        );
    }

    // Do the same thing for wg_exit
    let v6_addrs = match get_ipv6_from_iface("wg_exit") {
        Ok(a) => {
            trace!("Our ip list on wg_exit looks like {:?}", a);
            a
        }
        Err(e) => {
            error!("IPV6 ERROR: Unable to parse ips from interface wg_exit, didnt not setup ipv6 correctly: {:?}", e);
            return;
        }
    };

    for (addr, _netmask) in v6_addrs {
        // slaac addr is already set
        if addr == router_ipv6_str.ip() {
            return;
        }

        // Remove all previously set ipv6 addrs
        if !is_link_local(IpAddr::V6(addr)) {
            if let Err(e) = run_command("ip", &["addr", "del", &addr.to_string(), "dev", "wg_exit"])
            {
                error!(
                    "IPV6 Error: Why are not able to delete the addr {:?} Error {:?}",
                    addr, e
                );
            }
        }
    }

    // Add the new ipv6 addr
    if let Err(e) = run_command(
        "ip",
        &[
            "addr",
            "add",
            &router_ipv6_str.ip().to_string(),
            "dev",
            "wg_exit",
        ],
    ) {
        error!(
            "IPV6 ERROR: WHy are we unalbe to add the new ip {:?} Error: {:?}",
            router_ipv6_str, e
        );
    }
}

/// Adds an ipv4 address to a given interface, true is returned when
/// the ip is added, false if it is already there and Error if the interface
/// does not exist or some other error has occured
pub fn add_ipv4_mask(ip: Ipv4Addr, mask: u32, dev: &str) -> Result<bool, Error> {
    let output = run_command("ip", &["addr", "add", &format!("{ip}/{mask}"), "dev", dev])?;
    // Get the first line, check if it has "file exists"
    match String::from_utf8(output.stderr) {
        Ok(stdout) => match stdout.lines().next() {
            Some(line) => {
                if line.contains("File exists") {
                    Ok(false)
                } else {
                    Err(Error::RuntimeError(format!("Error setting ip {line}")))
                }
            }
            None => Ok(true),
        },
        Err(e) => Err(Error::RuntimeError(format!(
            "Could not decode stderr from ip with {e:?}"
        ))),
    }
}
