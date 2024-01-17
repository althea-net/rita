//! This file contains functions that do not interact directly with Babel (eg tcp streams) but instead are dedicated
//! to parsing output

use crate::find_and_parse_babel_val;
use crate::find_babel_val;
use crate::structs::Interface;
use crate::structs::Neighbor;
use crate::structs::{BabelMonitorError, Route};
use ipnetwork::IpNetwork;
use std::iter::Iterator;
use std::net::IpAddr;
use std::str::{self};

/// Iterates over the output of a Babel dump and consumes the final line of output
/// determing if the babel command was successful or not, returning the rest of the output
/// for parsing by another function
pub fn read_babel_sync(output: &str) -> Result<String, BabelMonitorError> {
    let mut ret = String::new();
    for line in output.lines() {
        ret.push_str(line);
        ret.push('\n');
        match line.trim() {
            "ok" => {
                trace!(
                    "Babel returned ok; full output:\n{}\nEND OF BABEL OUTPUT",
                    ret
                );
                return Ok(ret);
            }
            "bad" | "no" => {
                warn!(
                    "Babel returned bad/no; full output:\n{}\nEND OF BABEL OUTPUT",
                    ret
                );
                return Err(BabelMonitorError::ReadFailed(ret));
            }
            _ => continue,
        }
    }
    trace!(
        "Terminator was never found; full output:\n{:?}\nEND OF BABEL OUTPUT",
        ret
    );
    Err(BabelMonitorError::NoTerminator(ret))
}

pub fn validate_preamble(preamble: String) -> Result<(), BabelMonitorError> {
    // Note you have changed the config interface, bump to 1.1 in babel
    if preamble.contains("ALTHEA 0.1") {
        trace!("Attached OK to Babel with preamble: {}", preamble);
        Ok(())
    } else {
        Err(BabelMonitorError::InvalidPreamble(preamble))
    }
}

pub fn parse_interfaces_sync(output: String) -> Result<Vec<Interface>, BabelMonitorError> {
    let mut vector: Vec<Interface> = Vec::new();
    let mut found_interface = false;
    for entry in output.split('\n') {
        if entry.contains("add interface") {
            found_interface = true;
            let interface = Interface {
                name: match find_babel_val("interface", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                up: match find_and_parse_babel_val("up", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                ipv4: match find_and_parse_babel_val("ipv4", entry) {
                    Ok(val) => Some(val),
                    Err(_) => None,
                },
                ipv6: match find_and_parse_babel_val("ipv6", entry) {
                    Ok(val) => Some(val),
                    Err(_) => None,
                },
            };
            vector.push(interface);
        }
    }
    if vector.is_empty() && found_interface {
        return Err(BabelMonitorError::BabelParseError(
            "All Babel Interface parsing failed!".to_string(),
        ));
    }
    Ok(vector)
}

pub fn get_local_fee_sync(babel_output: String) -> Result<u32, BabelMonitorError> {
    let fee_entry = match babel_output.split('\n').next() {
        Some(entry) => entry,
        // Even an empty string wouldn't yield None
        None => {
            return Err(BabelMonitorError::LocalFeeNotFound(String::from(
                "<Babel output is None>",
            )))
        }
    };

    if fee_entry.contains("local fee") {
        let fee = find_babel_val("fee", fee_entry)?.parse()?;
        trace!("Retrieved a local fee of {}", fee);
        return Ok(fee);
    }

    Err(BabelMonitorError::LocalFeeNotFound(String::from(fee_entry)))
}

pub fn parse_neighs_sync(output: String) -> Result<Vec<Neighbor>, BabelMonitorError> {
    let mut vector: Vec<Neighbor> = Vec::with_capacity(5);
    let mut found_neigh = false;
    for entry in output.split('\n') {
        if entry.contains("add neighbour") {
            found_neigh = true;
            let neigh = Neighbor {
                id: match find_babel_val("neighbour", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                address: match find_and_parse_babel_val("address", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                iface: match find_babel_val("if", entry) {
                    Ok(val) => val,
                    Err(_) => continue,
                },
                reach: match find_babel_val("reach", entry) {
                    Ok(val) => match u16::from_str_radix(&val, 16) {
                        Ok(val) => val,
                        Err(e) => {
                            warn!("Failed to convert reach {:?} {}", e, entry);
                            continue;
                        }
                    },
                    Err(_) => continue,
                },
                txcost: match find_and_parse_babel_val("txcost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                rxcost: match find_and_parse_babel_val("rxcost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
                // it's possible that the neighbor does not have rtt enabled
                rtt: find_and_parse_babel_val("rtt", entry).unwrap_or(0.0),
                rttcost: find_and_parse_babel_val("rttcost", entry).unwrap_or(0),
                cost: match find_and_parse_babel_val("cost", entry) {
                    Ok(entry) => entry,
                    Err(_) => continue,
                },
            };
            vector.push(neigh);
        }
    }
    if vector.is_empty() && found_neigh {
        return Err(BabelMonitorError::BabelParseError(
            "All Babel neigh parsing failed!".to_string(),
        ));
    }
    Ok(vector)
}

pub fn parse_routes_sync(babel_out: String) -> Result<Vec<Route>, BabelMonitorError> {
    let mut vector: Vec<Route> = Vec::with_capacity(20);
    let mut found_route = false;
    trace!("Got from babel dump: {}", babel_out);

    for entry in babel_out.split('\n') {
        if entry.contains("add route") {
            trace!("Parsing 'add route' entry: {}", entry);
            found_route = true;
            let route = Route {
                id: match find_babel_val("route", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                iface: match find_babel_val("if", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                xroute: false,
                installed: match find_babel_val("installed", entry) {
                    Ok(value) => value.contains("yes"),
                    Err(_) => continue,
                },
                neigh_ip: match find_and_parse_babel_val("via", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                prefix: match find_and_parse_babel_val("prefix", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                metric: match find_and_parse_babel_val("metric", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                refmetric: match find_and_parse_babel_val("refmetric", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                full_path_rtt: match find_and_parse_babel_val("full-path-rtt", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                price: match find_and_parse_babel_val("price", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
                fee: match find_and_parse_babel_val("fee", entry) {
                    Ok(value) => value,
                    Err(_) => continue,
                },
            };

            vector.push(route);
        }
    }
    if vector.is_empty() && found_route {
        return Err(BabelMonitorError::BabelParseError(
            "All Babel route parsing failed!".to_string(),
        ));
    }
    Ok(vector)
}

/// In this function we take a route snapshot then loop over the routes list twice
/// to find the neighbor local address and then the route to the destination
/// via that neighbor. This could be dramatically more efficient if we had the neighbors
/// local ip lying around somewhere.
pub fn get_route_via_neigh(
    neigh_mesh_ip: IpAddr,
    dest_mesh_ip: IpAddr,
    routes: &[Route],
) -> Result<Route, BabelMonitorError> {
    // First find the neighbors route to itself to get the local address
    for neigh_route in routes.iter() {
        // This will fail on v4 babel routes etc
        if let IpNetwork::V6(ref ip) = neigh_route.prefix {
            if ip.ip() == neigh_mesh_ip {
                let neigh_local_ip = neigh_route.neigh_ip;
                // Now we take the neigh_local_ip and search for a route via that
                for route in routes.iter() {
                    if let IpNetwork::V6(ref ip) = route.prefix {
                        if ip.ip() == dest_mesh_ip && route.neigh_ip == neigh_local_ip {
                            return Ok(route.clone());
                        }
                    }
                }
            }
        }
    }
    Err(BabelMonitorError::NoNeighbor(neigh_mesh_ip.to_string()))
}

/// Very simple utility function to get a neighbor given a route that traverses that neighbor
pub fn get_neigh_given_route(route: &Route, neighs: &[Neighbor]) -> Option<Neighbor> {
    for neigh in neighs.iter() {
        if route.neigh_ip == neigh.address {
            return Some(neigh.clone());
        }
    }
    None
}

/// Checks if Babel has an installed route to the given destination
pub fn do_we_have_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<bool, BabelMonitorError> {
    for route in routes.iter() {
        if let IpNetwork::V6(ref ip) = route.prefix {
            if ip.ip() == *mesh_ip && route.installed {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
/// Returns the installed route to a given destination
pub fn get_installed_route(mesh_ip: &IpAddr, routes: &[Route]) -> Result<Route, BabelMonitorError> {
    let mut exit_route = None;
    for route in routes.iter() {
        // Only ip6
        if let IpNetwork::V6(ref ip) = route.prefix {
            // Only host addresses and installed routes
            if ip.prefix() == 128 && route.installed && IpAddr::V6(ip.ip()) == *mesh_ip {
                exit_route = Some(route);
                break;
            }
        }
    }
    match exit_route {
        Some(v) => Ok(v.clone()),
        None => Err(BabelMonitorError::NoRoute(
            "No installed route to that destination!".to_string(),
        )),
    }
}
