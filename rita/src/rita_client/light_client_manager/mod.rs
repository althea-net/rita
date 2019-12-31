//! This module adds support for light clients, light clients being android hpones which connect directly to a client hotspot and have their
//! traffic piped out over the clients exit tunnel in exchange for payment. Light clients do not register to exits neither do they participate
//! in routing in any way. The billing and connection process is sort of a 'mini exit' at the router level. This isn't an ideal design at all,
//! especially since the client traffic exits unencrypted at one point on the participating Rita Client router. Sadly this is unavoidable as
//! far as I can tell due to the restrictive nature of how and when Android allows ipv6 routing.

use crate::rita_common::peer_listener::Peer;
use crate::rita_common::tunnel_manager::id_callback::IdentityCallback;
use crate::rita_common::tunnel_manager::TunnelManager;
use crate::rita_common::utils::ip_increment::incrementv4;
use crate::KI;
use crate::SETTING;
use actix::{Actor, Context, Handler, Message, Supervised, SystemService};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, Json};
use althea_types::{LightClientLocalIdentity, LocalIdentity};
use failure::Error;
use futures01::future::Either;
use futures01::{future, Future};
use settings::RitaCommonSettings;
use std::boxed::Box;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

/// Sets up a variant of the exit tunnel nat rules, assumes that the exit
/// tunnel is already created and doesn't change the system routing table
fn setup_light_client_forwarding(client_addr: Ipv4Addr, nic: &str) -> Result<(), Error> {
    // the way this works is pretty heavy on the routes and iptables rules
    // it wouldn't be feasible if we expected more than a few dozen phone
    // clients on a single device. Instead of having an aggregating network
    // like br-lan to allow us to treat multiple interfaces as a single nic
    // we manipulate routes and iptables rules for the wg tunnels directly
    // this is easier to manage programatically but as mentioned before
    // doesn't exactly scale well.
    // Key points to note here is that the routes and addresses
    // get cleaned up on their own whent the interface is deleted I'm not
    // so sure about the iptables rules yet
    trace!("adding light client nat rules");
    KI.add_client_nat_rules(nic)?;
    KI.add_ipv4("192.168.20.0".parse().unwrap(), nic)?;
    KI.run_command(
        "ip",
        &["route", "add", &format!("{}/32", client_addr), "dev", nic],
    )?;
    Ok(())
}

/// Response to the light_client_hello endpoint on the Rita client module with a modified hello packet
/// this modified packet includes an ipv4 address and opens a modified tunnel that is attached to the
/// phone network bridge into a natted ipv4 network rather than into a Babel network.
pub fn light_client_hello_response(
    req: (Json<LocalIdentity>, HttpRequest),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let their_id = *req.0;
    Box::new(
        LightClientManager::from_registry()
            .send(GetAddress(their_id))
            .from_err()
            .and_then(move |light_client_address| {
                let err_mesg = "Malformed light client hello tcp packet!";
                let socket = match req.1.connection_info().remote() {
                    Some(val) => match val.parse::<SocketAddr>() {
                        Ok(val) => val,
                        Err(e) => {
                            error!("{}", e);
                            return Either::A(future::ok(
                                HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                    .into_builder()
                                    .json(err_mesg),
                            ));
                        }
                    },
                    None => {
                        error!("{}", err_mesg);
                        return Either::A(future::ok(
                            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                .into_builder()
                                .json(err_mesg),
                        ));
                    }
                };

                let (light_client_address_option, light_client_address) = match light_client_address
                {
                    Ok(addr) => (Some(addr), addr),
                    Err(e) => {
                        let err_mesg = "Could not allocate address!";
                        error!("{} {}", err_mesg, e);
                        return Either::A(future::ok(
                            HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)
                                .into_builder()
                                .json(err_mesg),
                        ));
                    }
                };

                trace!(
                    "Got light client Hello from {:?}",
                    req.1.connection_info().remote()
                );
                trace!(
                    "opening tunnel in light_client_hello_response for {:?}",
                    their_id
                );

                let peer = Peer {
                    contact_socket: socket,
                    ifidx: 0, // only works because we lookup ifname in kernel interface
                };

                // We send the callback, which can safely allocate a port because it already successfully
                // contacted a neighbor. The exception to this is when the TCP session fails at exactly
                // the wrong time.
                Either::B(
                    TunnelManager::from_registry()
                        .send(IdentityCallback::new(
                            their_id,
                            peer,
                            None,
                            light_client_address_option,
                        ))
                        .from_err()
                        .and_then(move |tunnel| {
                            let (tunnel, have_tunnel) = match tunnel {
                                Some(val) => val,
                                None => return Err(format_err!("tunnel open failure!")),
                            };

                            let lci = LightClientLocalIdentity {
                                global: match SETTING.get_identity() {
                                    Some(id) => id,
                                    None => {
                                        return Err(format_err!(
                                            "Identity has no mesh IP ready yet"
                                        ))
                                    }
                                },
                                wg_port: tunnel.listen_port,
                                have_tunnel: Some(have_tunnel),
                                tunnel_address: light_client_address,
                            };
                            // Two bools -> 4 state truth table, in 3 of
                            // those states we need to re-add these rules
                            // router phone
                            // false false  we need to add rules to new tunnel
                            // true  false  tunnel will be re-created so new rules
                            // false true   new tunnel on our side new rules
                            // true  true   only case where we don't need to run this
                            if let Some(they_have_tunnel) = their_id.have_tunnel {
                                if !(have_tunnel && they_have_tunnel) {
                                    setup_light_client_forwarding(
                                        light_client_address,
                                        &tunnel.iface_name,
                                    )?;
                                }
                            } else {
                                error!("Light clients should never send the none tunnel option!");
                            }

                            let response = HttpResponse::Ok().json(lci);
                            Ok(response)
                        }),
                )
            }),
    )
}

pub struct LightClientManager {
    start_address: Ipv4Addr,
    prefix: u8,
    assigned_addresses: HashMap<LocalIdentity, Ipv4Addr>,
}

impl Default for LightClientManager {
    fn default() -> LightClientManager {
        LightClientManager {
            start_address: "192.168.20.1".parse().unwrap(),
            prefix: 24,
            assigned_addresses: HashMap::new(),
        }
    }
}

impl Actor for LightClientManager {
    type Context = Context<Self>;

    fn started(&mut self, _ctx: &mut Context<Self>) {
        info!("Started LightClientManager")
    }
}

impl Supervised for LightClientManager {}
impl SystemService for LightClientManager {
    fn service_started(&mut self, _ctx: &mut Context<Self>) {}
}

pub struct GetAddress(LocalIdentity);

impl Message for GetAddress {
    type Result = Result<Ipv4Addr, Error>;
}

impl Handler<GetAddress> for LightClientManager {
    type Result = Result<Ipv4Addr, Error>;

    fn handle(&mut self, msg: GetAddress, _: &mut Context<Self>) -> Self::Result {
        let requester_id = msg.0;
        trace!("Assigning light client address");
        // we already have an ip for this id on record, send the same one out
        if let Some(ip) = self.assigned_addresses.get(&requester_id) {
            return Ok(*ip);
        }
        let assigned_ips = {
            let mut set = HashSet::new();
            for (_id, ip) in self.assigned_addresses.iter() {
                set.insert(ip);
            }
            set
        };

        // get the first unused address this is kinda inefficient, I'm sure we could do this in all O(1) operations
        // but at the cost of more memory usage, which I'd rather avoid. Either way it's trivial
        // both in terms of memory and cpu at the scale of only 16 bits of address space (ipv4 private range size)
        let mut new_address: Ipv4Addr = self.start_address;
        while assigned_ips.contains(&new_address) {
            trace!("light client address {} is already assigned", new_address);
            new_address = incrementv4(new_address, self.prefix)?;
        }
        self.assigned_addresses.insert(requester_id, new_address);
        trace!(
            "finished selecting light client address, it is {}",
            new_address
        );
        Ok(new_address)
    }
}

pub struct ReturnAddress(Ipv4Addr);

impl Message for ReturnAddress {
    type Result = ();
}

impl Handler<ReturnAddress> for LightClientManager {
    type Result = ();

    fn handle(&mut self, msg: ReturnAddress, _: &mut Context<Self>) -> Self::Result {
        let returned_address = msg.0;
        let mut key_to_remove: Option<LocalIdentity> = None;
        for (key, ip) in self.assigned_addresses.iter() {
            if *ip == returned_address {
                key_to_remove = Some(*key);
            }
        }
        if let Some(val) = key_to_remove {
            self.assigned_addresses.remove(&val);
        } else {
            error!("Failed to free address {}", returned_address);
        }
    }
}
