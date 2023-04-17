//! This module contains a bunch of dummy functions that are called to populate a dummy exit so that heart beats
//! send data to op tools without actually being connected to an exit
use althea_types::ExitDetails;
use althea_types::FromStr;
use althea_types::Identity;
use althea_types::LocalIdentity;
use althea_types::WgKey;
use babel_monitor::structs::Neighbor;
use babel_monitor::structs::Route;
use clarity::Address;
use ipnetwork::IpNetwork;
use rita_common::tunnel_manager::Neighbor as RitaNeighbor;
use std::net::IpAddr;
use std::net::Ipv4Addr;

/// Creates a dummy babel monitor route
#[allow(dead_code)]
pub fn dummy_route() -> Route {
    Route {
        id: "dummy".to_string(),
        iface: "dummy_if".to_string(),
        xroute: false,
        installed: true,
        neigh_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        prefix: IpNetwork::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 16).unwrap(),
        metric: 100,
        refmetric: 200,
        full_path_rtt: 200.0,
        price: 100,
        fee: 100,
    }
}

/// Creates a dummy babel monitor neighbor
#[allow(dead_code)]
pub fn dummy_neigh_babel() -> Neighbor {
    Neighbor {
        id: "dummy_nei".to_string(),
        address: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        iface: "dummy_iface".to_string(),
        reach: 10,
        txcost: 10,
        rxcost: 10,
        rtt: 10.0,
        rttcost: 10,
        cost: 10,
    }
}

/// creates a dummy rita neighbor
#[allow(dead_code)]
pub fn dummy_neigh_tunnel() -> RitaNeighbor {
    RitaNeighbor {
        identity: LocalIdentity {
            wg_port: 10,
            have_tunnel: None,
            global: Identity {
                mesh_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                eth_address: Address::parse_and_validate(
                    "0x9CAFD25b8b5982F1edA0691DEF8997C55a4d8188",
                )
                .unwrap(),
                althea_address: Some(
                    "althea11lrsu892mqx2mndyvjufrh2ux56tyfxl2e3eht3"
                        .parse()
                        .unwrap(),
                ),
                wg_public_key: WgKey::from_str("8BeCExnthLe5ou0EYec5jNqJ/PduZ1x2o7lpXJOpgXk=")
                    .unwrap(),
                nickname: None,
            },
        },
        iface_name: "dummy_iface".to_string(),
        tunnel_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        speed_limit: None,
    }
}

/// Creates dummy 'ExitDetails' struct
#[allow(dead_code)]
pub fn dummy_selected_exit_details() -> ExitDetails {
    ExitDetails {
        server_internal_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        netmask: 200,
        wg_exit_port: 100,
        exit_price: 100,
        exit_currency: althea_types::SystemChain::Ethereum,
        description: "".to_string(),
        verif_mode: althea_types::ExitVerifMode::Off,
    }
}
