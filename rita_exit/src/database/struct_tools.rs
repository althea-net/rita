use althea_kernel_interface::ExitClient;
use althea_types::ExitClientIdentity;
use althea_types::Identity;
use arrayvec::ArrayString;
use exit_db::models;
use exit_db::models::Client;
use ipnetwork::IpNetwork;
use rand::Rng;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::RitaExitError;

pub fn to_identity(client: &Client) -> Result<Identity, Box<RitaExitError>> {
    trace!("Converting client {:?}", client);
    Ok(Identity {
        mesh_ip: match client.mesh_ip.clone().parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        eth_address: match client.eth_address.clone().parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        wg_public_key: match client.wg_pubkey.clone().parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        nickname: Some(ArrayString::<32>::from(&client.nickname).unwrap_or_default()),
    })
}

pub fn to_exit_client(client: Client) -> Result<ExitClient, Box<RitaExitError>> {
    let mut internet_ipv6_list = vec![];
    let string_list: Vec<&str> = client.internet_ipv6.split(',').collect();
    for ip_net in string_list {
        // can we parse the ip net
        match ip_net.parse::<IpNetwork>() {
            Ok(ip_net) => internet_ipv6_list.push(ip_net),
            Err(e) => error!(
                "Unable to parse {:?}, Invalid database state? {:?}",
                ip_net, e
            ),
        }
    }

    Ok(ExitClient {
        mesh_ip: match client.mesh_ip.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        internal_ip: match client.internal_ip.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        port: client.wg_port as u16,
        public_key: match client.wg_pubkey.parse() {
            Ok(a) => a,
            Err(e) => return Err(Box::new(e.into())),
        },
        internet_ipv6_list,
    })
}

pub fn clients_to_ids(clients: Vec<Client>) -> Vec<Identity> {
    let mut ids: Vec<Identity> = Vec::new();
    for client in clients.iter() {
        match (client.verified, to_identity(client)) {
            (true, Ok(id)) => ids.push(id),
            (true, Err(e)) => warn!("Corrupt database entry {:?}", e),
            (false, _) => trace!("{:?} is not registered", client),
        }
    }
    ids
}

/// returns true if client is verified
pub fn verif_done(client: &models::Client) -> bool {
    client.verified
}

/// returns the number of text messages this entry has requested
/// and recieved so far
pub fn texts_sent(client: &models::Client) -> i32 {
    client.text_sent
}

/// quick display function for a neat error
pub fn display_hashset(input: &HashSet<String>) -> String {
    let mut out = String::new();
    for item in input.iter() {
        write!(out, "{item}, ").unwrap();
    }
    out
}

pub fn client_to_new_db_client(
    client: &ExitClientIdentity,
    new_ip: IpAddr,
    country: String,
    internet_ip: Option<IpNetwork>,
) -> models::Client {
    let mut rng = rand::thread_rng();
    let rand_code: u64 = rng.gen_range(0..999_999);
    models::Client {
        wg_port: i32::from(client.wg_port),
        mesh_ip: client.global.mesh_ip.to_string(),
        wg_pubkey: client.global.wg_public_key.to_string(),
        eth_address: client.global.eth_address.to_string().to_lowercase(),
        nickname: client.global.nickname.unwrap_or_default().to_string(),
        internal_ip: new_ip.to_string(),
        internet_ipv6: {
            if let Some(ip_net) = internet_ip {
                ip_net.to_string()
            } else {
                "".to_string()
            }
        },
        email: client.reg_details.email.clone().unwrap_or_default(),
        phone: client.reg_details.phone.clone().unwrap_or_default(),
        country,
        email_code: format!("{rand_code:06}"),
        text_sent: 0,
        verified: false,
        email_sent_time: 0,
        last_seen: 0,
        last_balance_warning_time: 0,
    }
}
