#![allow(clippy::extra_unused_lifetimes)]
use crate::schema::assigned_ips;
use crate::schema::clients;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable, Clone, Default)]
#[table_name = "clients"]
pub struct Client {
    pub mesh_ip: String,
    pub wg_pubkey: String,
    pub wg_port: i32,
    pub eth_address: String,
    pub althea_address: String,
    pub internal_ip: String,
    pub internet_ipv6: String,
    pub nickname: String,
    pub email: String,
    pub phone: String,
    pub country: String,
    pub email_code: String,
    pub verified: bool,
    pub email_sent_time: i64,
    pub text_sent: i32,
    pub last_seen: i64,
    pub last_balance_warning_time: i64,
}

/// This struct holds information about the ipv6 subnets being assigned to clients who connect.
/// The vector available subnets is a stack that has a list of available subnets to use. This stack gets populated whenever
/// a client gets removed from the database. It is stored as a string of indecies, for example, "1,24,36"
/// The iterative index stores the index at which we assign a subnet to a client
/// For example, if our exit subnet is fd00::1000/120 and our client subnets are /124, index 0 represents
/// fd00::1000/124 index 1 represents fd00::1010/124, 2 is fd00::1120/124 etc...
#[derive(Queryable, Serialize, Deserialize, Debug, Insertable, Clone, Default)]
#[table_name = "assigned_ips"]
pub struct AssignedIps {
    pub subnet: String,
    pub available_subnets: String,
    pub iterative_index: i64,
}
