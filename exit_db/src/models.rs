use schema::clients;
use std::net::IpAddr;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable, Clone, AsChangeset)]
#[table_name = "clients"]
pub struct Client {
    pub mesh_ip: String,
    pub wg_pubkey: String,
    pub wg_port: String,
    pub luci_pass: String,
    pub internal_ip: String,
    pub email: String,
    pub zip: String,
    pub country: String,
}
