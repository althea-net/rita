use super::schema::client;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable)]
#[table_name = "client"]
pub struct Client {
    pub mesh_ip: String,
    pub wg_pubkey: String,
    pub wg_port: String,
    pub luci_pass: String,
    pub internal_ip: String,
}
