use super::schema::*;

use althea_types::{Identity, PaymentTx};
use num256::Uint256;

use failure::Error;

use serde_json;

#[derive(Queryable, Serialize, Deserialize, Debug, Insertable)]
#[table_name = "nodes"]
pub struct Node {
    pub ip: String,
    pub balance: String,
}
