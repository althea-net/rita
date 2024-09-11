use crate::Identity;

/// Struct for storing peer status data for reporting to the operator tools server
/// the goal is to give a full picture of all links in the network to the operator
/// so we include not only the link speed but also the stats history of the link
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct NeighborStatus {
    /// the id of the neighbor
    pub id: Identity,
    /// their shaped wg interface speed in mbps
    pub shaper_speed: Option<usize>,
    /// If this user is currently being enforced upon
    #[serde(default)]
    pub enforced: bool,
}
