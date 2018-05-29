use std::time::SystemTime;

/// This is a helper struct for measuring the round trip time over the exit tunnel independently
/// from Babel. In the future, `RTTimestamps` should aid in RTT-related overadvertisement detection.
#[derive(Serialize, Deserialize, Debug)]
pub struct RTTimestamps {
    pub exit_rx: SystemTime,
    pub exit_tx: SystemTime,
}
