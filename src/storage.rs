use std::collections::HashMap;
use types::{Bytes32, Channel};

struct Storage {
    channels: HashMap<Bytes32, Channel>,
}

impl Storage {
    pub fn new() -> Storage {
        let channels = HashMap::new();
        Storage { channels }
    }
    pub fn getChannel(&self, channelId: &Bytes32) -> Option<&Channel> {
        self.channels.get(channelId)
    }
    pub fn setChannel(&mut self, channelId: Bytes32, channel: Channel) {
        self.channels.insert(channelId, channel);
    }
}
