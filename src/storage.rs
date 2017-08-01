use std::collections::HashMap;
use types::{Bytes32, Address, Channel, Account, Counterparty, Fullnode};

pub struct Storage {
    channels: HashMap<Bytes32, Channel>,
    accounts: HashMap<Address, Account>,
    counterparties: HashMap<Address, Counterparty>,
    fullNodes: Vec<Fullnode>,
}

impl Storage {
    pub fn new() -> Storage {
        Storage {
            channels: HashMap::new(),
            accounts: HashMap::new(),
            counterparties: HashMap::new(),
            fullNodes: Vec::new(),
        }
    }

    pub fn get_channel(&self, channel_id: &Bytes32) -> Option<&Channel> {
        self.channels.get(channel_id)
    }
    pub fn new_channel(&mut self, channel: Channel) -> Result<(), String> {
        if self.channels.contains_key(&channel.channel_id) {
            Err("foo".to_string())
        } else {
            self.set_channel(channel);
            Ok(())
        }
    }
    pub fn set_channel(&mut self, channel: Channel) {
        self.channels.insert(channel.channel_id, channel);
    }
}
