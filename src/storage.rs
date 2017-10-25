use std::collections::HashMap;
use types::{Account, Address, Bytes32, Channel, Counterparty, Fullnode};

#[cfg(test)]
pub struct Storage {}

#[cfg(not(test))]
pub struct Storage {
    channels: HashMap<Bytes32, Channel>,
    accounts: HashMap<Address, Account>,
    counterparties: HashMap<Address, Counterparty>,
    fullNodes: Vec<Fullnode>,
}

#[cfg(not(test))]
impl Storage {
    pub fn new() -> Storage {
        Storage {
            channels: HashMap::new(),
            accounts: HashMap::new(),
            counterparties: HashMap::new(),
            fullNodes: Vec::new(),
        }
    }

    pub fn new_channel(&mut self, channel: Channel) -> Result<(), String> {
        if self.channels.contains_key(&channel.channel_id) {
            Err(String::from("foo"))
        } else {
            self.set_channel(channel);
            Ok(())
        }
    }
    pub fn set_channel(&mut self, channel: Channel) {
        self.channels.insert(channel.channel_id, channel);
    }
    pub fn get_channel(&self, channel_id: &Bytes32) -> Option<&Channel> {
        self.channels.get(channel_id)
    }

    pub fn new_counterparty(&mut self, counterparty: Counterparty) -> Result<(), String> {
        if self.counterparties.contains_key(&counterparty.address) {
            Err(String::from("foo"))
        } else {
            self.set_counterparty(counterparty);
            Ok(())
        }
    }
    pub fn set_counterparty(&mut self, counterparty: Counterparty) {
        self.counterparties
            .insert(counterparty.address, counterparty);
    }
    pub fn get_counterparty(&self, address: &Address) -> Option<&Counterparty> {
        self.counterparties.get(address)
    }
}
