extern crate rocksdb;
use std::collections::HashMap;
use types::{Account, Address, Bytes32, Channel, Counterparty, Fullnode};
use self::rocksdb::DB;

const CHANNELS: u8 = 1;


pub trait Storage {
    fn new_channel(&self, channel: Channel) -> Result<(), String>;
    fn set_channel(&self, channel: Channel) -> Result<(), String>;
    fn get_channel(&self, channel_id: &Bytes32) -> Result<Option<&Channel>, String>;
    // fn new_counterparty(self, counterparty: Counterparty) -> Result<(), String>;
    // fn set_counterparty(self, counterparty: Counterparty) -> Result<(), String>;
    // fn get_counterparty(&self, address: &Address) -> Result<Option<&Counterparty>, String>;
}

pub struct MemStorage {
    channels: HashMap<Bytes32, Channel>,
    accounts: HashMap<Address, Account>,
    counterparties: HashMap<Address, Counterparty>,
    fullNodes: Vec<Fullnode>,
}

pub struct RocksStorage {
    db: DB,
}

impl RocksStorage {
    fn new() -> RocksStorage {
        RocksStorage {
            db: DB::open_default("path/for/rocksdb/storage").unwrap(),
        }
    }
}

fn prefix_with_id(id: u8, input: &[u8]) -> &[u8] {
    let mut v = Vec::with_capacity(input.len() + 1);
    v.extend_from_slice(input);
    &v
}

impl Storage for RocksStorage {
    fn new_channel(&self, channel: Channel) -> Result<(), String> {
        match self.db.get(&channel.channel_id) {
            Ok(Some(value)) => {
                return Err(String::from(
                    "channel with this id already exists in storage",
                ))
            }
            Ok(None) => Ok(()),
            Err(e) => Err(e.to_string()),
        };

        self.db
            .put(
                prefix_with_id(CHANNELS, &channel.channel_id),
                b"CHANNEL AS STRING",
            )
            .map_err(|e| e.to_string())
    }

    fn set_channel(&self, channel: Channel) -> Result<(), String> {
        self.db
            .put(
                prefix_with_id(CHANNELS, &channel.channel_id),
                b"CHANNEL AS STRING",
            )
            .map_err(|e| e.to_string())
    }

    fn get_channel(&self, channel_id: &Bytes32) -> Result<Option<&Channel>, String> {
        self.db
            .get(
                prefix_with_id(CHANNELS, &channel.channel_id),
                b"CHANNEL AS STRING",
            )
            .map_err(|e| e.to_string())
    }
}

// impl MemStorage {
//     fn new() -> MemStorage {
//         MemStorage {
//             channels: HashMap::new(),
//             accounts: HashMap::new(),
//             counterparties: HashMap::new(),
//             fullNodes: Vec::new(),
//         }
//     }
// }

// impl Storage for MemStorage {
//     fn new_channel(&mut self, channel: Channel) -> Result<(), String> {
//         if self.channels.contains_key(&channel.channel_id) {
//             Err(String::from("foo"))
//         } else {
//             self.set_channel(channel);
//             Ok(())
//         }
//     }

//     fn set_channel(&mut self, channel: Channel) -> Result<(), String> {
//         self.channels.insert(channel.channel_id, channel);
//         Ok(())
//     }

//     fn get_channel(&self, channel_id: &Bytes32) -> Result<Option<&Channel>, String> {
//         Ok(self.channels.get(channel_id))
//     }

//     fn new_counterparty(&mut self, counterparty: Counterparty) -> Result<(), String> {
//         if self.counterparties.contains_key(&counterparty.address) {
//             Err(String::from("foo"))
//         } else {
//             self.set_counterparty(counterparty);
//             Ok(())
//         }
//     }

//     fn set_counterparty(&mut self, counterparty: Counterparty) -> Result<(), String> {
//         self.counterparties
//             .insert(counterparty.address, counterparty);
//         Ok(())
//     }

//     fn get_counterparty(&self, address: &Address) -> Result<Option<Counterparty>, String> {
//         Ok(self.counterparties.get(address).map(|v| *v.clone()))
//     }
// }
