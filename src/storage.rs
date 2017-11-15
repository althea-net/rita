extern crate rocksdb;
use serde::de::DeserializeOwned;
use std;
use std::collections::HashMap;
use std::str::Utf8Error;
use std::str;

use types::{Account, Address, Bytes32, Channel, Counterparty, Fullnode};
use self::rocksdb::DB;
use serde_json;



#[derive(Debug, Error)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Utf8(std::str::Utf8Error),
    Rocksdb(rocksdb::Error),
    #[error(msg_embedded, no_from, non_std)] RuntimeError(String),
}

pub trait Storage {
    fn new_channel(&self, channel: Channel) -> Result<(), Error>;
    // fn set_channel(&self, channel: Channel) -> Result<(), Error>;
    fn get_channel(&self, channel_id: Bytes32) -> Result<Option<Channel>, Error>;
    // fn new_counterparty(self, counterparty: Counterparty) -> Result<(), Error>;
    // fn set_counterparty(self, counterparty: Counterparty) -> Result<(), Error>;
    // fn get_counterparty(&self, address: &Address) -> Result<Option<&Counterparty>, Error>;
}

pub struct MemStorage {
    channels: HashMap<Bytes32, Channel>,
    accounts: HashMap<Address, Account>,
    counterparties: HashMap<Address, Counterparty>,
    full_nodes: Vec<Fullnode>,
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
    fn get_item<T>(&self, cat: Category, id: Bytes32) -> Result<Option<T>, Error>
    where
        T: DeserializeOwned,
    {
        Ok(match self.db.get(&prefix_with_category(cat, &*id)) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v)?),
            _ => None,
        })
    }
}

#[derive(Copy, Clone)]
enum Category {
    Channels,
    Counterparties,
}

fn prefix_with_category(cat: Category, input: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(input.len() + 1);
    v.push(cat as u8);
    v.extend_from_slice(input);
    v
}

impl Storage for RocksStorage {
    fn new_channel(&self, channel: Channel) -> Result<(), Error> {
        match self.db.get(&*channel.channel_id)? {
            Some(_) => Err(Error::RuntimeError(String::from(
                "channel with this id already exists in storage",
            ))),
            None => Ok(self.db.put(
                &prefix_with_category(Category::Channels, &*channel.channel_id),
                b"CHANNEL AS STRING",
            )?),
        }
    }

    // fn set_channel(&self, channel: Channel) -> Result<(), String> {
    //     self.db
    //         .put(
    //             prefix_with_id(CHANNELS, &*channel.channel_id),
    //             serde_json::to_string(&channel),
    //         )
    //         .map_err(|e| e.to_string())
    // }

    // fn get_channel(&self, channel_id: Bytes32) -> Result<Option<Channel>, Error> {
    //     match self.db.get(prefix_with_id(CHANNELS, &*channel_id)) {
    //         Ok(v) => match v {
    //             Some(v) => match str::from_utf8(&v) {
    //                 Ok(v) => match serde_json::from_str(v) {
    //                     Ok(v) => Ok(Some(v)),
    //                     Err(e) => Err(e.to_string()),
    //                 },
    //                 Err(e) => Err(e.to_string()),
    //             },
    //             None => Ok(None),
    //         },
    //         Err(e) => Err(e.to_string()),
    //     }
    // }
    fn get_channel(&self, channel_id: Bytes32) -> Result<Option<Channel>, Error> {
        Ok(match self.db
            .get(&prefix_with_category(Category::Channels, &*channel_id))
        {
            Ok(Some(v)) => Some(serde_json::from_str(str::from_utf8(&v)?)?),
            _ => None,
        })
    }
}


// fn parse_item (db_res: Result<rocksdb::DBVector>) -> Result<Option<Channel>, String>

// .map(|v| {
//     serde_json::from_str(str::from_utf8(v))
// })
// .map_err(|e| e.to_string())

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
// }
