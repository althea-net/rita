extern crate rocksdb;
use serde::de::DeserializeOwned;
use serde::Serialize;
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

pub trait Storable: Serialize + DeserializeOwned {
    fn my_bucket() -> u8;
    fn my_id(&self) -> &[u8];
}

pub trait Storage {
    fn get_item<T: Storable>(&self, id: &[u8]) -> Result<Option<T>, Error>;
    fn set_item<T: Storable>(&self, item: T) -> Result<(), Error>;
    fn new_item<T: Storable>(&self, item: T) -> Result<(), Error>;
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

fn prefix_with_bucket(typ: u8, input: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(input.len() + 1);
    v.push(typ);
    v.extend_from_slice(input);
    v
}

impl Storage for RocksStorage {
    fn new_item<T>(&self, item: T) -> Result<(), Error>
    where
        T: Storable,
    {
        match self.db
            .get(&prefix_with_bucket(T::my_bucket(), item.my_id()))?
        {
            Some(_) => Err(Error::RuntimeError(String::from(format!(
                "id {:?} already exists in {:?}",
                item.my_id(),
                T::my_bucket(),
            )))),
            None => self.set_item(item),
        }
    }
    fn get_item<T>(&self, id: &[u8]) -> Result<Option<T>, Error>
    where
        T: Storable,
    {
        Ok(
            match self.db.get(&prefix_with_bucket(T::my_bucket(), &*id)) {
                Ok(Some(v)) => Some(serde_json::from_slice(&v)?),
                _ => None,
            },
        )
    }
    fn set_item<T>(&self, item: T) -> Result<(), Error>
    where
        T: Storable,
    {
        Ok(self.db.put(
            &prefix_with_bucket(T::my_bucket(), item.my_id()),
            &serde_json::to_vec(&item)?,
        )?)
    }
}
