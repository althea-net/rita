#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derive_error;

extern crate rocksdb;
extern crate serde;
extern crate serde_json;

use serde::de::DeserializeOwned;
use serde::Serialize;

use std::str;

use self::rocksdb::DB;

#[derive(Debug, Error)]
pub enum Error {
    Json(serde_json::Error),
    Rocksdb(rocksdb::Error),
    #[error(msg_embedded, no_from, non_std)] Storage(String),
}

pub trait Storage {
    /// Get a value from the current key or None if it does not exist.
    fn get<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
    ) -> Result<Option<U>, Error>;
    /// Insert a value under the given key.
    fn insert<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
        item: &U,
    ) -> Result<(), Error>;
    /// Return the bucket identifier that the Storage was instantiated with (this is
    /// to allow multiple processes to use the same underlying store).
    fn my_bucket(&self) -> u8;
}

pub struct RocksStorage {
    db: DB,
    bucket: u8,
}

impl RocksStorage {
    fn new(bucket: u8, path: &str) -> RocksStorage {
        RocksStorage {
            db: DB::open_default(path).unwrap(),
            bucket,
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
    fn get<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
    ) -> Result<Option<U>, Error> {
        Ok(match self.db.get(&prefix_with_bucket(
            self.my_bucket(),
            &serde_json::to_vec(&id)?,
        )) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v)?),
            _ => None,
        })
    }
    fn insert<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
        item: &U,
    ) -> Result<(), Error> {
        Ok(self.db.put(
            &prefix_with_bucket(self.my_bucket(), &serde_json::to_vec(&id)?),
            &serde_json::to_vec(&item)?,
        )?)
    }
    fn my_bucket(&self) -> u8 {
        self.bucket
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Dog {
        name: String,
        color: String,
        age: u64,
    }
    #[test]
    fn it_works() {
        let store = RocksStorage::new(0, ".db");
        let dog = Dog {
            name: "franklin".to_string(),
            color: "brown".to_string(),
            age: 3,
        };

        store.insert(&dog.name, &dog).unwrap();
        assert_eq!(dog, store.get(&dog.name).unwrap().unwrap());
    }
}
