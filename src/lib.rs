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

/// Storage is a trait that can be implemented by structs wrapping key value stores.
///
/// ```
/// #[derive(Serialize, Deserialize, Debug, PartialEq)]
/// struct Dog {
///     name: String,
///     color: String,
///     age: u64,
/// }
///
/// let store = RocksStorage::new(0, ".db");
/// let dog = Dog {
///     name: "franklin".to_string(),
///     color: "brown".to_string(),
///     age: 3,
/// };
///
/// store.insert(&dog.name, &dog).unwrap();
/// assert_eq!(dog, store.get(&dog.name).unwrap().unwrap());

/// ```
pub trait Storage {
    /// Get a value from the current key or None if it does not exist.
    fn get<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
    ) -> Result<Option<U>, Error>;
    /// Insert a value under the given key. Will overwrite the existing value.
    fn insert<T: Serialize, U: Serialize + DeserializeOwned>(
        &self,
        id: &T,
        item: &U,
    ) -> Result<(), Error>;
}

/// RocksJsonStorage implements the Storage trait, storing data in RocksDB,
/// serialized as JSON. Multiple instances of RocksJsonStorage can use 1 RocksDB by
/// initializing with different "bucket" u8's. This is not currently safe to use from
/// different threads.
///
/// ```
/// enum Breeds {
///     Shiba = 1,
///     Rottweiler = 2,
/// }
///
/// #[derive(Serialize, Deserialize, Debug, PartialEq)]
/// struct Dog {
///     name: String,
///     color: String,
///     age: u64,
/// }
///
/// #[test]
/// fn it_works() {
///     let store = RocksJsonStorage::new(Breeds::Shiba as u8, ".db");
///     let dog = Dog {
///         name: "franklin".to_string(),
///         color: "brown".to_string(),
///         age: 3,
///     };
///
///     store.insert(&dog.name, &dog).unwrap();
///     assert_eq!(dog, store.get(&dog.name).unwrap().unwrap());
/// }
/// ```
pub struct RocksJsonStorage {
    db: DB,
    bucket: u8,
}

impl RocksJsonStorage {
    fn new(bucket: u8, path: &str) -> RocksJsonStorage {
        RocksJsonStorage {
            db: DB::open_default(path).unwrap(),
            bucket,
        }
    }
    fn my_bucket(&self) -> u8 {
        self.bucket
    }
}

fn prefix_with_bucket(typ: u8, input: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(input.len() + 1);
    v.push(typ);
    v.extend_from_slice(input);
    v
}

impl Storage for RocksJsonStorage {
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
}


#[cfg(test)]
mod tests {
    use super::*;
    enum Breeds {
        Shiba = 1,
        Rottweiler = 2,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Dog {
        name: String,
        color: String,
        age: u64,
    }
    #[test]
    fn it_works() {
        let store = RocksJsonStorage::new(Breeds::Shiba as u8, ".db");
        let dog = Dog {
            name: "franklin".to_string(),
            color: "brown".to_string(),
            age: 3,
        };

        store.insert(&dog.name, &dog).unwrap();
        assert_eq!(dog, store.get(&dog.name).unwrap().unwrap());
    }
}
