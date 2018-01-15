#[macro_use]
extern crate serde_derive;

use rocksdb::{DBIterator, IteratorMode, DB, Direction};

#[macro_use]
extern crate derive_error;

extern crate rocksdb;
extern crate serde;
extern crate serde_json;
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::Serialize;

use std::str;

// use self::rocksdb::DB;

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
pub trait Storage<T: Serialize + DeserializeOwned, U: Serialize + DeserializeOwned, I: Iterator<Item = (T, U)>> {
    /// Get a value from the current key or None if it does not exist.
    fn get(&self, id: &T) -> Result<Option<U>, Error>;
    /// Insert a value under the given key. Will overwrite the existing value.
    fn insert(&self, id: &T, item: &U) -> Result<(), Error>;
    fn iter(&self) -> I;
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
pub struct RocksJsonStorage<T: Serialize + DeserializeOwned, U: Serialize + DeserializeOwned> {
    db: DB,
    bucket: u8,
    phantom1: PhantomData<T>,
    phantom2: PhantomData<U>,
}

impl<T, U> RocksJsonStorage<T, U>
    where
        T: Serialize + DeserializeOwned,
        U: Serialize + DeserializeOwned {
    pub fn new(bucket: u8, path: &str) -> RocksJsonStorage<T, U> {
        RocksJsonStorage {
            db: DB::open_default(path).unwrap(),
            bucket,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
    fn my_bucket(&self) -> u8 {
        self.bucket
    }
    fn iter(&self) -> RocksJsonIterator<T, U> {
        RocksJsonIterator {
            bucket: self.bucket,
            db_iter: self.db.iterator(IteratorMode::Start),
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
}

fn prefix_with_bucket(typ: u8, input: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(input.len() + 1);
    v.push(typ);
    v.extend_from_slice(input);
    v
}

impl<
    T: Serialize + DeserializeOwned,
    U: Serialize + DeserializeOwned,
> Storage<T, U, RocksJsonIterator<T, U>> for RocksJsonStorage<T, U> {
    fn get(&self, id: &T) -> Result<Option<U>, Error> {
        Ok(match self.db.get(&prefix_with_bucket(
            self.my_bucket(),
            &serde_json::to_vec(&id)?,
        )) {
            Ok(Some(v)) => Some(serde_json::from_slice(&v)?),
            _ => None,
        })
    }
    fn insert(&self, id: &T, item: &U) -> Result<(), Error> {
        Ok(self.db.put(
            &prefix_with_bucket(self.my_bucket(), &serde_json::to_vec(&id)?),
            &serde_json::to_vec(&item)?,
        )?)
    }
    fn iter(&self) -> RocksJsonIterator<T, U> {
        RocksJsonIterator {
            db_iter: self.db.iterator(IteratorMode::From(&[self.bucket], Direction::Forward)),
            bucket: self.bucket,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
}

struct RocksJsonIterator<T: Serialize + DeserializeOwned, U: Serialize + DeserializeOwned> {
    db_iter: DBIterator,
    bucket: u8,
    phantom1: PhantomData<T>,
    phantom2: PhantomData<U>,
}

impl<T: Serialize + DeserializeOwned, U: Serialize + DeserializeOwned> Iterator
    for RocksJsonIterator<T, U> {
    type Item = (T, U);

    fn next(&mut self) -> Option<(T, U)> {
        match self.db_iter.next() {
            Some(v) => {
                let (bucket, key): (&[u8], &[u8]) = v.0.split_at(1);
                if bucket[0] != self.bucket {
                    None
                } else {
                    Some((
                        serde_json::from_slice(key).unwrap(),
                        serde_json::from_slice(&v.1).unwrap(),
                    ))
                }
            },
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    enum Breeds {
        Shiba = 10,
        Rottweiler = 2,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Dog {
        name: String,
        color: String,
        age: u64,
    }
    #[test]
    fn insert_and_get() {
        let store = RocksJsonStorage::new(Breeds::Shiba as u8, ".db");
        let dog = Dog {
            name: "franklin".to_string(),
            color: "brown".to_string(),
            age: 3,
        };

        store.insert(&dog.name, &dog).unwrap();
        assert_eq!(dog, store.get(&dog.name).unwrap().unwrap());
    }

    #[test]
    fn iterate() {
        let store = RocksJsonStorage::new(Breeds::Shiba as u8, ".db2");
        let dog1 = Dog {
            name: "franklin".to_string(),
            color: "brown".to_string(),
            age: 3,
        };
        let dog2 = Dog {
            name: "ro".to_string(),
            color: "red".to_string(),
            age: 5,
        };
        store.insert(&dog1.name, &dog1).unwrap();
        store.insert(&dog2.name, &dog2).unwrap();

        let map: HashMap<String, Dog> = store.iter().collect();

        assert_eq!("{\"ro\": Dog { name: \"ro\", color: \"red\", age: 5 }, \"franklin\": Dog { name: \"franklin\", color: \"brown\", age: 3 }}", format!("{:?}", map));
    }
}
