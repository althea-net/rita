//! The Settings crate handles settings for Rita, specifically it uses lazy_static to load and
//! deserialize the config file on system start. Once deserialized using Serde into internal data
//! structures it is then provided to Rita as a global static reference, this reference is locked
//! using a RwLock to allow multiple readers and writers throughout the code. If you hold a read
//! reference in a blocking function call or a read and write reference at the same time you will
//! cause a deadlock.
//!
//! This can be dependent on the behavior of the borrow checker since the lock
//! is released based on when the reference is dropped. Take care when using _mut to either
//! namespace or clone quickly to avoid deadlocks.

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

#[cfg(test)]
use std::sync::Mutex;

use config;

use toml;

use serde;
use serde_json;

use owning_ref::{RwLockReadGuardRef, RwLockWriteGuardRefMut};

use std::fs::File;
use std::io::Write;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use althea_kernel_interface::KernelInterface;

#[cfg(not(test))]
use althea_kernel_interface::LinuxCommandRunner;
#[cfg(test)]
use althea_kernel_interface::TestCommandRunner;

use althea_types::Identity;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use failure::Error;

pub mod client;
pub mod dao;
pub mod exit;
pub mod loging;
pub mod network;
pub mod payment;

use crate::dao::SubnetDAOSettings;
use crate::network::NetworkSettings;
use crate::payment::PaymentSettings;

/// This is the network settings for rita and rita_exit which generally only applies to networking
/// _within_ the mesh or setting up pre hop tunnels (so nothing on exits)
#[cfg(test)]
lazy_static! {
    static ref KI: Box<dyn KernelInterface> = Box::new(TestCommandRunner {
        run_command: Arc::new(Mutex::new(Box::new(|_program, _args| {
            panic!("kernel interface used before initialized");
        })))
    });
}

#[cfg(not(test))]
lazy_static! {
    static ref KI: Box<dyn KernelInterface> = Box::new(LinuxCommandRunner {});
}

pub trait RitaCommonSettings<T: Serialize + Deserialize<'static>> {
    fn get_payment<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, PaymentSettings>;
    fn get_payment_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, PaymentSettings>;

    fn get_dao<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, SubnetDAOSettings>;
    fn get_dao_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, SubnetDAOSettings>;

    fn get_network<'ret, 'me: 'ret>(&'me self) -> RwLockReadGuardRef<'ret, T, NetworkSettings>;
    fn get_network_mut<'ret, 'me: 'ret>(
        &'me self,
    ) -> RwLockWriteGuardRefMut<'ret, T, NetworkSettings>;

    fn merge(&self, changed_settings: Value) -> Result<(), Error>;
    fn get_all(&self) -> Result<serde_json::Value, Error>;

    // Can be None if the mesh ip was not configured yet
    fn get_identity(&self) -> Option<Identity>;

    fn get_future(&self) -> bool;
    fn set_future(&self, future: bool);
}

/// This merges 2 json objects, overwriting conflicting values in `a`
fn json_merge(a: &mut Value, b: &Value) {
    match (a, b) {
        (&mut Value::Object(ref mut a), &Value::Object(ref b)) => {
            for (k, v) in b {
                json_merge(a.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (a, b) => {
            *a = b.clone();
        }
    }
}

pub trait FileWrite {
    fn write(&self, file_name: &str) -> Result<(), Error>;
}

fn spawn_watch_thread<'de, T: 'static>(
    settings: Arc<RwLock<T>>,
    file_path: &str,
) -> Result<(), Error>
where
    T: serde::Deserialize<'de> + Sync + Send + std::fmt::Debug + Clone + Eq + FileWrite,
{
    let file_path = file_path.to_string();

    thread::spawn(move || {
        let old_settings = settings.read().unwrap().clone();
        loop {
            thread::sleep(Duration::from_secs(600));

            let new_settings = settings.read().unwrap().clone();

            if old_settings != new_settings {
                trace!("writing updated config: {:?}", new_settings);
                match settings.read().unwrap().write(&file_path) {
                    Err(e) => warn!("writing updated config failed {:?}", e),
                    _ => (),
                }
            }
        }
    });

    Ok(())
}

impl<T> FileWrite for T
where
    T: Serialize,
{
    fn write(&self, file_name: &str) -> Result<(), Error> {
        let ser = toml::Value::try_from(self.clone())?;
        let ser = toml::to_string(&ser)?;
        let mut file = File::create(file_name)?;
        file.write_all(ser.as_bytes())?;
        file.flush().unwrap();
        file.sync_all().unwrap();
        drop(file);
        KI.fs_sync()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::RitaSettingsStruct;
    use crate::exit::RitaExitSettingsStruct;

    #[test]
    fn test_settings_example() {
        RitaSettingsStruct::new("example.toml").unwrap();
    }

    #[test]
    fn test_settings_default() {
        RitaSettingsStruct::new("default.toml").unwrap();
    }

    #[test]
    fn test_exit_settings_default() {
        RitaExitSettingsStruct::new("default_exit.toml").unwrap();
    }

    #[test]
    fn test_exit_settings_example() {
        RitaExitSettingsStruct::new("example_exit.toml").unwrap();
    }

}
