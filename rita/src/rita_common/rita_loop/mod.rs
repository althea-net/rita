//! The main actor loop for Rita, this loop is common to both rita and rita_exit (as is everything
//! in rita common).
//!
//! This loops ties together various actors through messages and is generally the rate limiter on
//! all system functions. Anything that blocks will eventually filter up to block this loop and
//! halt essential functions like opening tunnels and managing peers

use crate::SETTING;
use rand::thread_rng;
use rand::Rng;
use settings::RitaCommonSettings;

pub mod fast_loop;
pub mod slow_loop;

/// Checks the list of full nodes, panics if none exist, if there exist
/// one or more a random entry from the list is returned in an attempt
/// to load balance across fullnodes
pub fn get_web3_server() -> String {
    if SETTING.get_payment().node_list.is_empty() {
        panic!("no full nodes configured!");
    }
    let node_list = SETTING.get_payment().node_list.clone();
    let mut rng = thread_rng();
    let val = rng.gen_range(0, node_list.len());

    node_list[val].clone()
}
