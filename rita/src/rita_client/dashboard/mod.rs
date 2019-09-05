//! This file contains all the network endpoints used for the client dashbaord. This management dashboard
//! is for users to use to configure and manage their router and should be firewalled from the outside
//! world.
//!
//! For more documentation on specific functions see the router-dashboard file in the docs folder

pub mod backup_created;
pub mod eth_private_key;
pub mod exits;
pub mod interfaces;
pub mod logging;
pub mod mesh_ip;
pub mod neighbors;
pub mod notifications;
pub mod release_feed;
pub mod remote_access;
pub mod router;
pub mod system_chain;
pub mod usage;
pub mod wifi;

use failure::Error;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;

fn get_lines(filename: &str) -> Result<Vec<String>, Error> {
    let f = File::open(filename)?;
    let file = BufReader::new(&f);
    let mut out_lines = Vec::new();
    for line in file.lines() {
        match line {
            Ok(val) => out_lines.push(val),
            Err(_) => break,
        }
    }

    Ok(out_lines)
}

fn write_out(filename: &str, content: Vec<String>) -> Result<(), Error> {
    // overwrite the old version
    let mut file = File::create(filename)?;
    let mut final_ouput = String::new();
    for item in content {
        final_ouput += &format!("{}\n", item);
    }
    file.write_all(final_ouput.as_bytes())?;
    Ok(())
}
