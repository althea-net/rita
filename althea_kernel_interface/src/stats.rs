use super::{KernelInterface, KernelInterfaceError};

use std::collections::HashMap;

use failure::Error;
use std::fs::File;
use std::io::Read;

impl KernelInterface {
    pub fn get_proc_stat(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/stat")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_proc_load_avg(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/loadavg")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_device_stats(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/net/dev")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_netstat(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/net/netstat")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_route_stats(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/net/route")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_snmp_stats(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/net/snmp")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_wg_stats(&self) -> Result<String, Error> {
        let mut f = File::open("/proc/net/netstat")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }
}
