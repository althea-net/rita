use super::KernelInterface;

use failure::Error;
use std::fs::File;
use std::io::Read;

impl KernelInterface {
    pub fn get_proc_stat(&self) -> Result<String, Error> {
        debug!("getting proc stat");
        let mut f = File::open("/proc/stat")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_proc_load_avg(&self) -> Result<String, Error> {
        debug!("getting proc loadavg");
        let mut f = File::open("/proc/loadavg")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_device_stats(&self) -> Result<String, Error> {
        debug!("getting device stats");
        let mut f = File::open("/proc/net/dev")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_meminfo_stats(&self) -> Result<String, Error> {
        debug!("getting meminfo");
        let mut f = File::open("/proc/meminfo")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_cpuinfo_stats(&self) -> Result<String, Error> {
        debug!("getting cpuinfo");
        let mut f = File::open("/proc/cpuinfo")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_route_stats(&self) -> Result<String, Error> {
        debug!("getting route stats");
        let mut f = File::open("/proc/net/route")?;

        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }
}
