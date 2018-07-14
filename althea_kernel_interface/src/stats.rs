use super::KernelInterface;

use failure::Error;
use std::fs::File;
use std::io::Read;

impl KernelInterface {
    fn read_file(&self, path_str: &str) -> Result<String, Error> {
        let mut f = File::open(path_str)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(contents)
    }

    pub fn get_proc_stat(&self) -> Result<String, Error> {
        debug!("getting proc stat");

        let contents = self.read_file("/proc/stat")?;

        Ok(contents)
    }

    pub fn get_proc_load_avg(&self) -> Result<String, Error> {
        debug!("getting proc loadavg");

        let contents = self.read_file("/proc/loadavg")?;

        Ok(contents)
    }

    pub fn get_device_stats(&self) -> Result<String, Error> {
        debug!("getting device stats");

        let contents = self.read_file("/proc/net/dev")?;

        Ok(contents)
    }

    pub fn get_meminfo_stats(&self) -> Result<String, Error> {
        debug!("getting meminfo");

        let contents = self.read_file("/proc/meminfo")?;

        Ok(contents)
    }

    pub fn get_cpuinfo_stats(&self) -> Result<String, Error> {
        debug!("getting cpuinfo");

        let contents = self.read_file("/proc/cpuinfo")?;

        Ok(contents)
    }

    pub fn get_route_stats(&self) -> Result<String, Error> {
        debug!("getting route stats");

        let contents = self.read_file("/proc/net/route")?;

        Ok(contents)
    }
}
