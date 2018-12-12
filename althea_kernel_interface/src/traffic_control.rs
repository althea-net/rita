use super::KernelInterface;
use failure::Error;
use std::net::Ipv4Addr;

impl KernelInterface {
    /// Determines if the provided interface has a configured qdisc
    pub fn has_limit(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", iface_name]);
        let stdout = &String::from_utf8(result?.stdout)?;
        Ok(!stdout.contains("noqueue"))
    }

    /// Creates a qdisc limit with the given bandwidth tuned for the correct rate
    pub fn create_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        // we need 1kbyte of burst cache per mbit of bandwidth to actually
        // reach the shaped rate
        let burst = bw / 1000 as u32;
        // amount of time a packet can spend in the burst cache, 40ms
        let latency = 40u32;

        let output = self.run_command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                iface_name,
                "root",
                "handle",
                "1:",
                "tbf",
                "latency",
                &format!("{}ms", latency),
                "burst",
                &format!("{}kbit", burst),
                "rate",
                &format!("{}kbit", bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to create new qdisc limit!");
        }
    }

    /// Creates a qdisc subclass that enforces the given limit bandwidth
    pub fn create_class_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        // we need 1kbyte of burst cache per mbit of bandwidth to actually
        // reach the shaped rate
        let burst = bw / 1000 as u32;
        // amount of time a packet can spend in the burst cache, 40ms
        let latency = 40u32;

        let output = self.run_command(
            "tc",
            &[
                "class",
                "add",
                "dev",
                iface_name,
                "parent",
                "1:",
                "classid",
                "1:1",
                "tbf",
                "latency",
                &format!("{}ms", latency),
                "burst",
                &format!("{}kbit", burst),
                "rate",
                &format!("{}kbit", bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to create new qdisc class limit!");
        }
    }

    /// edits a already limited interface to have the specified rate versus it's current rate
    pub fn update_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        // we need 1kbyte of burst cache per mbit of bandwidth to actually
        // reach the shaped rate
        let burst = bw / 1000 as u32;
        // amount of time a packet can spend in the burst cache, 40ms
        let latency = 40u32;

        let output = self.run_command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                iface_name,
                "root",
                "handle",
                "1:",
                "tbf",
                "latency",
                &format!("{}ms", latency),
                "burst",
                &format!("{}kbit", burst),
                "rate",
                &format!("{}kbit", bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to update qdisc limit!");
        }
    }

    /// deletes the interface limit
    pub fn delete_limit(&self, iface_name: &str) -> Result<(), Error> {
        let output = self.run_command("tc", &["qdisc", "del", "dev", iface_name])?;
        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to delete qdisc limit!");
        }
    }

    /// Creates a bandwidth limitation that only applies to a specific ip
    /// TODO when ipv6 exit support is added this will need to be revisited
    pub fn create_limit_by_ip(&self, iface_name: &str, ip: Ipv4Addr) -> Result<(), Error> {
        let output = self.run_command(
            "tc",
            &[
                "filter",
                "add",
                "dev",
                iface_name,
                "parent",
                "1:",
                "protocol",
                "ip",
                "prio 16",
                "u32",
                "match",
                "ip",
                "dst",
                &ip.to_string(),
                "flowid",
                "1:1",
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to create limit by ip!");
        }
    }

    /// Creates a bandwidth limitation that only applies to a specific ip
    /// TODO when ipv6 exit support is added this will need to be revisited
    pub fn delete_limit_by_ip(&self, iface_name: &str, ip: Ipv4Addr) -> Result<(), Error> {
        let output = self.run_command(
            "tc",
            &[
                "filter",
                "del",
                "dev",
                iface_name,
                "parent",
                "1:",
                "protocol",
                "ip",
                "prio 16",
                "u32",
                "match",
                "ip",
                "dst",
                &ip.to_string(),
                "flowid",
                "1:1",
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to create limit by ip!");
        }
    }
}
