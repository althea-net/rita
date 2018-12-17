//! This module performs traffic control commands for botht the exit and rita common
//! exit and common traffic control are fundamentally different becuase the exit is limiting
//! clients on the single exit tunnel, requiring classification of traffic from specific ip's
//! Rita common in contrast is a simple limitation of the neighbors tunnel, which does not do
//! any classful categorization. As a result one uses tbf and the other uses the clsssful htb

use super::KernelInterface;
use failure::Error;
use std::net::Ipv4Addr;

impl KernelInterface {
    /// Determines if the provided interface has a configured qdisc
    pub fn has_qdisc(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", iface_name]);
        let stdout = &String::from_utf8(result?.stdout)?;
        Ok(!stdout.contains("noqueue"))
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_limit(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", iface_name]);
        let stdout = &String::from_utf8(result?.stdout)?;
        Ok(stdout.contains("tbf") && !stdout.contains("codel") && !stdout.contains("noqueue"))
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_cake(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", iface_name]);
        let stdout = &String::from_utf8(result?.stdout)?;
        Ok((stdout.contains("codel") || stdout.contains("cake"))
            && !stdout.contains("tbf")
            && !stdout.contains("noqueue")
            && !stdout.contains("htb"))
    }

    /// This sets up latency protecting flow control, either cake on openwrt
    /// or fq_codel on older devices/kernels
    pub fn set_codel_shaping(&self, iface_name: &str) -> Result<(), Error> {
        if self.has_qdisc(iface_name)? {
            self.delete_qdisc(iface_name)?;
        }

        let output = self.run_command(
            "tc",
            &[
                "qdisc", "add", "dev", iface_name, "root", "handle", "1:", "cake",
            ],
        )?;

        if !output.status.success() {
            warn!("No support for the cake qdisc as detected, falling back to fq_codel");
            warn!("Cake is strongly recomended, you should install it");
            let output = self.run_command(
                "tc",
                &[
                    "qdisc", "add", "dev", iface_name, "root", "handle", "1:", "fq_codel",
                ],
            )?;

            if !output.status.success() {
                let res = String::from_utf8(output.stderr)?;
                bail!("Failed to create new qdisc limit! {:?}", res);
            }
        }

        Ok(())
    }

    /// Creates a qdisc limit with the given bandwidth tuned for the correct rate
    /// this limit uses tbf which is classless and faster since we leave prioritization
    /// to the fq_codel on the ingress and egress interfaces
    pub fn set_classless_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        if self.has_qdisc(iface_name)? {
            self.delete_qdisc(iface_name)?;
        }

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
            let res = String::from_utf8(output.stderr)?;
            bail!("Failed to create new qdisc limit! {:?}", res);
        }
    }

    /// Creates the root limit on the wg_exit tunnel for the exit, under which all other classes
    /// operate
    pub fn create_root_classful_limit(&self, iface_name: &str) -> Result<(), Error> {
        let output = self.run_command(
            "tc",
            &[
                "qdisc", "add", "dev", iface_name, "root", "handle", "1:", "htb", "default", "0",
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            bail!("Failed to create new qdisc limit! {:?}", res);
        }
    }

    pub fn set_class_limit(
        &self,
        iface_name: &str,
        min_bw: u32,
        max_bw: u32,
        class_id: u32,
    ) -> Result<(), Error> {
        if self.has_qdisc(iface_name)? {
            self.delete_qdisc(iface_name)?;
        }

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
                &format!("1:{}", class_id),
                "htb",
                "rate",
                &format!("{}kbps", min_bw),
                "ceil",
                &format!("{}kbps", max_bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            bail!("Failed to update qdisc class limit! {:?}", res);
        }
    }

    /// Generates a unique traffic class id for a exit user, essentially a really dumb hashing function
    pub fn get_class_id(&self, ip: &Ipv4Addr) -> u32 {
        ip.octets()[3] as u32 + ip.octets()[2] as u32
    }

    /// Filters traffic from a given ipv4 address into the class that we are using
    /// to shape that traffic on the exit side, uses the last two octets of the ip
    /// to generate a class id.
    /// TODO when ipv6 exit support is added this will need to be revisited
    pub fn create_classifier_by_ip(&self, iface_name: &str, ip: &Ipv4Addr) -> Result<(), Error> {
        let class_id = self.get_class_id(ip);

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
                "prio 1",
                "u32",
                "match",
                "ip",
                "dst",
                &ip.to_string(),
                "flowid",
                &format!("1:{}", class_id),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            bail!("Failed to create limit by ip! {:?}", res);
        }
    }

    /// deletes the interface qdisc
    pub fn delete_qdisc(&self, iface_name: &str) -> Result<(), Error> {
        let output = self.run_command("tc", &["qdisc", "del", "dev", iface_name, "root"])?;
        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to delete qdisc limit!");
        }
    }
}