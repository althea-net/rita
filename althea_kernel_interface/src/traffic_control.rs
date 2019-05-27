//! This module performs traffic control commands for botht the exit and rita common
//! exit and common traffic control are fundamentally different becuase the exit is limiting
//! clients on the single exit tunnel, requiring classification of traffic from specific ip's
//! Rita common in contrast is a simple limitation of the neighbors tunnel, which does not do
//! any classful categorization. As a result one uses tbf and the other uses the clsssful htb

use super::KernelInterface;
use failure::Error;
use regex::Regex;
use std::net::Ipv4Addr;

impl KernelInterface {
    /// Determines if the provided interface has a configured qdisc
    pub fn has_qdisc(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            bail!("Failed to check qdisc for {}! {:?}", iface_name, res);
        }

        let stdout = &String::from_utf8(result.stdout)?;

        trace!("has_qdisc: {} {}", stdout, !stdout.contains("noqueue"));
        Ok(!stdout.contains("noqueue"))
    }

    /// Determines if the provided flow is assigned
    pub fn has_flow(&self, ip: &Ipv4Addr, iface_name: &str) -> Result<bool, Error> {
        let class_id = self.get_class_id(&ip);
        let result = self.run_command("tc", &["filter", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            bail!("Failed to check filter for {}! {:?}", class_id, res);
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok(stdout.contains(&format!("1:{}", class_id)))
    }

    /// Determines if the provided flow is assigned
    pub fn has_class(&self, ip: &Ipv4Addr, iface_name: &str) -> Result<bool, Error> {
        let class_id = self.get_class_id(ip);
        let result = self.run_command("tc", &["class", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            bail!("Failed to check filter for {}! {:?}", class_id, res);
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok(stdout.contains(&format!("1:{}", class_id)))
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_limit(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            bail!("Failed to check limit for {}! {:?}", iface_name, res);
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok((stdout.contains("htb") || stdout.contains("tbf"))
            && !stdout.contains("codel")
            && !stdout.contains("noqueue"))
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_cake(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            bail!("Failed to check limit for {}! {:?}", iface_name, res);
        }

        let stdout = &String::from_utf8(result.stdout)?;
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
            warn!("No support for the cake qdisc is detected, falling back to fq_codel");
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

        // we need 1kbyte of burst cache per mbit of bandwidth to actually keep things
        // moving
        let burst = bw * 1000 as u32;
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
                &format!("{}", burst),
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
        ip: &Ipv4Addr,
    ) -> Result<(), Error> {
        let class_id = self.get_class_id(ip);
        let modifier;
        if self.has_class(ip, iface_name)? {
            modifier = "change";
        } else {
            modifier = "add";
        }

        let output = self.run_command(
            "tc",
            &[
                "class",
                modifier,
                "dev",
                iface_name,
                "parent",
                "1:",
                "classid",
                &format!("1:{}", class_id),
                "htb",
                "rate",
                &format!("{}kbit", min_bw),
                "ceil",
                &format!("{}kbit", max_bw),
                // 50 packets as mtu plus 14 bytes
                "burst",
                "70K",
                "quantum",
                "1354",
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
        format!(
            "{}{}{}{}",
            ip.octets()[3],
            ip.octets()[2],
            ip.octets()[1],
            ip.octets()[0]
        )
        .parse::<u32>()
        .unwrap()
            % 9999 //9999 is the maximum flow id value allowed
    }

    /// Filters traffic from a given ipv4 address into the class that we are using
    /// to shape that traffic on the exit side, uses the last two octets of the ip
    /// to generate a class id.
    /// TODO when ipv6 exit support is added this will need to be revisited
    pub fn create_flow_by_ip(&self, iface_name: &str, ip: &Ipv4Addr) -> Result<(), Error> {
        let class_id = self.get_class_id(ip);
        if let Ok(true) = self.has_flow_by_ip(iface_name, ip) {
            trace!("Prevented the creation of a duplicate flow by ip!");
            return Ok(());
        }
        trace!("Creating new flow by ip");

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
                "u32",
                "match",
                "ip",
                "dst",
                &format!("{}/32", ip.to_string()),
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

    /// Determines if a given interface already has a flow by a given ip
    pub fn has_flow_by_ip(&self, iface_name: &str, ip: &Ipv4Addr) -> Result<bool, Error> {
        let traffic_class = self.get_class_id(ip);
        let output = self.run_command("tc", &["filter", "show", "dev", iface_name])?;
        trace!("Got {:?} from `tc filter show`", output);

        lazy_static! {
            // this regex will become invalid if you change the parent flow in create flow by ip! see the 1:
            static ref RE: Regex =
                Regex::new(r"flowid 1:([0-9]+)?").expect("Unable to compile regular expression");
        }

        let cap_str = String::from_utf8(output.stdout)?;
        let _err = String::from_utf8(output.stderr)?;
        let cap = RE.captures(&cap_str);
        for line in cap {
            let c: u32 = line[1].parse()?;
            if c == traffic_class {
                return Ok(true);
            }
        }
        Ok(false)
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

#[test]
fn test_has_flow_by_ip_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "tc");
                assert_eq!(args, &["filter", "show", "dev", "wg_exit"]);

                Ok(Output {
                    stdout: b"
filter parent 1: protocol ip pref 48960 u32 
filter parent 1: protocol ip pref 48960 u32 fh 8c0: ht divisor 1 
filter parent 1: protocol ip pref 48960 u32 fh 8c0::800 order 2048 key ht 8c0 bkt 0 flowid 1:5290 not_in_hw"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => unimplemented!("called too many times"),
        }
    }));

    assert_eq!(KI.get_class_id(&"172.168.1.17".parse().unwrap()), 5290);

    assert!(KI
        .has_flow_by_ip("wg_exit", &"172.168.1.17".parse().unwrap())
        .unwrap());
}

#[test]
fn test_does_not_have_flow_by_ip_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "tc");
                assert_eq!(args, &["filter", "show", "dev", "wg_exit"]);

                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => unimplemented!("called too many times"),
        }
    }));

    assert!(!KI
        .has_flow_by_ip("wg_exit", &"172.168.1.17".parse().unwrap())
        .unwrap());
}
