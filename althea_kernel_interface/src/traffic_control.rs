//! This module performs traffic control commands for both the exit and rita common
//! exit and common traffic control are fundamentally different because the exit is limiting
//! clients on the single exit tunnel, requiring classification of traffic from specific ip's
//! Rita common in contrast is a simple limitation of the neighbors tunnel, which does not do
//! any classful categorization. As a result one uses tbf and the other uses the clsssful htb

use ipnetwork::IpNetwork;

use crate::KernelInterface;
use crate::KernelInterfaceError as Error;
use std::collections::HashSet;
use std::net::Ipv4Addr;

impl dyn KernelInterface {
    /// Determines if the provided interface has a configured qdisc
    pub fn has_qdisc(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to check qdisc for {iface_name}! {res:?}"
            )));
        }

        let stdout = &String::from_utf8(result.stdout)?;

        trace!("has_qdisc: {} {}", stdout, !stdout.contains("noqueue"));
        Ok(!stdout.contains("noqueue"))
    }

    /// Determines if the provided flow is assigned
    pub fn has_flow(&self, ip: Ipv4Addr, iface_name: &str) -> Result<bool, Error> {
        let class_id = self.get_class_id(ip);
        let result = self.run_command("tc", &["filter", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to check filter for {class_id}! {res:?}"
            )));
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok(stdout.contains(&format!("1:{class_id}")))
    }

    /// Gets the full flows list to pass to bulk functions
    pub fn get_flows(&self, iface_name: &str) -> Result<String, Error> {
        let result = self.run_command("tc", &["filter", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to get flows {res:?}"
            )));
        }
        Ok(String::from_utf8(result.stdout)?)
    }

    /// A version of the flows check designed to be run from the raw input, more efficient
    /// in the exit setup loop than running the same command several hundred times
    pub fn has_flow_bulk(&self, ip: Ipv4Addr, tc_out: &str) -> bool {
        let class_id = self.get_class_id(ip);
        tc_out.contains(&format!("1:{class_id}"))
    }

    /// This function is the ipv6 version of has_flow_bulk, but is different in how its implemented. Since we simply cant
    /// check for a handle to verify an ipv6 handle, we use a datastore to store a mapping for (interface, class_id)
    pub fn has_flow_bulk_ipv6(
        &self,
        ipv4: Ipv4Addr,
        iface: &str,
        ipv6_filter_handles: &mut HashSet<(String, u32)>,
    ) -> bool {
        let class_id = self.get_class_id(ipv4);
        if ipv6_filter_handles.contains(&(iface.to_string(), class_id)) {
            return true;
        }
        false
    }

    /// Determines if the provided flow is assigned
    pub fn has_class(&self, ip: Ipv4Addr, iface_name: &str) -> Result<bool, Error> {
        let class_id = self.get_class_id(ip);
        let result = self.run_command("tc", &["class", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to check filter for {class_id}! {res:?}"
            )));
        }

        let stdout = &String::from_utf8(result.stdout)?;
        for line in stdout.lines() {
            let split = line.split_ascii_whitespace();
            for item in split {
                if item == &format!("1:{class_id}") {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_limit(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to check limit for {iface_name}! {res:?}"
            )));
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok((stdout.contains("htb") || stdout.contains("tbf"))
            && !stdout.contains("codel")
            && !stdout.contains("cake")
            && !stdout.contains("noqueue"))
    }

    /// Determines if the provided interface has a configured qdisc
    pub fn has_cake(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", "dev", iface_name])?;

        if !result.status.success() {
            let res = String::from_utf8(result.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to check limit for {iface_name}! {res:?}"
            )));
        }

        let stdout = &String::from_utf8(result.stdout)?;
        Ok((stdout.contains("codel") || stdout.contains("cake"))
            && !stdout.contains("tbf")
            && !stdout.contains("noqueue")
            && !stdout.contains("htb"))
    }

    /// This sets up latency protecting flow control, either cake on openwrt
    /// or fq_codel on older devices/kernels, the Cake configuration sets several advanced parameters
    /// that are not reflected if we fall back to codel
    pub fn set_codel_shaping(&self, iface_name: &str, speed: Option<usize>) -> Result<(), Error> {
        let operator = if self.has_qdisc(iface_name)? {
            "change"
        } else {
            "add"
        };
        let mut cake_args = vec![
            "qdisc", operator, "dev", iface_name, "root", "handle", "1:", "cake",
        ];
        // declared here but used only in the match to provide a longer lifetime
        let mbit;

        match speed {
            Some(val) => {
                mbit = format!("{val}mbit");
                cake_args.extend(["bandwidth", &mbit])
            }
            None => cake_args.extend(["unlimited"]),
        }

        // cake arguments for per hop tunnels only
        cake_args.extend([
            // we want to use the 'internet' parameter here because the total rtt
            // of the path from endpoint to endpoint is what this value cares about
            // not neighbor to neighbor
            "internet",
            // diffserv4 allocates 50% of the connection to video streams and
            // generally recognizes more traffic classes than the default diffserv3
            // there's some debate by cake maintainers internally if this is a good idea
            "diffserv4",
        ]);

        let output = self.run_command("tc", &cake_args)?;

        if !output.status.success() {
            trace!(
                "No support for the Cake qdisc is detected, falling back to fq_codel. Error: {}",
                String::from_utf8(output.stderr)?
            );
            trace!("Command was tc {}", crate::print_str_array(&cake_args));
            warn!("sch_cake is strongly recommended, you should install it");
            let output = self.run_command(
                "tc",
                &[
                    "qdisc", operator, "dev", iface_name, "root", "handle", "1:", "fq_codel",
                    "target", "100ms",
                ],
            )?;

            if !output.status.success() {
                let res = String::from_utf8(output.stderr)?;
                error!("Cake and fallback fq_codel have both failed!");
                return Err(Error::TrafficControlError(format!(
                    "Failed to create new qdisc limit! {res:?}"
                )));
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
        let burst = bw * 1000u32;
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
                &format!("{latency}ms"),
                "burst",
                &format!("{burst}"),
                "rate",
                &format!("{bw}kbit"),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            Err(Error::TrafficControlError(format!(
                "Failed to create new qdisc limit! {res:?}"
            )))
        }
    }

    /// Creates the root limit on the wg_exit tunnel for the exit, under which all other classes
    /// operate
    pub fn create_root_classful_limit(&self, iface_name: &str) -> Result<(), Error> {
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
                "htb",
                "default",
                "0",
                "r2q",
                "1",
                "direct_qlen",
                "1000000",
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            Err(Error::TrafficControlError(format!(
                "Failed to create new qdisc limit! {res:?}"
            )))
        }
    }

    pub fn delete_class(&self, iface_name: &str, ip: Ipv4Addr) -> Result<(), Error> {
        let class_id = self.get_class_id(ip);
        match self.has_class(ip, iface_name) {
            Ok(has_class) => {
                if has_class {
                    self.run_command(
                        "tc",
                        &[
                            "class",
                            "del",
                            "dev",
                            iface_name,
                            "parent",
                            "1:",
                            "classid",
                            &format!("1:{class_id}"),
                        ],
                    )?;
                }
                Ok(())
            }
            Err(e) => {
                error!(
                    "Unable to find class for ip {:?} on {:?} with {:?}",
                    ip, iface_name, e
                );
                Err(e)
            }
        }
    }

    pub fn set_class_limit(
        &self,
        iface_name: &str,
        min_bw: u32,
        max_bw: u32,
        ip: Ipv4Addr,
    ) -> Result<(), Error> {
        let class_id = self.get_class_id(ip);
        let modifier = if self.has_class(ip, iface_name)? {
            "change"
        } else {
            "add"
        };

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
                &format!("1:{class_id}"),
                "htb",
                "rate",
                &format!("{min_bw}kbit"),
                "ceil",
                &format!("{max_bw}kbit"),
            ],
        )?;

        if !output.status.success() {
            let res = String::from_utf8(output.stderr)?;
            return Err(Error::TrafficControlError(format!(
                "Failed to update qdisc class limit! {res:?}"
            )));
        }

        Ok(())
    }

    /// Generates a unique traffic class id for a exit user, essentially a really dumb hashing function
    pub fn get_class_id(&self, ip: Ipv4Addr) -> u32 {
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

    /// Filters traffic from a given ipv6 address into the class that we are using
    /// to shape that traffic on the exit side, uses the last two octets of the ip
    /// to generate a class id.
    pub fn create_flow_by_ipv6(
        &self,
        iface_name: &str,
        ip_net: IpNetwork,
        ip: Ipv4Addr,
    ) -> Result<(), Error> {
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
                "ipv6",
                "u32",
                "match",
                "ip6",
                "dst",
                &ip_net.to_string(),
                "flowid",
                &format!("1:{class_id}"),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            Err(Error::TrafficControlError(format!(
                "Failed to create limit by ip! {res:?}"
            )))
        }
    }

    /// Filters traffic from a given ipv4 address into the class that we are using
    /// to shape that traffic on the exit side, uses the last two octets of the ip
    /// to generate a class id.
    pub fn create_flow_by_ip(&self, iface_name: &str, ip: Ipv4Addr) -> Result<(), Error> {
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
                "u32",
                "match",
                "ip",
                "dst",
                &format!("{ip}/32"),
                "flowid",
                &format!("1:{class_id}"),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            let res = String::from_utf8(output.stderr)?;
            Err(Error::TrafficControlError(format!(
                "Failed to create limit by ip! {res:?}"
            )))
        }
    }

    /// deletes the interface qdisc
    pub fn delete_qdisc(&self, iface_name: &str) -> Result<(), Error> {
        let output = self.run_command("tc", &["qdisc", "del", "dev", iface_name, "root"])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::TrafficControlError(
                "Failed to delete qdisc limit".to_string(),
            ))
        }
    }
}

#[test]
fn get_id() {
    use crate::KI;
    println!("{}", KI.get_class_id("172.168.4.121".parse().unwrap()));
}
