use super::{KernelInterface, KernelManagerError};

use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashMap;

use eui48::MacAddress;
use regex::Regex;

use failure::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum ExitFilterTarget {
    Input,
    Output,
}

impl ExitFilterTarget {
    pub fn table(&self) -> &str {
        match self {
            &ExitFilterTarget::Input => "INPUT",
            &ExitFilterTarget::Output => "OUTPUT",
        }
    }

    pub fn set_name(&self) -> &str {
        match self {
            &ExitFilterTarget::Input => "rita_exit_input",
            &ExitFilterTarget::Output => "rita_exit_output",
        }
    }
}

fn parse_exit_ipset(input: &str) -> Result<HashMap<IpAddr, u64>, Error> {
    let mut map = HashMap::new();

    // example line `add aa fd::1 packets 28 bytes 2212`
    let reg = Regex::new(r"(?m)^add \S+ ([a-f0-9:]+) packets (\d+) bytes (\d+)")?;
    for caps in reg.captures_iter(input) {
        map.insert(IpAddr::from_str(&caps[1])?, caps[3].parse::<u64>()?);
    }
    Ok(map)
}

impl KernelInterface {
    pub fn init_exit_counter(&self, target: &ExitFilterTarget) -> Result<(), Error> {
        self.run_command(
            "ipset",
            &[
                "create",
                target.set_name(),
                "hash:net",
                "family",
                "inet6",
                "counters",
            ],
        )?;
        self.run_command(
            "ip6tables",
            &[
                "-w",
                "-A",
                target.table(),
                "-m",
                "set",
                "!",
                "--match-set",
                target.set_name(),
                "dst",
                "-j",
                "SET",
                "--add-set",
                target.set_name(),
                "dst",
            ],
        )?;
        Ok(())
    }

    pub fn read_exit_counters(
        &self,
        target: &ExitFilterTarget,
    ) -> Result<HashMap<IpAddr, u64>, Error> {
        self.run_command(
            "ipset",
            &[
                "create",
                &format!("tmp_{}", target.set_name()),
                "hash:net",
                "family",
                "inet6",
                "counters",
            ],
        )?;

        self.run_command(
            "ipset",
            &[
                "swap",
                &format!("tmp_{}", target.set_name()),
                target.set_name(),
            ],
        )?;

        let output = self.run_command("ipset", &["save", &format!("tmp_{}", target.set_name())])?;
        let res = parse_exit_ipset(&String::from_utf8(output.stdout)?);
        trace!("ipset parsed into {:?}", res);

        self.run_command("ipset", &["destroy", &format!("tmp_{}", target.set_name())])?;
        res
    }
}
