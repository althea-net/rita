use super::{Error, KernelInterface};

use std::net::{IpAddr};
use std::str::FromStr;
use std::collections::HashMap;

use eui48::MacAddress;
use regex::Regex;

#[derive(Debug)]
pub enum FilterTarget{
    Input,
    Output,
    ForwardInput,
    ForwardOutput
}

impl FilterTarget {
    pub fn interface(&self) -> &str {
        match self {
            &FilterTarget::Input | &FilterTarget::ForwardInput => "-i",
            &FilterTarget::Output | &FilterTarget::ForwardOutput => "-o",
        }
    }

    pub fn table(&self) -> &str {
        match self {
            &FilterTarget::Input => "INPUT",
            &FilterTarget::Output  => "OUTPUT",
            &FilterTarget::ForwardOutput | &FilterTarget::ForwardInput => "FORWARD"
        }
    }

    pub fn regex(&self) -> Regex {
        match self {
            &FilterTarget::Input  | &FilterTarget::ForwardInput => Regex::new(r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+([a-zA-Z0-9]+)\s+\*\s+[a-f0-9:/]+\s+([a-f0-9:/]+)").unwrap(),
            &FilterTarget::Output | &FilterTarget::ForwardOutput => Regex::new(r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+\*\s+([a-zA-Z0-9]+)\s+[a-f0-9:/]+\s+([a-f0-9:/]+)").unwrap(),
        }
    }
}

impl KernelInterface {
    pub fn start_counter(
        &self,
        neighbor_if: String,
        destination: IpAddr,
        target: &FilterTarget,
        existing: &HashMap<(IpAddr, String), u64>
    ) -> Result<(), Error> {
        if !existing.contains_key(&(destination.clone(), neighbor_if.clone())) {
            self.run_command(
                "ip6tables",
                &[
                    "-w",
                    "-A",
                    target.table(),
                    target.interface(),
                    &format!("{}", neighbor_if),
                    "-d",
                    &format!("{}", destination),
                ],
            )?;
        } else {
            trace!("rule exists");
        }
        Ok(())
    }

    pub fn read_counters(&self, zero: bool, target: &FilterTarget) -> Result<HashMap<(IpAddr, String), u64>, Error> {
        let output = if zero {
            self.run_command("ip6tables", &["-L", target.table(), "-Z", "-x", "-n", "-v", "-w"])?
        } else {
            self.run_command("ip6tables", &["-L", target.table(), "-x", "-n", "-v", "-w"])?
        };
        let mut map = HashMap::new();

        let re = target.regex();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            map.insert((IpAddr::from_str(&caps[4])?, String::from(&caps[3])), caps[2].parse::<u64>()?);
        }
        trace!("Read {:?} counters {:?}", target, &map);
        Ok(map)
    }

    pub fn read_fwd_counters(&self, zero: bool) -> Result<(HashMap<(IpAddr, String), u64>, HashMap<(IpAddr, String), u64>), Error> {
        let output = if zero {
            self.run_command("ip6tables", &["-L", "FORWARD", "-Z", "-x", "-n", "-v", "-w"])?
        } else {
            self.run_command("ip6tables", &["-L", "FORWARD", "-x", "-n", "-v", "-w"])?
        };
        let mut in_map = HashMap::new();
        let mut out_map = HashMap::new();

        let stdout = String::from_utf8(output.stdout)?;

        let re = FilterTarget::Input.regex();
        for caps in re.captures_iter(&stdout) {
            in_map.insert((IpAddr::from_str(&caps[4])?, String::from(&caps[3])), caps[2].parse::<u64>()?);
        }

        let re = FilterTarget::Output.regex();
        for caps in re.captures_iter(&stdout) {
            out_map.insert((IpAddr::from_str(&caps[4])?, String::from(&caps[3])), caps[2].parse::<u64>()?);
        }
        trace!("Read fwd counters {:?}", (&in_map, &out_map));
        Ok((in_map, out_map))
    }
}
