use super::KernelInterface;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use regex::Regex;

use failure::Error;

#[derive(Debug, Eq, PartialEq)]
pub enum FilterTarget {
    Input,
    Output,
    ForwardInput,
    ForwardOutput,
}

impl FilterTarget {
    pub fn interface(&self) -> &str {
        match self {
            &FilterTarget::Input | &FilterTarget::ForwardInput => "src",
            &FilterTarget::Output | &FilterTarget::ForwardOutput => "dst",
        }
    }

    pub fn set_name(&self) -> &str {
        match self {
            &FilterTarget::Input => "rita_input",
            &FilterTarget::Output => "rita_output",
            &FilterTarget::ForwardInput => "rita_fwd_input",
            &FilterTarget::ForwardOutput => "rita_fwd_output",
        }
    }

    pub fn table(&self) -> &str {
        match self {
            &FilterTarget::Input => "INPUT",
            &FilterTarget::Output => "OUTPUT",
            &FilterTarget::ForwardOutput | &FilterTarget::ForwardInput => "FORWARD",
        }
    }
}

fn parse_ipset(input: &str) -> Result<HashMap<(IpAddr, String), u64>, Error> {
    let mut map = HashMap::new();

    // example line `add aa fd00::1,wg0 packets 28 bytes 2212`
    let reg = Regex::new(r"(?m)^add \S+ ([a-f0-9:]+),(wg\d+) packets (\d+) bytes (\d+)")?;
    for caps in reg.captures_iter(input) {
        map.insert(
            (IpAddr::from_str(&caps[1])?, String::from(&caps[2])),
            caps[4].parse::<u64>()? + caps[3].parse::<u64>()? * 40,
        );
    }
    Ok(map)
}

#[test]
fn test_parse_ipset() {
    let data = r#"
add asdf 1234:5678:9801:2345:6789:0123:4567:8901,wg42 packets 123456789 bytes 987654321
add zxcv 1234:5678:9801:2345:6789:0123:4567:8902,wg0 packets 123456789 bytes 987654320
"#;
    let result = parse_ipset(data);
    match result {
        Ok(result) => {
            let addr1 = Ipv6Addr::new(
                0x1234, 0x5678, 0x9801, 0x2345, 0x6789, 0x0123, 0x4567, 0x8901,
            );
            assert_eq!(result.len(), 2);
            let value1 = result
                .get(&(IpAddr::V6(addr1), "wg42".into()))
                .expect("Unable to find key");
            assert_eq!(value1, &(987654321u64 + 123456789u64 * 40));

            let addr2 = Ipv6Addr::new(
                0x1234, 0x5678, 0x9801, 0x2345, 0x6789, 0x0123, 0x4567, 0x8902,
            );
            let value2 = result
                .get(&(IpAddr::V6(addr2), "wg0".into()))
                .expect("Unable to find key");
            assert_eq!(value2, &(987654320u64 + 123456789u64 * 40));
        }
        Err(e) => {
            panic!("Unexpected error {:?}", e);
        }
    }
}

impl KernelInterface {
    pub fn init_counter(&self, target: &FilterTarget) -> Result<(), Error> {
        self.run_command(
            "ipset",
            &[
                "create",
                target.set_name(),
                "hash:net,iface",
                "family",
                "inet6",
                "counters",
            ],
        )?;
        self.add_iptables_rule(
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
                &format!("dst,{}", target.interface()),
                "-j",
                "SET",
                "--add-set",
                target.set_name(),
                &format!("dst,{}", target.interface()),
            ],
        )?;
        Ok(())
    }

    pub fn read_counters(
        &self,
        target: &FilterTarget,
    ) -> Result<HashMap<(IpAddr, String), u64>, Error> {
        self.run_command(
            "ipset",
            &[
                "create",
                &format!("tmp_{}", target.set_name()),
                "hash:net,iface",
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
        let res = parse_ipset(&String::from_utf8(output.stdout)?);
        trace!("ipset parsed into {:?}", res);

        self.run_command("ipset", &["destroy", &format!("tmp_{}", target.set_name())])?;
        res
    }
}
