use super::KernelInterface;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

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

    pub fn direction(&self) -> &str {
        match self {
            &ExitFilterTarget::Input => "src",
            &ExitFilterTarget::Output => "dst",
        }
    }

    pub fn interface(&self) -> &str {
        match self {
            &ExitFilterTarget::Input => "-o",
            &ExitFilterTarget::Output => "-i",
        }
    }
}

fn parse_exit_ipset(input: &str) -> Result<HashMap<IpAddr, u64>, Error> {
    let mut map = HashMap::new();

    // example line `add aa fd00::1 packets 28 bytes 2212`
    let reg = Regex::new(r"(?m)^add \S+ (fd00::[a-f0-9:]+) packets (\d+) bytes (\d+)")?;
    for caps in reg.captures_iter(input) {
        map.insert(
            IpAddr::from_str(&caps[1])?,
            caps[3].parse::<u64>()? + caps[2].parse::<u64>()? * 80,
        );
    }
    Ok(map)
}

#[test]
fn test_parse_exit_ipset() {
    let data = r#"
add asdf fd00::1337:123 packets 123456789 bytes 987654321
add zxcv fd00::b4dc:0d3 packets 123456789 bytes 987654320
"#;
    let result = parse_exit_ipset(data);
    match result {
        Ok(result) => {
            assert_eq!(result.len(), 2);
            println!("result {:?}", result);

            let addr1 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0x1337, 0x0123);
            let value1 = result
                .get(&IpAddr::V6(addr1))
                .expect("Unable to find key 1");
            assert_eq!(value1, &(987654321u64 + 123456789u64 * 80));

            let addr2 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xb4dc, 0x00d3);
            let value2 = result
                .get(&(IpAddr::V6(addr2)))
                .expect("Unable to find key 2");
            assert_eq!(value2, &(987654320u64 + 123456789u64 * 80));
        }
        Err(e) => {
            panic!("Unexpected error {:?}", e);
        }
    }
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
                target.direction(),
                "-j",
                "SET",
                "--add-set",
                target.set_name(),
                target.direction(),
            ],
        )?;
        Ok(())
    }

    pub fn read_exit_server_counters(
        &self,
        target: &ExitFilterTarget,
    ) -> Result<HashMap<IpAddr, u64>, Error> {
        let ipset_result = self.run_command(
            "ipset",
            &[
                "create",
                &format!("tmp_{}", target.set_name()),
                "hash:net",
                "family",
                "inet6",
                "counters",
            ],
        );
        match ipset_result {
            Err(e) => warn!("ipset tmp creation failed with {:?}", e),
            _ => (),
        };

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
