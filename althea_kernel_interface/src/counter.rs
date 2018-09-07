use super::KernelInterface;

use std::collections::HashMap;
use std::net::IpAddr;
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

#[test]
fn test_filter_target_interface() {
    assert_eq!(FilterTarget::Input.interface(), "src");
    assert_eq!(FilterTarget::ForwardInput.interface(), "src");
    assert_eq!(FilterTarget::Output.interface(), "dst");
    assert_eq!(FilterTarget::ForwardOutput.interface(), "dst");
}

#[test]
fn test_filter_table_set_name() {
    assert_eq!(FilterTarget::Input.set_name(), "rita_input");
    assert_eq!(FilterTarget::Output.set_name(), "rita_output");
    assert_eq!(FilterTarget::ForwardInput.set_name(), "rita_fwd_input");
    assert_eq!(FilterTarget::ForwardOutput.set_name(), "rita_fwd_output");
}

#[test]
fn test_filter_table_table() {
    assert_eq!(FilterTarget::Input.table(), "INPUT");
    assert_eq!(FilterTarget::Output.table(), "OUTPUT");
    assert_eq!(FilterTarget::ForwardOutput.table(), "FORWARD");
    assert_eq!(FilterTarget::ForwardInput.table(), "FORWARD");
}

fn parse_ipset(input: &str) -> Result<HashMap<(IpAddr, String), u64>, Error> {
    lazy_static! {
        static ref RE: Regex = Regex::new(
            r"(?m)^add \S+ ([a-f0-9:]+),(wg\d+) packets (\d+) bytes (\d+)"
        ).expect("Unable to compile regular expression");
    }
    let mut map = HashMap::new();

    // example line `add aa fd00::1,wg0 packets 28 bytes 2212`

    for caps in RE.captures_iter(input) {
        map.insert(
            (IpAddr::from_str(&caps[1])?, String::from(&caps[2])),
            caps[4].parse::<u64>()? + caps[3].parse::<u64>()? * 40,
        );
    }
    Ok(map)
}

#[test]
fn test_parse_ipset() {
    use std::net::Ipv6Addr;
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

#[test]
fn test_init_counter() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    use KI;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ipset");
                assert_eq!(
                    args,
                    vec![
                        "create",
                        "rita_input",
                        "hash:net,iface",
                        "family",
                        "inet6",
                        "counters",
                    ]
                );
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                assert_eq!(program, "ip6tables");
                assert_eq!(
                    args,
                    vec![
                        "-w",
                        "-C",
                        "INPUT",
                        "-m",
                        "set",
                        "!",
                        "--match-set",
                        "rita_input",
                        "dst,src",
                        "-j",
                        "SET",
                        "--add-set",
                        "rita_input",
                        "dst,src",
                    ]
                );
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }

            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));
    KI.init_counter(&FilterTarget::Input)
        .expect("Unable to init counter");
}
#[test]
fn test_read_counters() {
    use std::net::Ipv6Addr;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    use KI;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "ipset");
                assert_eq!(
                    args,
                    vec![
                        "create",
                        "tmp_rita_input",
                        "hash:net,iface",
                        "family",
                        "inet6",
                        "counters",
                    ]
                );
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            2 => {
                assert_eq!(program, "ipset");
                assert_eq!(args, vec!["swap", "tmp_rita_input", "rita_input"]);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            3 => {
                assert_eq!(program, "ipset");
                assert_eq!(args, vec!["save", "tmp_rita_input"]);
                Ok(Output {
                    stdout: b"
add xxx fd00::dead:beef,wg42 packets 111 bytes 222
"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            4 => {
                assert_eq!(program, "ipset");
                assert_eq!(args, vec!["destroy", "tmp_rita_input"]);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));
    let result = KI
        .read_counters(&FilterTarget::Input)
        .expect("Unable to read values");
    assert_eq!(result.len(), 1);

    let value = result
        .get(&(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xdead, 0xbeef)),
            "wg42".into(),
        ))
        .expect("Unable to find key");
    assert_eq!(value, &(222u64 + 111u64 * 40));
}
