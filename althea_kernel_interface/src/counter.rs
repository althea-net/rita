use super::{Error, KernelInterface};

use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashMap;

use eui48::MacAddress;
use regex::Regex;

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
            &FilterTarget::Input | &FilterTarget::ForwardInput => "-i",
            &FilterTarget::Output | &FilterTarget::ForwardOutput => "-o",
        }
    }

    pub fn table(&self) -> &str {
        match self {
            &FilterTarget::Input => "INPUT",
            &FilterTarget::Output => "OUTPUT",
            &FilterTarget::ForwardOutput | &FilterTarget::ForwardInput => "FORWARD",
        }
    }

    pub fn regex(&self) -> Regex {
        match self {
            &FilterTarget::Input | &FilterTarget::ForwardInput => Regex::new(
                r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+([a-zA-Z0-9]+)\s+\*\s+[a-f0-9:/]+\s+([a-f0-9:/]+)",
            ).unwrap(),
            &FilterTarget::Output | &FilterTarget::ForwardOutput => Regex::new(
                r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+\*\s+([a-zA-Z0-9]+)\s+[a-f0-9:/]+\s+([a-f0-9:/]+)",
            ).unwrap(),
        }
    }
}

impl KernelInterface {
    pub fn start_counter(
        &self,
        neighbor_if: String,
        destination: IpAddr,
        target: &FilterTarget,
        existing: &HashMap<(IpAddr, String), u64>,
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

    pub fn read_counters(
        &self,
        zero: bool,
        target: &FilterTarget,
    ) -> Result<HashMap<(IpAddr, String), u64>, Error> {
        assert!(
            !(zero
                && (target == &FilterTarget::ForwardInput
                    || target == &FilterTarget::ForwardOutput))
        );
        let output = if zero {
            self.run_command(
                "ip6tables",
                &["-L", target.table(), "-Z", "-x", "-n", "-v", "-w"],
            )?
        } else {
            self.run_command("ip6tables", &["-L", target.table(), "-x", "-n", "-v", "-w"])?
        };
        let mut map = HashMap::new();

        let re = target.regex();
        for caps in re.captures_iter(&String::from_utf8(output.stdout)?) {
            map.insert(
                (IpAddr::from_str(&caps[4])?, String::from(&caps[3])),
                caps[2].parse::<u64>()?,
            );
        }
        trace!("Read {:?} counters {:?}", target, &map);
        Ok(map)
    }

    pub fn read_fwd_counters(
        &self,
        zero: bool,
    ) -> Result<
        (
            HashMap<(IpAddr, String), u64>,
            HashMap<(IpAddr, String), u64>,
        ),
        Error,
    > {
        let output = if zero {
            self.run_command(
                "ip6tables",
                &["-L", "FORWARD", "-Z", "-x", "-n", "-v", "-w"],
            )?
        } else {
            self.run_command("ip6tables", &["-L", "FORWARD", "-x", "-n", "-v", "-w"])?
        };
        let mut in_map = HashMap::new();
        let mut out_map = HashMap::new();

        let stdout = String::from_utf8(output.stdout)?;

        let re = FilterTarget::Input.regex();
        for caps in re.captures_iter(&stdout) {
            in_map.insert(
                (IpAddr::from_str(&caps[4])?, String::from(&caps[3])),
                caps[2].parse::<u64>()?,
            );
        }

        let re = FilterTarget::Output.regex();
        for caps in re.captures_iter(&stdout) {
            out_map.insert(
                (IpAddr::from_str(&caps[4])?, String::from(&caps[3])),
                caps[2].parse::<u64>()?,
            );
        }
        trace!("Read fwd counters {:?}", (&in_map, &out_map));
        Ok((in_map, out_map))
    }
}

#[test]
fn test_start_counter_not_found_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            assert_eq!(program, "ip6tables");
            assert_eq!(args, &["-w", "-A", "INPUT", "-i", "eth0", "-d", "fd::1"]);

            Ok(Output {
                stdout: b"".to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    ki.start_counter(
        "eth0".to_string(),
        "fd::1".parse().unwrap(),
        &FilterTarget::Input,
        &HashMap::new(),
    ).unwrap();
}

#[test]
fn test_start_counter_found_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| panic!("should not execute"))),
    };

    let mut existing = HashMap::new();

    existing.insert(("fd::1".parse().unwrap(), "eth0".to_string()), 0);

    ki.start_counter(
        "eth0".to_string(),
        "fd::1".parse().unwrap(),
        &FilterTarget::Input,
        &existing,
    ).unwrap();
}

#[test]
fn test_read_input_counters_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            assert_eq!(program, "ip6tables");
            assert_eq!(args, &["-L", "INPUT", "-Z", "-x", "-n", "-v", "-w"]);

            Ok(Output {
                stdout: b"Chain INPUT (policy ACCEPT 105 packets, 18842 bytes)
pkts      bytes target     prot opt in     out     source               destination
   6      678            all      wg0    *       ::/0                 fd::1
   0        0            all      wg0    *       ::/0                 fd::2
   0        0            all      wg0    *       ::/0                 fd::3
   0        0            all      wg0    *       ::/0                 fd::4
   0        0            all      wg0    *       ::/0                 fd::6
   0        0            all      wg0    *       ::/0                 fd::7     "
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    let mut out = HashMap::new();

    out.insert(("fd::1".parse().unwrap(), "wg0".to_string()), 678);
    out.insert(("fd::2".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::3".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::4".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::6".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::7".parse().unwrap(), "wg0".to_string()), 0);

    let read = ki.read_counters(true, &FilterTarget::Input).unwrap();

    assert_eq!(read, out)
}

#[test]
fn test_read_output_counters_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            assert_eq!(program, "ip6tables");
            assert_eq!(args, &["-L", "OUTPUT", "-Z", "-x", "-n", "-v", "-w"]);

            Ok(Output {
                stdout: b"Chain OUTPUT (policy ACCEPT 105 packets, 18842 bytes)
pkts      bytes target     prot opt in     out     source               destination
   6      678            all   *   wg0           ::/0                 fd::1
   0        0            all   *   wg0           ::/0                 fd::2
   0        0            all   *   wg0           ::/0                 fd::3
   0        0            all   *   wg0           ::/0                 fd::4
   0        0            all   *   wg0           ::/0                 fd::6
   0        0            all   *   wg0           ::/0                 fd::7     "
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    let mut out = HashMap::new();

    out.insert(("fd::1".parse().unwrap(), "wg0".to_string()), 678);
    out.insert(("fd::2".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::3".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::4".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::6".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::7".parse().unwrap(), "wg0".to_string()), 0);

    let read = ki.read_counters(true, &FilterTarget::Output).unwrap();

    assert_eq!(read, out)
}

#[test]
fn test_read_fwd_counters_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            assert_eq!(program, "ip6tables");
            assert_eq!(args, &["-L", "FORWARD", "-Z", "-x", "-n", "-v", "-w"]);

            Ok(Output {
                stdout: b"Chain FORWARD (policy ACCEPT 105 packets, 18842 bytes)
pkts      bytes target     prot opt in     out     source               destination
   6      678            all   *   wg0           ::/0                 fd::1
   0        0            all   *   wg0           ::/0                 fd::2
   0        0            all   *   wg0           ::/0                 fd::3
   0        0            all   *   wg0           ::/0                 fd::4
   0        0            all   *   wg0           ::/0                 fd::6
   0        0            all   *   wg0           ::/0                 fd::7
   6      678            all       wg0     *     ::/0                 fd::1
   0        0            all       wg0     *     ::/0                 fd::2
   0        0            all       wg0     *     ::/0                 fd::3
   0        0            all       wg0     *     ::/0                 fd::4
   0        0            all       wg0     *     ::/0                 fd::6
   0        0            all       wg0     *     ::/0                 fd::7     "
                    .to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };

    let mut out = HashMap::new();

    out.insert(("fd::1".parse().unwrap(), "wg0".to_string()), 678);
    out.insert(("fd::2".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::3".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::4".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::6".parse().unwrap(), "wg0".to_string()), 0);
    out.insert(("fd::7".parse().unwrap(), "wg0".to_string()), 0);

    let read = ki.read_fwd_counters(true).unwrap();

    assert_eq!(read, (out.clone(), out.clone()))
}
