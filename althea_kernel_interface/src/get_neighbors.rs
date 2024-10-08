use crate::{run_command, KernelInterfaceError as Error};
use regex::Regex;
use std::net::IpAddr;
use std::process::Output;
use std::str::FromStr;

/// Internal testing function to parse the output of `ip neighbor` on Linux.
fn parse_neighbors_internal(output: Output) -> Result<Vec<(IpAddr, String)>, Error> {
    let mut vec = Vec::new();

    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"(\S*).*dev (\S*).*lladdr (\S*).*(REACHABLE|STALE|DELAY)")
                .expect("Unable to compile regular expression");
    }
    for caps in RE.captures_iter(&String::from_utf8(output.stdout)?) {
        trace!("Regex captured {:?}", caps);

        vec.push((IpAddr::from_str(&caps[1])?, caps[2].to_string()));
    }
    trace!("Got neighbors {:?}", vec);
    Ok(vec)
}

/// Returns a vector of neighbors reachable over layer 2, giving IP address of each.
/// Implemented with `ip neighbor` on Linux.
pub fn get_neighbors() -> Result<Vec<(IpAddr, String)>, Error> {
    let output = run_command("ip", &["neigh"])?;
    trace!("Got {:?} from `ip neighbor`", output);
    parse_neighbors_internal(output)
}

#[test]
fn test_get_neighbors_linux() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let output = Output {
        stdout: b"10.0.2.2 dev eth0 lladdr 00:00:00:aa:00:03 STALE
10.0.0.2 dev eth0  FAILED
10.0.1.2 dev eth0 lladdr 00:00:00:aa:00:05 REACHABLE
2001::2 dev eth0 lladdr 00:00:00:aa:00:56 REACHABLE
fe80::7459:8eff:fe98:81 dev eth0 lladdr 76:59:8e:98:00:81 STALE
fe80::433:25ff:fe8c:e1ea dev eth0 lladdr 1a:32:06:78:05:0a STALE
2001::2 dev eth0  FAILED"
            .to_vec(),
        stderr: b"".to_vec(),
        status: ExitStatus::from_raw(0),
    };

    let addresses = parse_neighbors_internal(output).unwrap();

    //assert_eq!(format!("{}", addresses[0].0), "00-00-00-aa-00-03");
    assert_eq!(addresses[0].0.to_string(), "10.0.2.2");
    assert_eq!(addresses[0].1.to_string(), "eth0");

    //assert_eq!(format!("{}", addresses[1].0), "00-00-00-aa-00-05");
    assert_eq!(addresses[1].0.to_string(), "10.0.1.2");
    assert_eq!(addresses[1].1.to_string(), "eth0");

    //assert_eq!(format!("{}", addresses[2].0), "00-00-00-aa-00-56");
    assert_eq!(addresses[2].0.to_string(), "2001::2");
    assert_eq!(addresses[2].1.to_string(), "eth0");
}
