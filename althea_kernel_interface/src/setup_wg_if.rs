use crate::interface_tools::get_interfaces;
use crate::{run_command, KernelInterfaceError, KernelInterfaceError as Error};
use althea_types::WgKey;
use std::str::from_utf8;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The maximum allowed time for a handshake to be considered active (5 days)
pub const WG_INACTIVE_THRESHOLD: Duration = if cfg!(feature = "integration_test") {
    Duration::new(140, 0)
} else {
    Duration::from_secs(432_000)
};

pub fn get_peers(iface_name: &str) -> Result<Vec<WgKey>, Error> {
    let output = run_command("wg", &["show", iface_name, "peers"])?;

    let output = from_utf8(&output.stdout)?;

    let mut peers = Vec::new();

    for l in output.lines() {
        let parsed = l.parse();
        if let Ok(val) = parsed {
            peers.push(val);
        } else {
            warn!("Could not parse peer! {}", l);
        }
    }

    Ok(peers)
}

/// checks the existing interfaces to find an interface name that isn't in use.
/// then calls iproute2 to set up a new interface with that name
pub fn create_blank_wg_numbered_wg_interface() -> Result<String, Error> {
    // this is the maximum allowed retries for when an interface is claimed to have already existed
    // since we only setup interfaces once this can only happen if we have lost an interface or if
    // the kernel is acting strange, either way it's better just to skip that interface and wait
    // on a Rita restart to clean it up some day.
    const MAX_RETRY: u8 = 5;

    //call "ip links" to get a list of currently set up links
    let links = get_interfaces()?;
    let mut if_num = 0;
    //loop through the output of "ip links" until we find a wg suffix that isn't taken (e.g. "wg3")
    while links.contains(&format!("wg{if_num}")) {
        if_num += 1;
    }

    let mut count = 0;
    let mut interface = format!("wg{if_num}");
    let mut res = create_blank_wg_interface(&interface);
    while let Err(KernelInterfaceError::WgExistsError) = res {
        if_num += 1;
        interface = format!("wg{if_num}");
        res = create_blank_wg_interface(&interface);
        count += 1;
        if count > MAX_RETRY {
            break;
        }
    }

    res?;
    Ok(interface)
}

/// calls iproute2 to set up a new interface with a given name.
pub fn create_blank_wg_interface(name: &str) -> Result<(), KernelInterfaceError> {
    let output = run_command("ip", &["link", "add", name, "type", "wireguard"])?;
    let stderr = String::from_utf8(output.stderr)?;
    if !stderr.is_empty() {
        if stderr.contains("exists") {
            return Err(KernelInterfaceError::WgExistsError);
        } else {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {stderr}"
            )));
        }
    }

    Ok(())
}

/// internal helper function for get_wg_exit_clients_online
fn get_wg_exit_clients_online_internal(out: String) -> Result<u32, Error> {
    let mut num: u32 = 0;
    for line in out.lines() {
        let content: Vec<&str> = line.split('\t').collect();
        let mut itr = content.iter();
        itr.next();
        let timestamp = itr.next().ok_or_else(|| {
            KernelInterfaceError::RuntimeError("Option did not contain a value.".to_string())
        })?;
        let d = UNIX_EPOCH + Duration::from_secs(timestamp.parse()?);

        if SystemTime::now().duration_since(d)? < Duration::new(600, 0) {
            num += 1;
        }
    }
    Ok(num)
}

/// Returns the number of clients that are active(<10m since last handshake) on the wg_exit tunnel
pub fn get_wg_exit_clients_online(interface: &str) -> Result<u32, Error> {
    let output = run_command("wg", &["show", interface, "latest-handshakes"])?;
    let out = String::from_utf8(output.stdout)?;
    get_wg_exit_clients_online_internal(out)
}

/// For all wg clients on an interface, sort them into online and offline clients based on the last handshake time.
/// returns (online, offline) clients
pub fn get_wg_clients_online_offline(ifname: &str) -> Result<(Vec<WgKey>, Vec<WgKey>), Error> {
    let last_handshakes = get_last_handshake_time(ifname)?;
    let mut online: Vec<WgKey> = Vec::new();
    let mut offline: Vec<WgKey> = Vec::new();
    for (key, timestamp) in last_handshakes {
        // if timestamp is 0 we have just set up the tunnel, do not include it in the list
        error!("timestamp: {:?}", timestamp);
        if timestamp == UNIX_EPOCH {
            continue;
        }
        if SystemTime::now().duration_since(timestamp)? > WG_INACTIVE_THRESHOLD {
            offline.push(key);
        } else {
            online.push(key);
        }
    }
    Ok((online, offline))
}

/// Internal helper function for ci testing get_last_handshake_time
fn get_last_active_handshake_time_internal(out: String) -> Result<Vec<(WgKey, SystemTime)>, Error> {
    let mut timestamps = Vec::new();
    for line in out.lines() {
        let content: Vec<&str> = line.split('\t').collect();
        let mut itr = content.iter();
        let wg_key: WgKey = match itr.next() {
            Some(val) => val.parse()?,
            None => {
                return Err(KernelInterfaceError::RuntimeError(
                    "Invalid line!".to_string(),
                ))
            }
        };
        let timestamp = match itr.next() {
            Some(val) => val.parse()?,
            None => {
                return Err(KernelInterfaceError::RuntimeError(
                    "Invalid line!".to_string(),
                ))
            }
        };
        let d = UNIX_EPOCH + Duration::from_secs(timestamp);
        timestamps.push((wg_key, d))
    }
    Ok(timestamps)
}
// here

/// Returns the last handshake time of every client on this tunnel.
pub fn get_last_handshake_time(ifname: &str) -> Result<Vec<(WgKey, SystemTime)>, Error> {
    let output = run_command("wg", &["show", ifname, "latest-handshakes"])?;
    let out = String::from_utf8(output.stdout)?;
    get_last_active_handshake_time_internal(out)
}

/// Returns the last handshake time of every ACTIVE client on this tunnel.
/// An active handshake mean a wireguard tunnel that has a latest handshake value
/// When running wg show wg_exit latest-handshake, a entries with timestamp 0 are inactive
pub fn get_last_active_handshake_time(ifname: &str) -> Result<Vec<(WgKey, SystemTime)>, Error> {
    let timestamps = get_last_handshake_time(ifname)?;
    let timestamps = timestamps
        .into_iter()
        .filter(|(_, time)| *time != UNIX_EPOCH)
        .collect();
    Ok(timestamps)
}

/// Gets a list of all active wireguard interfaces on this device
pub fn get_list_of_wireguard_interfaces() -> Result<Vec<String>, Error> {
    let output = run_command("wg", &["show", "interfaces"])?;
    let out = String::from_utf8(output.stdout)?;
    let mut interfaces = Vec::new();
    for interface in out.split_ascii_whitespace() {
        interfaces.push(interface.to_string())
    }
    Ok(interfaces)
}

#[test]
fn test_durations() {
    let d = UNIX_EPOCH + Duration::from_secs(5);
    let d2 = UNIX_EPOCH + Duration::from_secs(10);

    println!("d: {d:?}, d2: {d2:?}");
}

#[test]
fn test_get_wg_exit_clients_online() {
    let stdout = format!("88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs=	{}\nW1BwNSC9ulTutCg53KIlo+z2ihkXao3sXHaBBpaCXEw=	1536936247\n9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ=	0", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

    assert_eq!(get_wg_exit_clients_online_internal(stdout).unwrap(), 1);
}

#[test]
fn test_get_last_handshake_time() {
    let wgkey1: WgKey = "88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs="
        .parse()
        .unwrap();
    let wgkey2: WgKey = "bGkj7Z6bX1593G0pExfzxocWKhS3Un9uifIhZP9c5iM="
        .parse()
        .unwrap();
    let wgkey3: WgKey = "9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ="
        .parse()
        .unwrap();
    let stdout = format!("88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs=	{}\nbGkj7Z6bX1593G0pExfzxocWKhS3Un9uifIhZP9c5iM=	1536936247\n9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ=	0", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

    let res = get_last_active_handshake_time_internal(stdout.to_string())
        .expect("Failed to run get_last_handshake_time!");
    assert!(res.contains(&(wgkey3, SystemTime::UNIX_EPOCH)));
    assert!(res.contains(&(
        wgkey2,
        (SystemTime::UNIX_EPOCH + Duration::from_secs(1_536_936_247))
    )));
    for (key, time) in res {
        if key == wgkey1 {
            // system time is very high resolution but within a second is fine
            assert!(time > SystemTime::now() - Duration::from_secs(1));
        }
    }
}
