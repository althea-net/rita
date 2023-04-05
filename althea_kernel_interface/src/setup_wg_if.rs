use crate::{KernelInterface, KernelInterfaceError, KernelInterfaceError as Error};
use althea_types::WgKey;
use std::str::from_utf8;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

impl dyn KernelInterface {
    pub fn get_peers(&self, iface_name: &str) -> Result<Vec<WgKey>, Error> {
        let output = self.run_command("wg", &["show", iface_name, "peers"])?;

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
    /// then calls iproute2 to set up a new interface.
    pub fn setup_wg_if(&self) -> Result<String, Error> {
        // this is the maximum allowed retries for when an interface is claimed to have already existed
        // since we only setup interfaces once this can only happen if we have lost an interface or if
        // the kernel is acting strange, either way it's better just to skip that interface and wait
        // on a Rita restart to clean it up some day.
        const MAX_RETRY: u8 = 5;

        //call "ip links" to get a list of currently set up links
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;
        let mut if_num = 0;
        //loop through the output of "ip links" until we find a wg suffix that isn't taken (e.g. "wg3")
        while links.contains(format!("wg{if_num}").as_str()) {
            if_num += 1;
        }

        let mut count = 0;
        let mut interface = format!("wg{if_num}");
        let mut res = self.setup_wg_if_named(&interface);
        while let Err(KernelInterfaceError::WgExistsError) = res {
            if_num += 1;
            interface = format!("wg{if_num}");
            res = self.setup_wg_if_named(&interface);
            count += 1;
            if count > MAX_RETRY {
                break;
            }
        }

        res?;
        Ok(interface)
    }

    /// calls iproute2 to set up a new interface with a given name.
    pub fn setup_wg_if_named(&self, name: &str) -> Result<(), KernelInterfaceError> {
        let output = self.run_command("ip", &["link", "add", name, "type", "wireguard"])?;
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

    /// Returns the number of clients that are active on the wg_exit tunnel
    pub fn get_wg_exit_clients_online(&self, interface: &str) -> Result<u32, Error> {
        let output = self.run_command("wg", &["show", interface, "latest-handshakes"])?;
        let mut num: u32 = 0;
        let out = String::from_utf8(output.stdout)?;
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

    /// Returns the last handshake time of every client on this tunnel.
    pub fn get_last_handshake_time(&self, ifname: &str) -> Result<Vec<(WgKey, SystemTime)>, Error> {
        let output = self.run_command("wg", &["show", ifname, "latest-handshakes"])?;
        let out = String::from_utf8(output.stdout)?;
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

    /// Returns the last handshake time of every ACTIVE client on this tunnel.
    /// An active handshake mean a wireguard tunnel that has a latest handshake value
    /// When running wg show wg_exit latest-handshake, a entries with timestamp 0 are inactive
    pub fn get_last_active_handshake_time(
        &self,
        ifname: &str,
    ) -> Result<Vec<(WgKey, SystemTime)>, Error> {
        let output = self.run_command("wg", &["show", ifname, "latest-handshakes"])?;
        let out = String::from_utf8(output.stdout)?;
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
            if timestamp == 0 {
                continue;
            }
            let d = UNIX_EPOCH + Duration::from_secs(timestamp);
            timestamps.push((wg_key, d))
        }
        Ok(timestamps)
    }
}

#[test]
fn test_durations() {
    let d = UNIX_EPOCH + Duration::from_secs(5);
    let d2 = UNIX_EPOCH + Duration::from_secs(10);

    println!("d: {d:?}, d2: {d2:?}");
}

#[test]
fn test_setup_wg_if_linux() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    let link_args = &["link"];
    let link_add = &["link", "add", "wg1", "type", "wireguard"];
    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "ip");
        counter += 1;

        match counter {
            1 => {
                assert_eq!(args, link_args);
                Ok(Output{
                        stdout: b"82: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noop state DOWN mode DEFAULT group default qlen 1000".to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            2 => {
                assert_eq!(args, link_add);
                Ok(Output {
                    stdout: b"".to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("command called too many times"),
        }
    }));

    KI.setup_wg_if().unwrap();
}

#[test]
fn test_get_wg_exit_clients_online() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    let link_args = &["show", "wg_exit", "latest-handshakes"];
    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "wg");
        counter += 1;

        match counter {
            1 => {
                assert_eq!(args, link_args);
                Ok(Output{
                        stdout: format!("88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs=	{}\nW1BwNSC9ulTutCg53KIlo+z2ihkXao3sXHaBBpaCXEw=	1536936247\n9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ=	0", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()).as_bytes().to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            _ => panic!("command called too many times"),
        }
    }));

    assert_eq!(KI.get_wg_exit_clients_online("wg_exit").unwrap(), 1);
}

#[test]
fn test_get_last_handshake_time() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    let mut counter = 0;

    let link_args = &["show", "wg1", "latest-handshakes"];
    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "wg");
        counter += 1;

        match counter {
            1 => {
                assert_eq!(args, link_args);
                Ok(Output{
                        stdout: format!("88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs=	{}\nbGkj7Z6bX1593G0pExfzxocWKhS3Un9uifIhZP9c5iM=	1536936247\n9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ=	0", SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()).as_bytes().to_vec(),
                        stderr: b"".to_vec(),
                        status: ExitStatus::from_raw(0),
                    })
            }
            _ => panic!("command called too many times"),
        }
    }));

    let wgkey1: WgKey = "88gbNAZx7NoNK9hatYuDkeZOjQ8EBmJ8VBpcFhXPqHs="
        .parse()
        .unwrap();
    let wgkey2: WgKey = "bGkj7Z6bX1593G0pExfzxocWKhS3Un9uifIhZP9c5iM="
        .parse()
        .unwrap();
    let wgkey3: WgKey = "9jRr6euMHu3tBIsZyqxUmjbuKVVFZCBOYApOR2pLNkQ="
        .parse()
        .unwrap();

    let res = KI
        .get_last_handshake_time("wg1")
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
