use super::{KernelInterface, KernelInterfaceError};
use althea_types::WgKey;
use failure::err_msg;
use std::str::from_utf8;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use failure::Error;

impl KernelInterface {
    pub fn get_peers(&self, iface_name: &str) -> Result<Vec<WgKey>, Error> {
        let output = self.run_command("wg", &["show", iface_name, "peers"])?;

        let output = from_utf8(&output.stdout)?;

        let mut peers = Vec::new();

        for l in output.lines() {
            let parsed = l.parse();
            if parsed.is_ok() {
                peers.push(parsed.unwrap());
            } else {
                warn!("Could not parse peer! {}", l);
            }
        }

        Ok(peers)
    }

    /// checks the existing interfaces to find an interface name that isn't in use.
    /// then calls iproute2 to set up a new interface.
    pub fn setup_wg_if(&self) -> Result<String, Error> {
        //call "ip links" to get a list of currently set up links
        let links = String::from_utf8(self.run_command("ip", &["link"])?.stdout)?;
        let mut if_num = 0;
        //loop through the output of "ip links" until we find a wg suffix that isn't taken (e.g. "wg3")
        while links.contains(format!("wg{}", if_num).as_str()) {
            if_num += 1;
        }
        let interface = format!("wg{}", if_num);
        self.setup_wg_if_named(&interface)?;
        Ok(interface)
    }

    /// calls iproute2 to set up a new interface with a given name.
    pub fn setup_wg_if_named(&self, name: &str) -> Result<(), Error> {
        let output = self.run_command("ip", &["link", "add", &name, "type", "wireguard"])?;
        let stderr = String::from_utf8(output.stderr)?;
        if !stderr.is_empty() {
            if stderr.contains("exists") {
                return Ok(());
            } else {
                return Err(KernelInterfaceError::RuntimeError(format!(
                    "received error adding wg link: {}",
                    stderr
                )).into());
            }
        }
        Ok(())
    }

    /// Returns the number of clients that are active on the wg_exit tunnel
    pub fn get_wg_exit_clients_online(&self) -> Result<u32, Error> {
        let output = self.run_command("wg", &["show", "wg_exit", "latest-handshakes"])?;
        let mut num: u32 = 0;
        let out = String::from_utf8(output.stdout)?;
        for line in out.lines() {
            let content: Vec<&str> = line.split("\t").collect();
            let mut itr = content.iter();
            itr.next();
            let timestamp = itr
                .next()
                .ok_or(err_msg("Option did not contain a value."))?;
            let d = UNIX_EPOCH + Duration::from_secs(timestamp.parse()?);

            if SystemTime::now().duration_since(d)? < Duration::new(600, 0) {
                num += 1;
            }
        }
        Ok(num)
    }
}

#[test]
fn test_setup_wg_if_linux() {
    use KI;

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
    use KI;

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

    assert_eq!(KI.get_wg_exit_clients_online().unwrap(), 1);
}
