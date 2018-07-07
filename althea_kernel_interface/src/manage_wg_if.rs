use super::{KernelInterface, KernelInterfaceError};
use std::net::IpAddr;
use std::str::from_utf8;

use failure::Error;

impl KernelInterface {
    pub fn get_peers(&self, iface_name: &str) -> Result<Vec<String>, Error> {
        let output = self.run_command("wg", &["show", iface_name, "peers"])?;

        let output = from_utf8(&output.stdout)?;

        let mut peers = Vec::new();

        for l in output.lines() {
            peers.push(l.to_string());
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

    pub fn delete_wg_if(&self, interface: &String) -> Result<u16, Error> {
        let port = self.run_command("wg", &["show", &interface, "listen-port"])?;
        if !port.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error getting wireguard interface port: {}",
                String::from_utf8(port.stderr)?
            )).into());
        }
        let output = self.run_command("ip", &["link", "del", &interface])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error deleting wireguard interface: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(String::from_utf8(port.stdout)?.parse()?)
    }

    pub fn delete_wg_if_by_address(&self, peer_ip: IpAddr) -> Result<u16, Error> {
        let interfaces = self.run_command("wg", &["show", "all", "endpoints"])?;
        if !interfaces.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error getting wireguard endpoints: {}",
                String::from_utf8(interfaces.stderr)?
            )).into());
        }
        for tunnel in String::from_utf8(interfaces.stdout)?.lines() {
            if tunnel.contains(&peer_ip.to_string()) {
                let mut line = tunnel.split_whitespace();
                let iface = line.next().expect("bad wireguard line!");
                return self.delete_wg_if(&iface.to_string());
            }
        }

        return Err(KernelInterfaceError::RuntimeError(format!(
            "No wg interface to peer: {}",
            peer_ip.to_string()
        )).into());
    }

    pub fn delete_wg_if_by_key(&self, wg_key: &String) -> Result<u16, Error> {
        let interfaces = self.run_command("wg", &["show", "all", "endpoints"])?;
        if !interfaces.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error getting wireguard endpoints: {}",
                String::from_utf8(interfaces.stderr)?
            )).into());
        }
        for tunnel in String::from_utf8(interfaces.stdout)?.lines() {
            if tunnel.contains(wg_key) {
                let mut line = tunnel.split_whitespace();
                let iface = line.next().expect("bad wireguard line!");
                return self.delete_wg_if(&iface.to_string());
            }
        }

        return Err(KernelInterfaceError::RuntimeError(format!(
            "No wg interface to peer: {}",
            wg_key
        )).into());
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_delete_wg_if_linux() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::ExitStatus;
        use std::process::Output;

        use KI;

        let wg_args = &["wg", "show", "wg1", "listen-port"];

        KI.set_mock(Box::new(move |program, args| {
            assert_eq!(program, "wg");
            assert_eq!(args, wg_args);
            Ok(Output {
                stdout: b"60001".to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        }));

        let ip_args = &["link", "del", "wg1"];

        KI.set_mock(Box::new(move |program, args| {
            assert_eq!(program, "ip");
            assert_eq!(args, ip_args);
            Ok(Output {
                stdout: b"".to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        }));
        assert_eq!(KI.delete_wg_if(&String::from("wg1")).unwrap(), 6001);
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
}
