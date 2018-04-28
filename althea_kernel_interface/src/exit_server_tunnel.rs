use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

use std::net::IpAddr;

#[derive(Debug)]
pub struct ExitClient {
    pub internal_ip: IpAddr,
    pub public_key: String,
    pub mesh_ip: IpAddr,
    pub port: u16,
}

impl KernelInterface {
    pub fn set_exit_wg_config(
        &self,
        clients: Vec<(ExitClient)>,
        listen_port: u16,
        private_key_path: &str,
        local_ip: &IpAddr,
        netmask: u8,
    ) -> Result<(), Error> {
        let command = "wg".to_string();

        let mut args = Vec::new();
        args.push("set".into());
        args.push("wg_exit".into());
        args.push("listen-port".into());
        args.push(format!("{}", listen_port));
        args.push("private-key".into());
        args.push(private_key_path.to_string());

        for c in clients {
            args.push("peer".into());
            args.push(format!("{}", c.public_key));
            args.push("endpoint".into());
            args.push(format!("[{}]:{}", c.mesh_ip, c.port));
            args.push("allowed-ips".into());
            args.push(format!("{}", c.internal_ip));
            args.push("persistent-keepalive".into());
            args.push("5".into());
        }

        let arg_str: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

        self.run_command(&command, &arg_str[..])?;

        let _output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{}/{}", local_ip, netmask),
                "dev",
                "wg_exit",
            ],
        )?;

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        Ok(())
    }

    pub fn setup_nat(&self, external_interface: &str) -> Result<(), Error> {
        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                external_interface,
                "-j",
                "MASQUERADE",
            ],
        )?;

        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-o",
                external_interface,
                "-i",
                "wg_exit",
                "-j",
                "ACCEPT",
            ],
        )?;

        self.add_iptables_rule(
            "iptables",
            &[
                "-w",
                "-t",
                "filter",
                "-A",
                "FORWARD",
                "-o",
                "wg_exit",
                "-i",
                external_interface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )?;

        Ok(())
    }
}
