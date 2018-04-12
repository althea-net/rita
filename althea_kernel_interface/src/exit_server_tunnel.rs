use super::{KernelInterface, KernelManagerError};

use failure::Error;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

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

        let mut args_str = Vec::new();

        let arg_count = args.len();

        for i in 0..arg_count {
            args_str.push(args[i].as_str())
        }

        self.run_command(&command, &args_str[..])?;

        let output = self.run_command(
            "ip",
            &[
                "address",
                "add",
                &format!("{}/24", local_ip),
                "dev",
                "wg_exit",
            ],
        )?;

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "mtu", "1340"])?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "received error adding wg link: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        let output = self.run_command("ip", &["link", "set", "dev", "wg_exit", "up"])?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "received error setting wg interface up: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        Ok(())
    }

    pub fn setup_nat(&self, external_interface: &str) -> Result<(), Error> {
        self.run_command(
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

        Ok(())
    }
}
