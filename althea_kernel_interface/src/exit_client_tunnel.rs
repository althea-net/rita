use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

impl KernelInterface {
    pub fn set_client_exit_tunnel_config(
        &self,
        endpoint: SocketAddr,
        pubkey: String,
        private_key_path: String,
        listen_port: u16,
        local_ip: IpAddr,
    ) -> Result<(), Error> {
        self.run_command(
            "wg",
            &[
                "set",
                "wg_exit",
                "listen-port",
                &listen_port.to_string(),
                "private-key",
                &private_key_path,
                "peer",
                &pubkey,
                "endpoint",
                &format!("[{}]:{}", endpoint.ip(), endpoint.port()),
                "allowed-ips",
                "172.168.1.254",
                "persistent-keepalive",
                "5",
            ],
        )?;

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

    pub fn set_route_to_tunnel(&self, gateway: &IpAddr) -> Result<(), Error> {
        let output = self.run_command(
            "ip",
            &["route", "add", "default", "via", &gateway.to_string()],
        )?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error setting ip route: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        Ok(())
    }
}
