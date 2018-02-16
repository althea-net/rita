use super::{KernelInterface, Error};

use std::net::{SocketAddr};
use std::path::Path;

impl KernelInterface {
    pub fn open_tunnel_linux(
        &mut self,
        interface: &String,
        port: u16,
        endpoint: &SocketAddr,
        remote_pub_key: &String,
        private_key_path: &Path
    ) -> Result<(), Error> {
        if let &SocketAddr::V6(socket) = endpoint {
            let phy_name = self.get_device_name_linux(endpoint.ip())?;
            let local_ip = self.get_link_local_reply_ip_linux(endpoint.ip())?;
            let output = self.run_command("wg", &[
                "set",
                &interface,
                "listen-port",
                &format!("{}", port),
                "private-key",
                &format!("{}", private_key_path.to_str().unwrap()),
                "peer",
                &format!("{}", remote_pub_key),
                "endpoint",
                &format!("[{}%{}]:{}", endpoint.ip(), phy_name, endpoint.port()),
                "allowed-ips",
                "::/0",
                "persistent-keepalive",
                "5"
            ])?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!("received error from wg command: {}", String::from_utf8(output.stderr)?)));
            }
            let output = self.run_command("ip", &["link", "set", &interface, "up"])?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!("received error setting wg interface up: {}", String::from_utf8(output.stderr)?)))
            }
            Ok(())
        } else {
            return Err(Error::RuntimeError(format!("Only ipv6 neighbors are supported")))
        }
    }
}