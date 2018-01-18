use super::{KernelInterface, Error};

use std::net::{SocketAddr};
use std::path::Path;

impl KernelInterface {
    pub fn open_tunnel_linux(
        &mut self,
        interface: &String,
        endpoint: &SocketAddr,
        remote_pub_key: &String,
        private_key_path: &Path
    ) -> Result<(), Error> {
        let output = self.run_command("wg", &[
            "set",
            &interface,
            "private-key",
            &format!("{}", private_key_path.to_str().unwrap()),
            "peer",
            &format!("{}", remote_pub_key),
            "endpoint",
            &format!("{}", endpoint),
            "allowed-ips",
            "::/0"
        ])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error from wg command: {}", String::from_utf8(output.stderr)?)));
        }
        Ok(())
    }
}