use super::{KernelInterface, Error};

impl KernelInterface {
    pub fn delete_tunnel(&mut self, interface: &String) -> Result<(),Error> {
        let output = self.run_command("ip", &["link", "del", &interface])?;
        if !output.stderr.is_empty() {
            return Err(Error::RuntimeError(format!("recieved error deleting wireguard interface: {}", String::from_utf8(output.stderr)?)));
        }
        Ok(())
    }

}