use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

impl KernelInterface {
    pub fn delete_tunnel(&self, interface: &String) -> Result<(), Error> {
        let output = self.run_command("ip", &["link", "del", &interface])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error deleting wireguard interface: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(())
    }
}

#[test]
fn test_delete_tunnel_linux() {
    use KI;

    KI.test_commands("test_delete_tunnel_linux", &[("ip link del wg1", "")]);

    KI.delete_tunnel(&String::from("wg1")).unwrap();
}
