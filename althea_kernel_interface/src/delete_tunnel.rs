use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

impl KernelInterface {
    pub fn delete_tunnel(&self, interface: &String) -> Result<(), Error> {
        let output = self.run_command("ip", &["link", "del", &interface])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error deleting wireguard interface: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(())
    }
}

#[test]
fn test_delete_tunnel_linux() {
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    use KI;

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
    KI.delete_tunnel(&String::from("wg1")).unwrap();
}
