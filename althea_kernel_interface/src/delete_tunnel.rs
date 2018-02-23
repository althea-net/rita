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

#[test]
fn test_delete_tunnel_linux() {
    use std::process::Output;
    use std::process::{ExitStatus};
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let ip_args = &["link", "del", "wg1"];

    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program,args| {
            assert_eq!(program, "ip");
            assert_eq!(args,ip_args);
            Ok(Output {
                stdout: b"".to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0)
            })
        }))
    };
    ki.delete_tunnel(&String::from("wg1")).unwrap();
}