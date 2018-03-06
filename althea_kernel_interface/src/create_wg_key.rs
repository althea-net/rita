use super::{KernelInterface, KernelManagerError};

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use failure::Error;

impl KernelInterface {
    pub fn create_wg_key(&self, path: &Path) -> Result<(), Error> {
        if path.exists() {
            trace!("File exists, not generating key");
            Ok(())
        } else {
            trace!("File does not exists, generating key");
            let mut output = self.run_command("wg", &["genkey"])?;
            if !output.stderr.is_empty() {
                return Err(KernelManagerError::RuntimeError(format!(
                    "received error in generating wg key: {}",
                    String::from_utf8(output.stderr)?
                )).into());
            }
            output.stdout.truncate(44); //key should only be 44 bytes
            let mut priv_key_file = File::create(path)?;
            write!(priv_key_file, "{}", String::from_utf8(output.stdout)?)?;
            Ok(())
        }
    }

    pub fn create_wg_keypair(&mut self) -> Result<[String; 2], Error> {
        let mut genkey = Command::new("wg")
            .args(&["genkey"])
            .stdout(Stdio::piped())
            .output()
            .unwrap();

        let mut genstdout = genkey.stdout;
        let mut pubkey = Command::new("wg")
            .args(&["pubkey"])
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();

        pubkey.stdin.as_mut().unwrap().write_all(&genstdout);
        let output = pubkey.wait_with_output().unwrap();

        let mut privkey_str = String::from_utf8(genstdout)?;
        let mut pubkey_str = String::from_utf8(output.stdout)?;
        privkey_str.truncate(44);
        pubkey_str.truncate(44);

        Ok([pubkey_str, privkey_str])
    }
}

#[test]
fn test_create_wg_key_linux() {
    use std::process::Output;
    use std::process::ExitStatus;
    use std::cell::RefCell;
    use std::os::unix::process::ExitStatusExt;

    let wg_args = &["genkey"];
    let mut ki = KernelInterface {
        run_command: RefCell::new(Box::new(move |program, args| {
            assert_eq!(program, "wg");
            assert_eq!(args, wg_args);
            Ok(Output {
                stdout: b"cD6//mKSM4mhaF4mNY7N93vu5zKad79/MyIRD3L9L0s=".to_vec(),
                stderr: b"".to_vec(),
                status: ExitStatus::from_raw(0),
            })
        })),
    };
    let test_path = Path::new("/tmp/wgtestkey");
    ki.create_wg_key(test_path).unwrap();
}
