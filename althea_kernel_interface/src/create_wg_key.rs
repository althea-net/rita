use super::{Error, KernelInterface};

use std::fs::File;
use std::io::Write;
use std::path::Path;

impl KernelInterface {
    pub fn create_wg_key(&self, path: &Path) -> Result<(), Error> {
        if path.exists() {
            trace!("File exists, not generating key");
            Ok(())
        } else {
            trace!("File does not exists, generating key");
            let mut output = self.run_command("wg", &["genkey"])?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "received error in generating wg key: {}",
                    String::from_utf8(output.stderr)?
                )));
            }
            output.stdout.truncate(44); //key should only be 44 bytes
            let mut priv_key_file = File::create(path)?;
            write!(priv_key_file, "{}", String::from_utf8(output.stdout)?)?;
            Ok(())
        }
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
