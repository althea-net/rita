use super::{Error, KernelInterface};

use std::fs::{File};
use std::io::{Write};
use std::path::Path;

impl KernelInterface {
    pub fn create_wg_key_linux(&self, path: &Path) -> Result<(), Error> {
        if path.exists() {
            Ok(())
        } else {
            let mut output = self.run_command("wg", &["genkey"])?;
            if !output.stderr.is_empty() {
                return Err(Error::RuntimeError(format!(
                    "recieved error in generating wg key: {}",
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