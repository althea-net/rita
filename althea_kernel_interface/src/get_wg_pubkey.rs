use super::{KernelInterface, KernelManagerError};

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

use failure::Error;

impl KernelInterface {
    pub fn get_wg_pubkey(&mut self, path: &Path) -> Result<String, Error> {
        let priv_key_file = File::open(path)?;
        let mut output = Command::new("wg")
            .args(&["pubkey"])
            .stdin(Stdio::from(priv_key_file))
            .output()?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "recieved error in getting wg public key: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        output.stdout.truncate(44); //key should only be 44 bytes
        Ok(String::from_utf8(output.stdout)?)
    }
}
