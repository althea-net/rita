use super::{KernelInterface, KernelManagerError};

use failure::Error;

impl KernelInterface {
    //Sets an arbitrary UCI variable on OpenWRT
    pub fn set_uci_var(&self, key: &str, value: &str) -> Result<bool, Error> {
        let output = self.run_command("uci", &["set", &format!("{}={}", key, value)])?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "recieved error while setting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(true)
    }

    //Sets an arbitrary UCI list on OpenWRT
    pub fn set_uci_list(&self, key: &str, value: &[&str]) -> Result<bool, Error> {
        self.del_uci_var(&key)?;
        for v in value {
            let output = self.run_command("uci", &["add_list", &key, "=", &v])?;
            if !output.stderr.is_empty() {
                return Err(KernelManagerError::RuntimeError(format!(
                    "recieved error while setting UCI: {}",
                    String::from_utf8(output.stderr)?
                )).into());
            }
        }
        Ok(true)
    }

    //Deletes an arbitrary UCI variable on OpenWRT
    pub fn del_uci_var(&self, key: &str) -> Result<bool, Error> {
        let output = self.run_command("uci", &["delete", &key])?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "recieved error while setting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(true)
    }

    //Retrieves the value of a given UCI path, could be one or multiple values
    pub fn get_uci_var(&self, key: &str) -> Result<String, Error> {
        let output = self.run_command("uci", &["show", &key])?;
        if !output.stderr.is_empty() {
            return Err(KernelManagerError::RuntimeError(format!(
                "recieved error while getting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(String::from_utf8(output.stdout)?)
    }

    //Commits changes to UCI
    pub fn uci_commit(&self) -> Result<bool, Error> {
        let output = self.run_command("uci", &["commit"])?;
        if !output.status.success() {
            return Err(KernelManagerError::RuntimeError(format!(
                "recieved error while commiting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(true)
    }
}
