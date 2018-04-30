use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

impl KernelInterface {
    fn run_uci(&self, command: &str, args: &[&str]) -> Result<(), Error> {
        let output = self.run_command(command, args)?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error while setting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(())
    }

    //Sets an arbitrary UCI variable on OpenWRT
    pub fn set_uci_var(&self, key: &str, value: &str) -> Result<bool, Error> {
        self.run_uci("uci", &["set", &format!("{}={}", key, value)])?;
        Ok(true)
    }

    //Adds an arbitrary UCI variable on OpenWRT
    pub fn add_uci_var(&self, key: &str, value: &str) -> Result<bool, Error> {
        self.run_uci("uci", &["add", key, value])?;
        Ok(true)
    }

    //Sets an arbitrary UCI list on OpenWRT
    pub fn set_uci_list(&self, key: &str, value: &[&str]) -> Result<bool, Error> {
        match self.del_uci_var(&key) {
            Err(e) => trace!("Delete uci var failed! {:?}",e),
            _ => ()
        };

        for v in value {
            self.run_uci("uci", &["add_list", &format!("{}={}", &key, &v)])?;
        }
        Ok(true)
    }

    //Deletes an arbitrary UCI variable on OpenWRT
    pub fn del_uci_var(&self, key: &str) -> Result<bool, Error> {
        self.run_uci("uci", &["delete", &key])?;
        Ok(true)
    }

    //Retrieves the value of a given UCI path, could be one or multiple values
    pub fn get_uci_var(&self, key: &str) -> Result<String, Error> {
        let output = self.run_command("uci", &["show", &key])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
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
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error while commiting UCI: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(true)
    }

    pub fn refresh_initd(&self, program: &str) -> Result<(), Error> {
        let output = self.run_command(&format!("/etc/init.d/{}", program), &["reload"])?;
        if !output.status.success() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "recieved error while refreshing {}: {}",
                program,
                String::from_utf8(output.stderr)?
            )).into());
        }
        Ok(())
    }
}
