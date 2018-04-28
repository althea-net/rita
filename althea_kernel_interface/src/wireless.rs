use super::KernelInterface;

use failure::Error;

impl KernelInterface {
    pub fn openwrt_reset_wireless(&self) -> Result<(), Error> {
        self.run_command("wifi", &[])?;
        Ok(())
    }
}
