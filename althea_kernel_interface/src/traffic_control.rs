use super::KernelInterface;
use failure::Error;

impl KernelInterface {
    /// Determines if the provided interface has a configured qdisc
    pub fn has_limit(&self, iface_name: &str) -> Result<bool, Error> {
        let result = self.run_command("tc", &["qdisc", "show", iface_name]);
        let stdout = &String::from_utf8(result?.stdout)?;
        Ok(!stdout.contains("noqueue"))
    }

    /// Creates a qdisc limit with the given bandwidth tuned for the correct rate
    pub fn create_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        // we need 1kbyte of burst cache per mbit of bandwidth to actually
        // reach the shaped rate
        let burst = bw / 1000 as u32;
        // amount of time a packet can spend in the burst cache, 40ms
        let latency = 40u32;

        let output = self.run_command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                iface_name,
                "root",
                "tbf",
                "latency",
                &format!("{}ms", latency),
                "burst",
                &format!("{}kbit", burst),
                "rate",
                &format!("{}kbit", bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to create new qdisc limit!");
        }
    }

    /// edits a already limited interface to have the specified rate versus it's current rate
    pub fn update_limit(&self, iface_name: &str, bw: u32) -> Result<(), Error> {
        // we need 1kbyte of burst cache per mbit of bandwidth to actually
        // reach the shaped rate
        let burst = bw / 1000 as u32;
        // amount of time a packet can spend in the burst cache, 40ms
        let latency = 40u32;

        let output = self.run_command(
            "tc",
            &[
                "qdisc",
                "add",
                "dev",
                iface_name,
                "root",
                "tbf",
                "latency",
                &format!("{}ms", latency),
                "burst",
                &format!("{}kbit", burst),
                "rate",
                &format!("{}kbit", bw),
            ],
        )?;

        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to update qdisc limit!");
        }
    }

    /// deletes the interface limit
    pub fn delete_limit(&self, iface_name: &str) -> Result<(), Error> {
        let output = self.run_command("tc", &["qdisc", "del", "dev", iface_name])?;
        if output.status.success() {
            Ok(())
        } else {
            bail!("Failed to delete qdisc limit!");
        }
    }
}
