use super::{KernelInterface, KernelInterfaceError};

use failure::Error;

use regex::Regex;

impl KernelInterface {
    pub fn init_exit_client_counters(&self) -> Result<(), Error> {
        self.run_command("iptables", &["-w", "-A", "OUTPUT", "-o", "wg_exit"])?;

        self.run_command("iptables", &["-w", "-A", "INPUT", "-i", "wg_exit"])?;

        Ok(())
    }

    pub fn read_exit_client_counters_output(&self) -> Result<u64, Error> {
        let output = self.run_command("iptables", &["-w", "-L", "OUTPUT", "-Z", "-x", "-v"])?;

        let re = Regex::new(r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+--\s+any\s+wg_exit").unwrap();

        let stdout = String::from_utf8(output.stdout)?;

        let caps = re.captures(&stdout).unwrap();

        return Ok(caps[2].parse::<u64>()? + (caps[1].parse::<u64>()? * 80));
    }

    pub fn read_exit_client_counters_input(&self) -> Result<u64, Error> {
        let output = self.run_command("iptables", &["-w", "-L", "INPUT", "-Z", "-x", "-v"])?;

        let re = Regex::new(r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+--\s+wg_exit\s+any").unwrap();

        let stdout = String::from_utf8(output.stdout)?;

        let caps = re.captures(&stdout).unwrap();

        return Ok(caps[2].parse::<u64>()? + (caps[1].parse::<u64>()? * 80));
    }
}
