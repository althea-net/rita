use super::KernelInterface;

use failure::Error;

use regex::Regex;

impl KernelInterface {
    pub fn init_iface_counters(&self, interface: &str) -> Result<(), Error> {
        let chain_name = format!("{}-counter", interface);

        // Create a new chain with the chain name
        self.run_command("iptables", &["-N", &chain_name])?;

        // Redirect everything to that chain
        self.add_iptables_rule("iptables", &["-w", "-I", "OUTPUT", "-j", &chain_name])?;
        self.add_iptables_rule("iptables", &["-w", "-I", "INPUT", "-j", &chain_name])?;

        // Check if they are going in or out over the epecific interface
        self.add_iptables_rule("iptables", &["-w", "-A", &chain_name, "-o", interface])?;
        self.add_iptables_rule("iptables", &["-w", "-A", &chain_name, "-i", interface])?;
        // Return packet for further processing
        self.add_iptables_rule("iptables", &["-w", "-A", &chain_name, "-j", "RETURN"])?;
        Ok(())
    }

    /// returns ((input bytes, input packets), (output bytes, output packets))
    pub fn read_iface_counters(&self, interface: &str) -> Result<((u64, u64), (u64, u64)), Error> {
        let chain_name = format!("{}-counter", interface);

        let output = self.run_command("iptables", &["-w", "-L", &chain_name, "-Z", "-x", "-v"])?;

        let stdout = String::from_utf8(output.stdout)?;

        let re = Regex::new(&format!(
            r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+--\s+any\s+{}",
            interface
        )).unwrap();
        let caps = re.captures(&stdout).unwrap();
        let output_traffic = (caps[2].parse::<u64>()?, caps[1].parse::<u64>()?);

        let re = Regex::new(&format!(
            r"(?m)^\s+(\d+)\s+(\d+)\s+all\s+--\s+{}\s+any",
            interface
        )).unwrap();
        let caps = re.captures(&stdout).unwrap();
        let input_traffic = (caps[2].parse::<u64>()?, caps[1].parse::<u64>()?);

        Ok((input_traffic, output_traffic))
    }
}
