use super::KernelInterface;

use failure::Error;

impl KernelInterface {
    pub fn add_iptables_rule(&self, command: &str, rule: &[&str]) -> Result<(), Error> {
        assert!(rule.contains(&"-A") || rule.contains(&"-I"));

        let check_rule: Vec<&str> = rule
            .iter()
            .map(|x| if x == &"-A" || x == &"-I" { "-C" } else { x })
            .collect();

        let check = self.run_command(command, &check_rule)?;

        if !check.status.success() {
            self.run_command(command, rule)?;
        }

        Ok(())
    }
}
