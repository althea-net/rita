use super::KernelInterface;

use failure::Error;

impl dyn KernelInterface {
    pub fn add_iptables_rule(&self, command: &str, rule: &[&str]) -> Result<(), Error> {
        assert!(rule.contains(&"-A") || rule.contains(&"-I") || rule.contains(&"-D"));

        // we replace the add or delete commands with a check command so that we can see if the rule is actually present
        // if it is then we don't need to do anything
        let mut new_command = Vec::new();
        let mut i_pos_skip = None;
        for i in 0..rule.len() {
            if i_pos_skip.is_some() && i == i_pos_skip.unwrap() {
                continue;
            }
            if rule[i] == "-I" {
                new_command.push("-C");
                i_pos_skip = Some(i + 2);
            } else if rule[i] == "-A" {
                new_command.push("-C");
            } else {
                new_command.push(rule[i]);
            }
        }

        let check = self.run_command(command, &new_command)?;

        if !check.status.success() {
            self.run_command(command, rule)?;
        }

        Ok(())
    }
}
