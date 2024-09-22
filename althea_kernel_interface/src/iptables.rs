use crate::{run_command, KernelInterfaceError};

/// -I and -A will be checked to see if they already exist before adding.
pub fn add_iptables_rule(command: &str, rule: &[&str]) -> Result<(), KernelInterfaceError> {
    assert!(rule.contains(&"-A") || rule.contains(&"-I") || rule.contains(&"-D"));

    // we replace the add or append commands with a check command so that we can see if the rule is actually present
    // if it is then we don't need to do anything
    let mut new_command = Vec::new();
    let mut i_pos_skip = None;

    for (i, rul) in rule.iter().enumerate() {
        if i_pos_skip.is_some() && i == i_pos_skip.unwrap() {
            continue;
        }
        if *rul == "-I" {
            // if there's an insertion index, then skip it for the check statement
            if rule[i + 2].parse::<u32>().is_ok() {
                i_pos_skip = Some(i + 2);
            }
            new_command.push("-C");
        } else if *rul == "-A" {
            new_command.push("-C");
        } else {
            new_command.push(rul);
        }
    }

    let check = run_command(command, &new_command)?;

    if !check.status.success() {
        run_command(command, rule)?;
    }

    Ok(())
}
