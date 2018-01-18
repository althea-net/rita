use super::{KernelInterface, Error};

use std::str;

use itertools::join;
use regex::Regex;

impl KernelInterface {
    pub fn delete_ebtables_rule(
        &mut self,
        args: &[&str]
    ) -> Result<(), Error> {
        let loop_limit = 100;
        for _ in 0..loop_limit {
            let program = "ebtables";
            let res = self.run_command(program, args)?;

            let re = Regex::new(r"rule does not exist").unwrap();

            // keeps looping until it is sure to have deleted the rule
            if re.is_match(str::from_utf8(&res.stderr)?) || re.is_match(str::from_utf8(&res.stdout)?) {
                return Ok(());
            }
            if res.stdout == b"".to_vec() {
                continue;
            } else {
                return Err(Error::RuntimeError(
                    format!("unexpected output from {} {:?}: {:?}", program, join(args, " "), String::from_utf8_lossy(&res.stdout)),
                ))
            }
        }
        Err(Error::RuntimeError(
            format!("loop limit of {} exceeded", loop_limit)
        ))
    }
}