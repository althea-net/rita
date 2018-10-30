//! This is an interface to read Wireguard's bandwidth usage counters for a given interface
//! this is mostly used in client and exit billing where we only have to concern ourselves with
//! a single destination and a single price.

use failure::Error;
use regex::Regex;

use std::collections::HashMap;

use super::{KernelInterface, KernelInterfaceError};

#[derive(Clone, Debug)]
pub struct WgUsage {
    pub upload: u64,
    pub download: u64,
}

impl KernelInterface {
    /// Takes a wg interface name and provides upload and download since creation in bytes
    /// in a hashmap indexed by peer WireGuard key
    pub fn read_wg_counters(&self, wg_name: &str) -> Result<HashMap<String, WgUsage>, Error> {
        let output = self.run_command("wg", &["show", wg_name, "transfer"])?;
        if !output.stderr.is_empty() {
            return Err(KernelInterfaceError::RuntimeError(format!(
                "received error from wg command: {}",
                String::from_utf8(output.stderr)?
            )).into());
        }

        lazy_static! {
            static ref RE: Regex = Regex::new(
                r"^(?P<key>[/=0-9a-zA-Z]+)\t(?P<download>[0-9]+)\t(?P<upload>[0-9]+)"
            ).expect("Unable to compile regular expression");
        }

        let mut result = HashMap::new();
        for item in RE.captures_iter(&String::from_utf8(output.stdout)?) {
            println!("{:?}", item);
            let usage = WgUsage {
                upload: item["upload"].parse()?,
                download: item["download"].parse()?,
            };
            result.insert(item["key"].to_string(), usage);
        }

        Ok(result)
    }
}

#[test]
fn test_read_wg_counters() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    use KI;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "wg");
                assert_eq!(args, vec!["show", "wg_exit", "transfer"]);
                Ok(Output {
                    stdout: b"jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg=\t821519724\t13592616000"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));
    let wg_counter = KI
        .read_wg_counters("wg_exit")
        .expect("Unable to parse wg counters");

    assert_eq!(wg_counter.len(), 1);
    assert!(wg_counter.contains_key("jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg="));
    assert_eq!(
        wg_counter
            .get("jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg=")
            .unwrap()
            .upload,
        13592616000
    );
    assert_eq!(
        wg_counter
            .get("jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg=")
            .unwrap()
            .download,
        821519724
    );
}
