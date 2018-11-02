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
            static ref RE: Regex =
                Regex::new(r"(?P<key>[/=0-9a-zA-Z]+)\t(?P<download>[0-9]+)\t(?P<upload>[0-9]+)\n*")
                    .expect("Unable to compile regular expression");
        }

        let mut result = HashMap::new();
        for item in RE.captures_iter(&String::from_utf8(output.stdout)?) {
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

#[test]
fn test_read_wg_exit_counters() {
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
                    stdout: b"7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI=\t0\t0
fFGhz1faSAqNjTqT5rpBWLD/FLrP6P/P59Z2Eo3jQDo=\t0\t3318456
oum4Nd5nngTjG5Hw+XFoLk18pTY8DA7bl2OIwWkc4wQ=\t0\t0
TFG8LAio7MDd+i5tExNX/vxR1pqpgNqo+RiUkmBekmU=\t0\t0
Iz668/X70eo/PF9C94cKAZjrSjU961V8xndxTtk0FRM=\t7088439728\t15281630160
Hgu1A3JFol3D6TFsmnjX/PVvupl0W2wMee0wRVFb0Aw=\t122193456\t1120342792
7dxulyk1UcCJ0zUDcGbV+CQRY0uGUnbY5exi6I8EeyE=\t351530232\t5424629680
b6HGtuWLAIHyINOgL7euzrMsMfzHIie5kYDScSCT7Ds=\t67526804\t88741160
RW1XPRn4nJQaDqqeDFRilPjtYOUBitXIuHwoKZAtKWw=\t480230868\t3531367092
AJYeYn4R+I+Jc7xiKQ15ImruYFXybTiR6BB6Ip3/njs=\t1777907382\t2034640104
jL+LlqHAM63Qd9/ynAuqqn4wrYO7Hp8cYMlnf2OoSH8=\t679969972\t6539417596
".to_vec(),
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

    assert_eq!(wg_counter.len(), 11);
    assert!(wg_counter.contains_key("Iz668/X70eo/PF9C94cKAZjrSjU961V8xndxTtk0FRM="));
    assert_eq!(
        wg_counter
            .get("Iz668/X70eo/PF9C94cKAZjrSjU961V8xndxTtk0FRM=")
            .unwrap()
            .upload,
        15281630160
    );
    assert_eq!(
        wg_counter
            .get("Iz668/X70eo/PF9C94cKAZjrSjU961V8xndxTtk0FRM=")
            .unwrap()
            .download,
        7088439728
    );
    assert!(wg_counter.contains_key("7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI="));
    assert_eq!(
        wg_counter
            .get("7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI=")
            .unwrap()
            .upload,
        0
    );
    assert_eq!(
        wg_counter
            .get("7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI=")
            .unwrap()
            .download,
        0
    );
    assert!(wg_counter.contains_key("fFGhz1faSAqNjTqT5rpBWLD/FLrP6P/P59Z2Eo3jQDo="));
    assert_eq!(
        wg_counter
            .get("fFGhz1faSAqNjTqT5rpBWLD/FLrP6P/P59Z2Eo3jQDo=")
            .unwrap()
            .upload,
        3318456
    );
    assert_eq!(
        wg_counter
            .get("fFGhz1faSAqNjTqT5rpBWLD/FLrP6P/P59Z2Eo3jQDo=")
            .unwrap()
            .download,
        0
    );
}
