//! This is an interface to read Wireguard's bandwidth usage counters for a given interface
//! this is mostly used in client and exit billing where we only have to concern ourselves with
//! a single destination and a single price.

use crate::KernelInterfaceError;
use crate::{run_command, KernelInterfaceError as Error};
use althea_types::WgKey;
use regex::Regex;
use std::collections::HashMap;

#[derive(Clone, Debug, Copy)]
pub struct WgUsage {
    pub upload: u64,
    pub download: u64,
}

pub fn prepare_usage_history<S: ::std::hash::BuildHasher>(
    counters: &HashMap<WgKey, WgUsage, S>,
    usage_history: &mut HashMap<WgKey, WgUsage, S>,
) {
    for (wg_key, bytes) in counters.iter() {
        match usage_history.get_mut(wg_key) {
            Some(history) => {
                // tunnel has been reset somehow, reset usage
                if history.download > bytes.download {
                    trace!("Reseting usage history downloads");
                    history.download = 0;
                }
                if history.upload > bytes.upload {
                    trace!("Reseting usage history uploads");
                    history.upload = 0;
                }
            }
            None => {
                trace!(
                    "We have not seen {:?} before, starting counter off at {:?}",
                    wg_key,
                    bytes
                );
                usage_history.insert(*wg_key, *bytes);
            }
        }
    }
}

/// Internal function to parse the output of `wg show <interface> transfer`
fn read_wg_counters_internal(stdout: String) -> Result<HashMap<WgKey, WgUsage>, Error> {
    lazy_static! {
        static ref RE: Regex =
            Regex::new(r"(?P<key>[+/=0-9a-zA-Z]+)\t(?P<download>[0-9]+)\t(?P<upload>[0-9]+)\n*")
                .expect("Unable to compile regular expression");
    }

    let mut result = HashMap::new();
    for item in RE.captures_iter(&stdout) {
        let usage = WgUsage {
            upload: item["upload"].parse()?,
            download: item["download"].parse()?,
        };
        match item["key"].parse() {
            Ok(key) => {
                result.insert(key, usage);
            }
            Err(e) => warn!("Failed to parse WgKey {} with {:?}", &item["key"], e),
        }
    }

    Ok(result)
}

/// Takes a wg interface name and provides upload and download since creation in bytes
/// in a hashmap indexed by peer WireGuard key
pub fn read_wg_counters(wg_name: &str) -> Result<HashMap<WgKey, WgUsage>, Error> {
    let output = run_command("wg", &["show", wg_name, "transfer"])?;
    if !output.stderr.is_empty() {
        return Err(KernelInterfaceError::RuntimeError(format!(
            "received error from wg command: {}",
            String::from_utf8(output.stderr)?
        )));
    }
    read_wg_counters_internal(String::from_utf8(output.stdout)?)
}

#[test]
fn test_read_wg_counters() {
    let wg_counter = read_wg_counters_internal(
        "jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg=\t821519724\t13592616000".to_string(),
    )
    .unwrap();
    let test_key = "jkIodvXKgij/rAEQXFEPJpls6ooxXJEC5XlWA1uUPUg="
        .parse()
        .unwrap();

    assert_eq!(wg_counter.len(), 1);
    assert!(wg_counter.contains_key(&test_key));
    assert_eq!(wg_counter.get(&test_key).unwrap().upload, 13_592_616_000);
    assert_eq!(wg_counter.get(&test_key).unwrap().download, 821_519_724);
}

#[test]
fn test_read_wg_exit_counters() {
    let stdout = "7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI=\t0\t0
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
    ";
    let wg_counter = read_wg_counters_internal(stdout.to_string()).unwrap();

    let test_key = "Iz668/X70eo/PF9C94cKAZjrSjU961V8xndxTtk0FRM="
        .parse()
        .unwrap();
    let test_key2 = "7fYutmH8iHIcuKjnzcgaDBNpVRw8ly0XMYFr7PtirDI="
        .parse()
        .unwrap();
    let test_key3 = "fFGhz1faSAqNjTqT5rpBWLD/FLrP6P/P59Z2Eo3jQDo="
        .parse()
        .unwrap();

    assert_eq!(wg_counter.len(), 11);
    assert!(wg_counter.contains_key(&test_key));
    assert_eq!(wg_counter.get(&test_key).unwrap().upload, 15_281_630_160);
    assert_eq!(wg_counter.get(&test_key).unwrap().download, 7_088_439_728);
    assert!(wg_counter.contains_key(&test_key2));
    assert_eq!(wg_counter.get(&test_key2).unwrap().upload, 0);
    assert_eq!(wg_counter.get(&test_key2).unwrap().download, 0);
    assert!(wg_counter.contains_key(&test_key3));
    assert_eq!(wg_counter.get(&test_key3).unwrap().upload, 3_318_456);
    assert_eq!(wg_counter.get(&test_key3).unwrap().download, 0);
}
