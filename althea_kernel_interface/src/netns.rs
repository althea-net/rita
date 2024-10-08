use crate::run_command;
use std::thread::sleep;

/// Custom function for our integration test environment, returns a numbered netnamespace
/// this thread is currently operating in, allowing us to dispatch lazy static data
/// independent to each thread. Arch wise the fact that we have this problem at all indicates
/// that the lazy static for cross thread comms arch if a bit questionable by nature
pub fn check_integration_test_netns() -> u32 {
    if cfg!(feature = "integration_test") {
        let mut ns = run_command("ip", &["netns", "identify"]);
        while let Err(e) = ns {
            warn!("Could not get netns name, retrying: {:?}", e);
            sleep(std::time::Duration::from_secs(1));
            ns = run_command("ip", &["netns", "identify"]);
        }
        let ns = ns.unwrap();
        let ns = match String::from_utf8(ns.stdout) {
            Ok(s) => s,
            Err(_) => panic!("Could not get netns name!"),
        };
        let ns = ns.trim();
        match (
            ns.split('-').last().unwrap().parse(),
            ns.split('_').last().unwrap().parse(),
        ) {
            (Ok(a), _) => a,
            (_, Ok(a)) => a,
            (Err(_), Err(_)) => {
                // for some reason it's not easily possible to tell if we're in a unit test
                error!("Could not get netns name, maybe a unit test?");
                0
            }
        }
    } else {
        0
    }
}

/// Gets the network namespace name that holds the thread this function was called from.
/// If the calling thread was not inside a network namespace/in the default namespace, this
/// function returns a None
pub fn get_namespace() -> Option<String> {
    let output = match run_command("ip", &["netns", "identify"]) {
        Ok(output) => output,
        Err(_) => {
            warn!("Could not run ip netns- is ip netns installed?");
            return None;
        }
    };
    match String::from_utf8(output.stdout) {
        Ok(mut s) => {
            s.truncate(s.len() - 1);
            if !s.is_empty() {
                return Some(s);
            }
            None
        }
        Err(_) => {
            warn!("Could not get ip netns name from stdout!");
            None
        }
    }
}
