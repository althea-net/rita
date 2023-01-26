use std::str::from_utf8;

use althea_kernel_interface::{KernelInterfaceError, KI};

use crate::NamespaceInfo;

pub fn test_reach_all(nsinfo: NamespaceInfo) -> Result<u16, KernelInterfaceError> {
    let mut count: u16 = 0;
    for i in nsinfo.clone().names {
        for j in nsinfo.clone().names {
            if test_reach(i.clone(), j) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn test_reach(from: (String, u32), to: (String, u32)) -> bool {
    // ip netns exec n-1 ping6 fd00::2
    let ip = format!("fd00::{}", to.1);
    let errormsg = format!("Could not run ping6 from {} to {}", from.0, to.0);
    let output = KI
        .run_command("ip", &["netns", "exec", &from.0, "ping6", &ip, "-c", "1"])
        .expect(&errormsg);
    let output = from_utf8(&output.stdout).expect("could not get output for ping6!");
    println!("ping output: {:?} end", output);
    output.contains("1 packets transmitted, 1 received, 0% packet loss")
}
