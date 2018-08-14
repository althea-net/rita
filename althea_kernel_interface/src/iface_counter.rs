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

#[test]
fn test_read_iface_counters() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    use KI;
    /*


*/

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "iptables");
                assert_eq!(args, vec!["-w", "-L", "eth0-counter", "-Z", "-x", "-v"]);
                Ok(Output {
                    stdout: b"Chain eth0-counter (2 references)
    pkts      bytes target     prot opt in     out     source               destination         
     4567  123456            all  --  any    eth1    anywhere             anywhere            
     201   455840            all  --  any    eth0    anywhere             anywhere            
      87     5873            all  --  eth0   any     anywhere             anywhere            
     288   461713 RETURN     all  --  any    any     anywhere             anywhere
     42    6666              all  --  eth1    any    anywhere             anywhere"
                        .to_vec(),
                    stderr: b"".to_vec(),
                    status: ExitStatus::from_raw(0),
                })
            }
            _ => panic!("Unexpected call {} {:?} {:?}", counter, program, args),
        }
    }));
    let ((input_bytes, input_packets), (output_bytes, output_packets)) = KI
        .read_iface_counters("eth0")
        .expect("Unable to parse iface counters");

    assert_eq!(input_bytes, 5873);
    assert_eq!(input_packets, 87);
    assert_eq!(output_bytes, 455840);
    assert_eq!(output_packets, 201);
}
