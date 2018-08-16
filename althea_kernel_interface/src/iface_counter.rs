use super::KernelInterface;

use failure::Error;

use regex::Regex;

pub struct IfaceCounter {
    pub bytes: u64,
    pub packets: u64,
}

impl IfaceCounter {
    pub fn new(bytes: u64, packets: u64) -> IfaceCounter {
        IfaceCounter { bytes, packets }
    }

    /// Return sum of bytes and packet times the overhead
    pub fn total_bytes(&self) -> u64 {
        self.bytes + self.packets * 80
    }
}

#[derive(Debug, Fail)]
enum IfaceCounterError {
    #[fail(display = "Unable to find counter for interface {}", name)]
    NoCounterForIfaceError { name: String },
}

#[test]
fn test_iface_counter_error() {
    let err: Error = IfaceCounterError::NoCounterForIfaceError {
        name: "iface".into(),
    }.into();
    assert_eq!(
        err.to_string(),
        "Unable to find counter for interface iface"
    );
}

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

    /// returns (input counters, output counters)
    pub fn read_iface_counters(
        &self,
        interface: &str,
    ) -> Result<(IfaceCounter, IfaceCounter), Error> {
        lazy_static! {
            static ref RE: Regex =
                Regex::new(r"(?m)^\s+(?P<pkts>\d+)\s+(?P<bytes>\d+)\s+all\s+--\s+(?P<in>.+?)\s+(?P<out>.+?)\s+")
                    .expect("Unable to compile regular expression");
        }
        let chain_name = format!("{}-counter", interface);

        let output = self.run_command("iptables", &["-w", "-L", &chain_name, "-Z", "-x", "-v"])?;

        let stdout = String::from_utf8(output.stdout)?;

        let mut input: Option<IfaceCounter> = None;
        let mut output: Option<IfaceCounter> = None;

        for caps in RE.captures_iter(&stdout) {
            if &caps["in"] == "any" && &caps["out"] == interface {
                output = Some(IfaceCounter::new(
                    caps["bytes"].parse()?,
                    caps["pkts"].parse()?,
                ));
            } else if &caps["in"] == interface && &caps["out"] == "any" {
                input = Some(IfaceCounter::new(
                    caps["bytes"].parse()?,
                    caps["pkts"].parse()?,
                ));
            }
        }

        if input.is_none() || output.is_none() {
            error!("Unable to parse iface counters: {:?}", stdout);
            return Err(IfaceCounterError::NoCounterForIfaceError {
                name: interface.into(),
            }.into());
        }

        // At this point its safe to unwrap optionals
        Ok((input.unwrap(), output.unwrap()))
    }
}

#[test]
fn test_read_iface_counters() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    use KI;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "iptables");
                assert_eq!(args, vec!["-w", "-L", "veth-5-8_weird^name-counter", "-Z", "-x", "-v"]);
                Ok(Output {
                    stdout: b"Chain veth-5-8_weird^name-counter (2 references)
    pkts      bytes target     prot opt in     out     source               destination         
     4567  123456            all  --  any    eth1    anywhere             anywhere            
     201   455840            all  --  any    veth-5-8_weird^name    anywhere             anywhere            
      87     5873            all  --  veth-5-8_weird^name   any     anywhere             anywhere            
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
    let (input_counter, output_counter) = KI
        .read_iface_counters("veth-5-8_weird^name")
        .expect("Unable to parse iface counters");

    assert_eq!(input_counter.bytes, 5873);
    assert_eq!(input_counter.packets, 87);
    assert_eq!(output_counter.bytes, 455840);
    assert_eq!(output_counter.packets, 201);
}

#[test]
fn test_read_iface_counters_with_missing_ifaces() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;
    use KI;

    let mut counter = 0;

    KI.set_mock(Box::new(move |program, args| {
        counter += 1;
        match counter {
            1 => {
                assert_eq!(program, "iptables");
                assert_eq!(
                    args,
                    vec!["-w", "-L", "veth-5-8_weird^name-counter", "-Z", "-x", "-v"]
                );
                Ok(Output {
                    stdout: b"Chain veth-5-8_weird^name-counter (2 references)
    pkts      bytes target     prot opt in     out     source               destination         
     4567  123456            all  --  any    eth1    anywhere             anywhere            
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
    let result = KI.read_iface_counters("veth-5-8_weird^name");
    match result {
        Err(err) => {
            let IfaceCounterError::NoCounterForIfaceError { name } = err
                .downcast::<IfaceCounterError>()
                .expect("Unable to downcast");
            assert_eq!(name, "veth-5-8_weird^name");
        }
        _ => assert!(false, "Invalid error"),
    }
}
