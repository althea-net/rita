use crate::KernelInterface;
use crate::KernelInterfaceError;

impl dyn KernelInterface {
    pub fn check_lan_forward_exists(&self) -> Result<bool, KernelInterfaceError> {
        match self.run_command(
            "nft",
            &[
                "list",
                "table",
                "inet",
                "fw4",
                "|",
                "grep",
                "'iifname \"br-lan\" oifname \"wg_exit\"'",
            ],
        ) {
            Ok(res) => {
                info!("NAT FORWARD FIND {:?}", res.stdout);
                Ok(!res.stdout.is_empty())
            }
            Err(err) => {
                info!("NAT FORWARD FIND ERR {:?}", err);
                Err(err)
            }
        }
    }

    pub fn add_lan_forward(&self) -> Result<(), KernelInterfaceError> {
        if self.check_lan_forward_exists()? {
            return Ok(());
        }
        self.run_command(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                "fw4",
                "forward",
                "iifname",
                "\"br-lan\"",
                "oifname",
                "\"wg_exit\"",
                "counter",
                "accept",
            ],
        )?;
        Ok(())
    }

    pub fn delete_lan_forward(&self) -> Result<(), KernelInterfaceError> {
        if !self.check_lan_forward_exists()? {
            return Ok(());
        }

        match self.run_command(
            "nft",
            &[
                "-a",
                "list",
                "table",
                "inet",
                "fw4",
                "|",
                "grep",
                "'iifname \"br-lan\" oifname \"wg_exit\"'",
                "|",
                "sed",
                "'s,^.*handle ,,'",
            ],
        ) {
            Ok(res) => {
                info!("NAT FORWARD HANDLE {:?}", res.stdout);
                if !res.stdout.is_empty() {
                    let handle_str = String::from_utf8(res.stdout)?;
                    self.run_command(
                        "nft",
                        &[
                            "delete",
                            "rule",
                            "inet",
                            "fw4",
                            "handle",
                            handle_str.as_str(),
                        ],
                    )?;
                }
            }
            Err(err) => info!("NAT FORWARD ERR {:?}", err),
        }

        Ok(())
    }

    pub fn check_nat_table_exists(&self) -> Result<bool, KernelInterfaceError> {
        let res = self.run_command("nft", &["list", "table", "nat"])?;
        Ok(!res.stdout.is_empty())
    }

    /// This only needs to happen once on startup.
    pub fn init_nat_chain(&self) -> Result<(), KernelInterfaceError> {
        // if the table already exists, then exit
        if self.check_nat_table_exists()? {
            return Ok(());
        }

        self.run_command("nft", &["add", "table", "nat"])?;
        match self.run_command(
            "nft",
            &[
                "add",
                "chain",
                "nat",
                "postrouting",
                "'{ type nat hook postrouting priority 100 ; }'",
            ],
        ) {
            Ok(res) => info!("NFT NAT RULE {:?}", res.stdout),
            Err(err) => info!("NFT NAT ERROR {:?}", err),
        };
        self.run_command(
            "nft",
            &[
                "add",
                "rule",
                "nat",
                "postrouting",
                "oifname",
                "wg_exit",
                "masquerade",
            ],
        )?;
        Ok(())
    }
}

#[test]
fn test_nftables() {
    use crate::KI;

    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::process::Output;

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "nft");
        assert_eq!(
            args,
            &[
                "list",
                "table",
                "inet",
                "fw4",
                "|",
                "grep",
                "'iifname \"br-lan\" oifname \"wg_exit\"'",
            ]
        );

        Ok(Output {
            stdout: b"		iifname \"br-lan\" oifname \"wg_exit\" counter packets 3125119 bytes 334054054 accept".to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .check_lan_forward_exists()
        .expect("Failure to run nftables command");
    assert!(val);

    KI.set_mock(Box::new(move |program, args| {
        assert_eq!(program, "nft");
        assert_eq!(args, &["list", "table", "nat"]);

        Ok(Output {
            stdout: b"table ip nat {...}".to_vec(),
            stderr: b"".to_vec(),
            status: ExitStatus::from_raw(0),
        })
    }));
    let val = KI
        .check_nat_table_exists()
        .expect("Failure to run nftables command");
    assert!(val);
}
