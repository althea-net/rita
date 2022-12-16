use crate::KernelInterface;
use crate::KernelInterfaceError;
use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression},
    helper::{apply_ruleset, get_current_ruleset},
    schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table},
    stmt::{Match, Operator, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

impl dyn KernelInterface {
    fn create_fwd_rule(&self) -> Rule {
        Rule {
            family: NfFamily::INet,
            table: "fw4".to_string(),
            chain: "forward_lan".to_string(),
            expr: vec![Statement::Accept(None)],
            handle: None,
            index: None,
            comment: Some(String::from("Althea ipv4 LAN forward rule")),
        }
    }

    fn create_nat_table(&self, batch: &mut Batch) {
        batch.add(NfListObject::Table(Table::new(
            NfFamily::IP,
            "nat".to_string(),
        )));
        batch.add(NfListObject::Chain(Chain::new(
            NfFamily::IP,
            "nat".to_string(),
            "postrouting".to_string(),
            Some(NfChainType::NAT),
            Some(NfHook::Postrouting),
            Some(100),
            None,
            Some(NfChainPolicy::Accept),
        )));
        batch.add(NfListObject::Rule(Rule::new(
            NfFamily::IP,
            "nat".to_string(),
            "postrouting".to_string(),
            vec![
                Statement::Match(Match {
                    left: Expression::Named(NamedExpression::Meta(Meta {
                        key: MetaKey::Oifname,
                    })),
                    right: Expression::String("wg_exit".to_string()),
                    op: Operator::EQ,
                }),
                Statement::Masquerade(None),
            ],
        )));
    }

    fn get_lan_fwd_handle(&self, rules: &Nftables) -> Option<u32> {
        for obj in &rules.objects {
            if let NfObject::ListObject(NfListObject::Rule(rule)) = obj {
                if rule.table == *"fw4" && rule.chain == *"forward_lan" {
                    if let Some(Statement::Accept(Some(_))) = rule.expr.first() {
                        return rule.handle;
                    }
                }
            }
        }
        None
    }

    fn get_reject_rule_handle(&self, rules: &Nftables) -> Option<u32> {
        for obj in &rules.objects {
            if let NfObject::ListObject(NfListObject::Rule(rule)) = obj {
                if rule.table == *"fw4" && rule.chain == *"forward_lan" {
                    if let Some(Statement::Reject(Some(_))) = rule.expr.first() {
                        return rule.handle;
                    }
                }
            }
        }
        None
    }

    fn get_nat_table_handle(&self, rules: &Nftables) -> Option<u32> {
        for obj in &rules.objects {
            if let NfObject::ListObject(NfListObject::Table(table)) = obj {
                if table.name == *"nat" {
                    return table.handle;
                }
            }
        }
        None
    }

    pub fn insert_reject_rule(&self) -> Result<(), KernelInterfaceError> {
        let rules = get_current_ruleset(None, None);
        if self.get_reject_rule_handle(&rules).is_none() {
            let reject_rule = Nftables {
                objects: vec![NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(
                    Rule {
                        family: NfFamily::INet,
                        table: "fw4".to_string(),
                        chain: "forward_lan".to_string(),
                        expr: vec![Statement::Reject(None)],
                        handle: None,
                        index: None,
                        comment: Some(String::from("Althea LAN forward reject rule")),
                    },
                )))],
            };
            nftables::helper::apply_ruleset(&reject_rule, None, None)?;
        }
        Ok(())
    }

    pub fn delete_reject_rule(&self) -> Result<(), KernelInterfaceError> {
        let rules = get_current_ruleset(None, None);
        if let Some(handle) = self.get_reject_rule_handle(&rules) {
            let delete_rule = Nftables {
                objects: vec![NfObject::CmdObject(NfCmd::Delete(NfListObject::Rule(
                    Rule {
                        family: NfFamily::INet,
                        table: "fw4".to_string(),
                        chain: "forward_lan".to_string(),
                        expr: vec![Statement::Reject(None)],
                        handle: Some(handle),
                        index: None,
                        comment: None,
                    },
                )))],
            };
            nftables::helper::apply_ruleset(&delete_rule, None, None)?;
        }
        Ok(())
    }

    pub fn init_nat_chain(&self) -> Result<(), KernelInterfaceError> {
        let rules = get_current_ruleset(None, None);
        let mut batch = Batch::new();
        if self.get_nat_table_handle(&rules).is_none() {
            self.create_nat_table(&mut batch);
        }
        if self.get_lan_fwd_handle(&rules).is_none() {
            batch.add(NfListObject::Rule(self.create_fwd_rule()));
        }
        let ruleset = batch.to_nftables();
        apply_ruleset(&ruleset, None, None)?;

        Ok(())
    }
}
