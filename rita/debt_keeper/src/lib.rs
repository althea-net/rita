#[macro_use]
extern crate derive_error;

extern crate althea_types;
extern crate num256;
extern crate stash;

mod debts;

#[derive(Debug, Error)]
pub enum Error {
    #[error(msg_embedded, no_from, non_std)] DebtKeeperError(String),
}

use debts::{Debt, Debts, Key};
use num256::Int256;

pub struct DebtKeeper {
    debts: Debts,
}

impl DebtKeeper {
    fn apply_debt(&mut self, key: Key, amount: Int256) -> Result<(), Error> {
        match self.debts.get(&key) {
            Some(mut debt) => {
                debt.amount = debt.amount + amount;
                Ok(self.debts.insert(debt))
            }
            None => Err(Error::DebtKeeperError(format!("No entry for {:?}", key))),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
