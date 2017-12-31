#[macro_use]
extern crate derive_error;

extern crate althea_types;
extern crate num256;
extern crate stash;

mod debts;

use debts::{Debt, Debts, Key};
use num256::Int256;

pub struct DebtKeeper {
    debts: Debts,
}

impl DebtKeeper {
    fn apply_debt(&mut self, key: Key, debt: Int256) {
        self.debts.get(key);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
