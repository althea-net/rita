extern crate num256;

use num256::Uint256;

pub enum DebtAction {
    CloseTunnel,
    MakePayment(Uint256),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
