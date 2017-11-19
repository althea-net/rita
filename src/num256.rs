use num::bigint::{BigInt, BigUint};
use std::ops::{Add, Deref, Sub};
use num::traits::ops::checked::{CheckedAdd, CheckedSub};

#[derive(Clone)]
pub struct Uint256(BigUint);

impl Deref for Uint256 {
  type Target = BigUint;

  fn deref(&self) -> &BigUint {
    &self.0
  }
}

impl Add for Uint256 {
  type Output = Uint256;
  fn add(self, v: Uint256) -> Uint256 {
    Uint256(self.0 + v.0)
  }
}

impl CheckedAdd for Uint256 {
  fn checked_add(&self, v: &Uint256) -> Option<Uint256> {
    let num = self.clone() + v.clone();
    if num.bits() > 256 {
      return None;
    }
    Some(num)
  }
}

impl Sub for Uint256 {
  type Output = Uint256;
  fn sub(self, v: Uint256) -> Uint256 {
    Uint256(self.0 - v.0)
  }
}

impl CheckedSub for Uint256 {
  fn checked_sub(&self, v: &Uint256) -> Option<Uint256> {
    if self.0 < v.0 {
      return None;
    }
    let num = self.clone() - v.clone();
    Some(num)
  }
}

#[derive(Clone)]
pub struct Int256(BigInt);

impl Deref for Int256 {
  type Target = BigInt;

  fn deref(&self) -> &BigInt {
    &self.0
  }
}

impl Add for Int256 {
  type Output = Int256;
  fn add(self, v: Int256) -> Int256 {
    Int256(self.0 + v.0)
  }
}

impl CheckedAdd for Int256 {
  fn checked_add(&self, v: &Int256) -> Option<Int256> {
    let num = self.clone() + v.clone();
    if num.bits() > 256 {
      return None;
    }
    Some(num)
  }
}

impl Sub for Int256 {
  type Output = Int256;
  fn sub(self, v: Int256) -> Int256 {
    Int256(self.0 - v.0)
  }
}

impl CheckedSub for Int256 {
  fn checked_sub(&self, v: &Int256) -> Option<Int256> {
    if self.0 < v.0 {
      return None;
    }
    let num = self.clone() - v.clone();
    Some(num)
  }
}


#[cfg(test)]
mod tests {
  use num256::{BigInt, BigUint, Int256, Uint256};
  use num::pow::pow;
  use num::traits::ops::checked::{CheckedAdd, CheckedSub};
  use std::ops::Sub;
  use num::traits::cast::ToPrimitive;
  #[test]
  fn test_uint256() {
    let biggest = Uint256(pow(BigUint::from(2 as u32), 256) - BigUint::from(1 as u32));

    assert!(
      biggest
        .checked_add(&Uint256(BigUint::from(1 as u32)))
        .is_none()
    );

    assert!(
      biggest
        .checked_add(&Uint256(BigUint::from(0 as u32)))
        .is_some()
    );

    assert!(&Uint256(BigUint::from(1 as u32))
      .checked_sub(&Uint256(BigUint::from(2 as u32)))
      .is_none());

    assert!(&Uint256(BigUint::from(1 as u32))
      .checked_sub(&Uint256(BigUint::from(1 as u32)))
      .is_some());

    let num = &Uint256(BigUint::from(1 as u32))
      .checked_sub(&Uint256(BigUint::from(1 as u32)))
      .unwrap()
      .to_u32()
      .unwrap();

    assert_eq!(*num, 0);

    let num2 = &Uint256(BigUint::from(346 as u32))
      .checked_sub(&Uint256(BigUint::from(23 as u32)))
      .unwrap()
      .to_u32()
      .unwrap();

    assert_eq!(*num2, 323);
  }

  #[test]
  fn test_int256() {
    let biggest = Int256(pow(BigInt::from(2 as u32), 255) - BigInt::from(1 as u32));
    let smallest = Int256(pow(BigInt::from(-2 as i32), 255));

    let bigger = biggest
      .checked_add(&Int256(BigInt::from(100000 as u32)))
      .unwrap();

    // This is where i'm working
    println!(
      "biggest {:?}, bits {:?}",
      &biggest.to_str_radix(10),
      &biggest.bits()
    );
    println!(
      "bigger {:?}, bits {:?}",
      &bigger.to_str_radix(10),
      &biggest.bits()
    );

    assert!(
      biggest
        .checked_add(&Int256(BigInt::from(2 as u32)))
        .is_none()
    );
    assert!(
      biggest
        .checked_add(&Int256(BigInt::from(0 as u32)))
        .is_some()
    );

    assert!(
      smallest
        .checked_sub(&Int256(BigInt::from(1 as u32)))
        .is_none()
    );
    assert!(
      smallest
        .checked_sub(&Int256(BigInt::from(0 as u32)))
        .is_some()
    );

    let num = &Int256(BigInt::from(1 as u32))
      .checked_sub(&Int256(BigInt::from(1 as u32)))
      .unwrap()
      .to_u32()
      .unwrap();

    assert_eq!(*num, 0);
  }
}
