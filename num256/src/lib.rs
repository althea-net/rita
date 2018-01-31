extern crate num;
extern crate pad;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

use pad::{Alignment, PadStr};
use std::fmt;
use num::bigint::{BigInt, BigUint, ToBigInt};
use std::ops::{Add, Deref, Mul, Sub};
use num::traits::ops::checked::{CheckedAdd, CheckedMul, CheckedSub};
use num::traits::Signed;
use serde::ser::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uint256(BigUint);

impl Deref for Uint256 {
    type Target = BigUint;

    fn deref(&self) -> &BigUint {
        &self.0
    }
}

impl From<Int256> for Uint256 {
    fn from(n: Int256) -> Self {
        Uint256(n.abs().to_biguint().unwrap())
    }
}

macro_rules! impl_from_uint {
    ($T:ty) => {
        impl From<$T> for Uint256 {
            #[inline]
            fn from(n: $T) -> Self {
                Uint256(BigUint::from(n))
            }
        }
    }
}

impl_from_uint!(u8);
impl_from_uint!(u16);
impl_from_uint!(u32);
impl_from_uint!(u64);
impl_from_uint!(usize);

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_str_radix(10))
    }
}

impl Serialize for Uint256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str_radix(10))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Uint256 {
    fn deserialize<D>(deserializer: D) -> Result<Uint256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;

        BigUint::from_str(s)
            .map(|v| Uint256(v))
            .map_err(serde::de::Error::custom)
    }
}

impl Add for Uint256 {
    type Output = Uint256;
    fn add(self, v: Uint256) -> Uint256 {
        let num = self.0 + v.0;
        if num.bits() > 256 {
            panic!("overflow");
        }
        Uint256(num)
    }
}

impl CheckedAdd for Uint256 {
    fn checked_add(&self, v: &Uint256) -> Option<Uint256> {
        let num = self.0.clone() + v.0.clone();
        if num.bits() > 256 {
            return None;
        }
        Some(Uint256(num))
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Int256(BigInt);

impl Deref for Int256 {
    type Target = BigInt;

    fn deref(&self) -> &BigInt {
        &self.0
    }
}

impl From<Uint256> for Int256 {
    fn from(n: Uint256) -> Self {
        let num = n.to_bigint().unwrap();
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

macro_rules! impl_from_int {
    ($T:ty) => {
        impl From<$T> for Int256 {
            #[inline]
            fn from(n: $T) -> Self {
                Int256(BigInt::from(n))
            }
        }
    }
}

impl_from_int!(i8);
impl_from_int!(i16);
impl_from_int!(i32);
impl_from_int!(i64);
impl_from_int!(isize);

impl Serialize for Int256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str_radix(10))
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for Int256 {
    fn deserialize<D>(deserializer: D) -> Result<Int256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;

        BigInt::from_str(s)
            .map(|v| Int256(v))
            .map_err(serde::de::Error::custom)
    }
}

impl Add for Int256 {
    type Output = Int256;
    fn add(self, v: Int256) -> Int256 {
        let num = self.0 + v.0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl CheckedAdd for Int256 {
    fn checked_add(&self, v: &Int256) -> Option<Int256> {
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() + v.0.clone();
        if num.bits() > 255 {
            return None;
        }
        Some(Int256(num))
    }
}

impl Sub for Int256 {
    type Output = Int256;
    fn sub(self, v: Int256) -> Int256 {
        let num = self.0 - v.0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl CheckedSub for Int256 {
    fn checked_sub(&self, v: &Int256) -> Option<Int256> {
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() - v.0.clone();
        if num.bits() > 255 {
            return None;
        }
        Some(Int256(num))
    }
}

impl Mul for Int256 {
    type Output = Int256;
    fn mul(self, v: Int256) -> Int256 {
        let num = self.0 * v.0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl CheckedMul for Int256 {
    fn checked_mul(&self, v: &Int256) -> Option<Int256> {
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() * v.0.clone();
        if num.bits() > 255 {
            return None;
        }
        Some(Int256(num))
    }
}

impl fmt::Display for Int256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_str_radix(10))
    }
}

pub trait PaddedHex {
    fn to_padded_hex(&self) -> String;
}

impl PaddedHex for Int256 {
    fn to_padded_hex(&self) -> String {
        let num_size = 64;
        //the number of  characters to be same size as in Web3
        //The number 64 is just the number of characters in Int256 when converted to hex
        let hex_str = format!("{}", self::to_str_radix(16));
        //Converts to hex and added padding to align with ethereum int256
        hex_str.pad(num_size, '0', Alignment::Right, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::pow::pow;
    use num::traits::ops::checked::{CheckedAdd, CheckedSub};
    use num::traits::cast::ToPrimitive;
    use serde_json;

    lazy_static! {
      static ref BIGGEST_UINT: Uint256 =
        Uint256(pow(BigUint::from(2 as u32), 256) - BigUint::from(1 as u32));

      static ref BIGGEST_INT: Int256 = Int256(pow(BigInt::from(2), 255) - BigInt::from(1));

      static ref SMALLEST_INT: Int256 = Int256(pow(BigInt::from(-2), 255) + BigInt::from(1));

      static ref BIGGEST_INT_AS_UINT: Uint256 =
        Uint256(pow(BigUint::from(2 as u32), 255) - BigUint::from(1 as u32));
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct MyStruct {
        uint: Uint256,
        int: Int256,
    }

    #[test]
    fn serialize() {
        let struc = MyStruct {
            uint: BIGGEST_UINT.clone(),
            int: SMALLEST_INT.clone(),
        };

        let expected = "{\"uint\":\"115792089237316195423570985008687907853269984665640564039457584007913129639935\",\"int\":\"-57896044618658097711785492504343953926634992332820282019728792003956564819967\"}";

        let j = serde_json::to_string(&struc).unwrap();

        assert_eq!(expected, j);
        let m: MyStruct = serde_json::from_str(expected).unwrap();

        assert_eq!(BIGGEST_UINT.clone(), m.uint);
        assert_eq!(SMALLEST_INT.clone(), m.int);
    }

    #[test]
    fn test_from_uint() {
        let (a, b, c, d, e) = (
            Uint256::from(8 as u8),
            Uint256::from(8 as u16),
            Uint256::from(8 as u32),
            Uint256::from(8 as u64),
            Uint256::from(8 as usize),
        );

        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
        assert_eq!(d, e);
    }

    #[test]
    fn test_from_int() {
        let (a, b, c, d, e) = (
            Int256::from(-8 as i8),
            Int256::from(-8 as i16),
            Int256::from(-8 as i32),
            Int256::from(-8 as i64),
            Int256::from(-8 as isize),
        );

        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
        assert_eq!(d, e);
    }

    #[test]
    #[should_panic]
    fn test_uint_add_panic() {
        BIGGEST_UINT.clone() + Uint256::from(1 as u32);
    }

    #[test]
    fn test_uint_add_no_panic() {
        BIGGEST_UINT.clone() + Uint256::from(0 as u32);
    }

    #[test]
    #[should_panic]
    fn test_uint_sub_panic() {
        &Uint256::from(1 as u32).sub(Uint256::from(2 as u32));
    }

    #[test]
    fn test_uint_sub_no_panic() {
        assert_eq!(
            Uint256::from(1 as u32).sub(Uint256::from(1 as u32)),
            Uint256::from(0 as u32)
        );
    }

    #[test]
    fn test_uint256() {
        assert!(
            BIGGEST_UINT.checked_add(&Uint256::from(1 as u32)).is_none(),
            "should return None adding 1 to biggest"
        );

        assert!(
            BIGGEST_UINT.checked_add(&Uint256::from(0 as u32)).is_some(),
            "should return Some adding 0 to biggest"
        );

        assert!(
            &Uint256::from(1 as u32)
                .checked_sub(&Uint256::from(2 as u32))
                .is_none(),
            "should return None if RHS is larger than LHS"
        );

        assert!(
            &Uint256::from(1 as u32)
                .checked_sub(&Uint256::from(1 as u32))
                .is_some(),
            "should return Some if RHS is not larger than LHS"
        );

        let num = &Uint256::from(1 as u32)
            .checked_sub(&Uint256::from(1 as u32))
            .unwrap()
            .to_u32()
            .unwrap();

        assert_eq!(*num, 0, "1 - 1 should = 0");

        let num2 = &Uint256::from(346 as u32)
            .checked_sub(&Uint256::from(23 as u32))
            .unwrap()
            .to_u32()
            .unwrap();

        assert_eq!(*num2, 323, "346 - 23 should = 323");
    }

    #[test]
    #[should_panic]
    fn test_int_add_panic() {
        BIGGEST_INT.clone() + Int256::from(1);
    }

    #[test]
    fn test_int_add_no_panic() {
        BIGGEST_INT.clone() + Int256::from(0);
    }

    #[test]
    #[should_panic]
    fn test_int_sub_panic() {
        SMALLEST_INT.clone().sub(Int256::from(1));
    }

    #[test]
    fn test_int_sub_no_panic() {
        assert_eq!(Int256::from(1).sub(Int256::from(1)), Int256::from(0));
    }

    #[test]
    #[should_panic]
    fn test_int_mul_panic() {
        SMALLEST_INT.clone().mul(Int256::from(2));
    }

    #[test]
    fn test_int_mul_no_panic() {
        assert_eq!(Int256::from(3).mul(Int256::from(2)), Int256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_uint_to_int_panic() {
        Int256::from(BIGGEST_INT_AS_UINT.clone().add(Uint256::from(1 as u32)));
    }

    #[test]
    fn test_int256() {
        assert_eq!(
            Int256::from(BIGGEST_INT_AS_UINT.clone().add(Uint256::from(0 as u32))),
            BIGGEST_INT.clone()
        );

        assert!(
            BIGGEST_INT.checked_add(&Int256::from(1)).is_none(),
            "should return None adding 1 to biggest"
        );
        assert!(
            BIGGEST_INT.checked_add(&Int256::from(0)).is_some(),
            "should return Some adding 0 to biggest"
        );

        assert!(
            SMALLEST_INT.checked_sub(&Int256::from(1)).is_none(),
            "should return None subtracting 1 from smallest"
        );
        assert!(
            SMALLEST_INT.checked_sub(&Int256::from(0)).is_some(),
            "should return Some subtracting 0 from smallest"
        );

        assert!(SMALLEST_INT.checked_mul(&Int256::from(2)).is_none());
        assert!(SMALLEST_INT.checked_mul(&Int256::from(1)).is_some());

        let num = &Int256::from(345)
            .checked_sub(&Int256::from(44))
            .unwrap()
            .to_u32()
            .unwrap();

        assert_eq!(*num, 301, "345 - 44 should = 301");
    }
}
