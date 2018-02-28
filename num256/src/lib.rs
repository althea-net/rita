extern crate num;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

use std::fmt;
use num::bigint::{BigInt, BigUint, ToBigInt};
use std::ops::{Add, AddAssign, Deref, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use num::traits::ops::checked::{CheckedAdd, CheckedDiv, CheckedMul, CheckedSub};
use num::traits::Signed;
use serde::ser::Serialize;
use serde::{Deserialize, Deserializer, Serializer};
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uint256(BigUint);

impl Deref for Uint256 {
    type Target = BigUint;

    fn deref(&self) -> &BigUint {
        &self.0
    }
}

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_str_radix(10))
    }
}

impl fmt::Debug for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Uint256({})", self.to_string())
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

impl<'de> Deserialize<'de> for Uint256 {
    fn deserialize<D>(deserializer: D) -> Result<Uint256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.clone();

        BigUint::from_str(&s)
            .map(|v| Uint256(v))
            .map_err(serde::de::Error::custom)
    }
}

impl Neg for Uint256 where {
    type Output = Int256;
    fn neg(self) -> Self::Output {
        let out = self.clone();
        Int256(out.0.to_bigint().unwrap() * -1)
    }
}

impl<T> Add<T> for Uint256
where
    T: Into<Int256>,
{
    type Output = Uint256;
    fn add(self, v: T) -> Uint256 {
        let num = (self.0.to_bigint().unwrap() + v.into().0)
            .to_biguint()
            .unwrap();
        if num.bits() > 256 {
            panic!("overflow");
        }
        Uint256(num)
    }
}

impl<T> AddAssign<T> for Uint256
where
    T: Into<Int256>,
{
    fn add_assign(&mut self, v: T) {
        self.0 = (self.0.clone().to_bigint().unwrap() + v.into().0)
            .to_biguint()
            .unwrap();
        if self.0.bits() > 256 {
            panic!("overflow");
        }
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

impl<T> Sub<T> for Uint256
where
    T: Into<Int256>,
{
    type Output = Uint256;
    fn sub(self, v: T) -> Uint256 {
        let num = (self.0.to_bigint().unwrap() - v.into().0)
            .to_biguint()
            .unwrap();
        Uint256(num)
    }
}

impl<T> SubAssign<T> for Uint256
where
    T: Into<Int256>,
{
    fn sub_assign(&mut self, v: T) {
        self.0 = (self.0.clone().to_bigint().unwrap() - v.into().0)
            .to_biguint()
            .unwrap();
        if self.0.bits() > 256 {
            panic!("overflow");
        }
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

impl<T> Mul<T> for Uint256
where
    T: Into<Uint256>,
{
    type Output = Uint256;
    fn mul(self, v: T) -> Uint256 {
        let num = self.0 * v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Uint256(num)
    }
}

impl<T> MulAssign<T> for Uint256
where
    T: Into<Uint256>,
{
    fn mul_assign(&mut self, v: T) {
        self.0 = self.0.clone() * v.into().0;
        if self.0.bits() > 256 {
            panic!("overflow");
        }
    }
}

impl CheckedMul for Uint256 {
    fn checked_mul(&self, v: &Uint256) -> Option<Uint256> {
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() * v.0.clone();
        if num.bits() > 255 {
            return None;
        }
        Some(Uint256(num))
    }
}

impl<T> Div<T> for Uint256
where
    T: Into<Uint256>,
{
    type Output = Uint256;
    fn div(self, v: T) -> Uint256 {
        let num = self.0 / v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Uint256(num)
    }
}

impl<T> DivAssign<T> for Uint256
where
    T: Into<Uint256>,
{
    fn div_assign(&mut self, v: T) {
        self.0 = self.0.clone() / v.into().0;
        if self.0.bits() > 256 {
            panic!("overflow");
        }
    }
}

impl CheckedDiv for Uint256 {
    fn checked_div(&self, v: &Uint256) -> Option<Uint256> {
        if *v == Uint256::from(0) {
            return None;
        }
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() / v.0.clone();
        Some(Uint256(num))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Int256(BigInt);

impl Int256 {
    pub fn abs(&self) -> Self {
        Int256(self.clone().0.abs())
    }
}

impl Deref for Int256 {
    type Target = BigInt;

    fn deref(&self) -> &BigInt {
        &self.0
    }
}

impl Neg for Int256 where {
    type Output = Int256;
    fn neg(self) -> Self::Output {
        let out = self.clone();
        Int256(out.0.to_bigint().unwrap() * -1)
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

impl From<Int256> for Uint256 {
    fn from(n: Int256) -> Self {
        let num = n.to_bigint().unwrap();
        if num.bits() > 256 {
            panic!("overflow");
        }
        Uint256(num.to_biguint().unwrap())
    }
}

impl From<BigUint> for Uint256 {
    fn from(n: BigUint) -> Self {
        if n.bits() > 256 {
            panic!("Overflow")
        }
        Uint256(n)
    }
}

impl From<BigInt> for Uint256 {
    fn from(n: BigInt) -> Self {
        if n.bits() > 256 {
            panic!("Overflow")
        }
        Uint256::from(Int256(n.abs()))
    }
}

impl From<BigUint> for Int256 {
    fn from(n: BigUint) -> Self {
        if n.bits() > 256 {
            panic!("Overflow")
        }
        Int256(n.to_bigint().unwrap())
    }
}

impl From<BigInt> for Int256 {
    fn from(n: BigInt) -> Self {
        if n.bits() > 256 {
            panic!("Overflow")
        }
        Int256(n)
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

        impl From<$T> for Uint256 {
            #[inline]
            fn from(n: $T) -> Self {
                if n.is_negative(){
                    panic!("negative")
                }
                Uint256(BigUint::from(n as u64))
            }
        }
    }
}

macro_rules! impl_from_uint {
    ($T:ty) => {
        impl From<$T> for Int256 {
            #[inline]
            fn from(n: $T) -> Self {
                Int256(BigInt::from(n))
            }
        }

        impl From<$T> for Uint256 {
            #[inline]
            fn from(n: $T) -> Self {
                Uint256(BigUint::from(n as u64))
            }
        }
    }
}

impl_from_int!(i8);
impl_from_int!(i16);
impl_from_int!(i32);
impl_from_int!(i64);
impl_from_int!(isize);
impl_from_uint!(u8);
impl_from_uint!(u16);
impl_from_uint!(u32);
impl_from_uint!(u64);
impl_from_uint!(usize);

impl<'a> From<&'a Int256> for Int256 {
    fn from(n: &Int256) -> Int256 {
        n.clone()
    }
}

impl<'a> From<&'a Uint256> for Uint256 {
    fn from(n: &Uint256) -> Uint256 {
        n.clone()
    }
}

impl<'a> From<&'a Int256> for Uint256 {
    fn from(n: &Int256) -> Uint256 {
        n.clone().into()
    }
}

impl<'a> From<&'a Uint256> for Int256 {
    fn from(n: &Uint256) -> Int256 {
        n.clone().into()
    }
}

impl fmt::Display for Int256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.to_str_radix(10))
    }
}

impl fmt::Debug for Int256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Int256({})", self.to_string())
    }
}

impl Serialize for Int256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str_radix(10))
    }
}

impl<'de> Deserialize<'de> for Int256 {
    fn deserialize<D>(deserializer: D) -> Result<Int256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        BigInt::from_str(&s)
            .map(|v| Int256(v))
            .map_err(serde::de::Error::custom)
    }
}

impl<T> Add<T> for Int256
where
    T: Into<Int256>,
{
    type Output = Int256;
    fn add(self, v: T) -> Int256 {
        let num = self.0 + v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl<T> AddAssign<T> for Int256
where
    T: Into<Int256>,
{
    fn add_assign(&mut self, v: T) {
        self.0 = self.0.clone() + v.into().0;
        if self.0.bits() > 255 {
            panic!("overflow");
        }
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

impl<T> Sub<T> for Int256
where
    T: Into<Int256>,
{
    type Output = Int256;
    fn sub(self, v: T) -> Int256 {
        let num = self.0 - v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl<T> SubAssign<T> for Int256
where
    T: Into<Int256>,
{
    fn sub_assign(&mut self, v: T) {
        self.0 = self.0.clone() - v.into().0;
        if self.0.bits() > 255 {
            panic!("overflow");
        }
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

impl<T> Mul<T> for Int256
where
    T: Into<Int256>,
{
    type Output = Int256;
    fn mul(self, v: T) -> Int256 {
        let num = self.0 * v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl<T> MulAssign<T> for Int256
where
    T: Into<Int256>,
{
    fn mul_assign(&mut self, v: T) {
        self.0 = self.0.clone() * v.into().0;
        if self.0.bits() > 255 {
            panic!("overflow");
        }
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

impl<T> DivAssign<T> for Int256
where
    T: Into<Int256>,
{
    fn div_assign(&mut self, v: T) {
        self.0 = self.0.clone() / v.into().0;
        if self.0.bits() > 255 {
            panic!("overflow");
        }
    }
}

impl<T> Div<T> for Int256
where
    T: Into<Int256>,
{
    type Output = Int256;
    fn div(self, v: T) -> Int256 {
        let num = self.0 / v.into().0;
        if num.bits() > 255 {
            panic!("overflow");
        }
        Int256(num)
    }
}

impl CheckedDiv for Int256 {
    fn checked_div(&self, v: &Int256) -> Option<Int256> {
        if *v == Int256::from(0) {
            return None;
        }
        // drop down to wrapped bigint to stop from panicing in fn above
        let num = self.0.clone() / v.0.clone();
        Some(Int256(num))
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
    fn test_uint_add_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big += Uint256::from(1 as u32);
    }

    #[test]
    fn test_uint_add_assign_no_panic() {
        let mut big = BIGGEST_UINT.clone();
        big += Uint256::from(0 as u32);
    }

    #[test]
    #[should_panic]
    fn test_uint_from_add_panic() {
        BIGGEST_UINT.clone() + 1;
    }

    #[test]
    fn test_uint_from_add_no_panic() {
        BIGGEST_UINT.clone() + 0;
    }

    #[test]
    #[should_panic]
    fn test_uint_from_add_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big += Uint256::from(1);
    }

    #[test]
    fn test_uint_from_add_assign_no_panic() {
        let mut big = BIGGEST_UINT.clone();
        big += Uint256::from(0);
    }

    #[test]
    #[should_panic]
    fn test_uint_sub_panic() {
        Uint256::from(1 as u32) - Uint256::from(2 as u32);
    }

    #[test]
    fn test_uint_sub_no_panic() {
        assert_eq!(
            Uint256::from(1 as u32) - Uint256::from(1 as u32),
            Uint256::from(0 as u32)
        );
    }

    #[test]
    #[should_panic]
    fn test_uint_sub_assign_panic() {
        let mut small = Uint256::from(1 as u32);
        small -= Uint256::from(2);
    }

    #[test]
    fn test_uint_sub_assign_no_panic() {
        let mut small = Uint256::from(1 as u32);
        small -= Uint256::from(1);
        assert_eq!(small, Uint256::from(0 as u32));
    }

    #[test]
    fn test_uint_from_sub_assign_no_panic() {
        let mut small = Uint256::from(1 as u32);
        small -= 1;
        assert_eq!(small, Uint256::from(0 as u32));
    }

    #[test]
    #[should_panic]
    fn test_uint_from_sub_assign_panic() {
        let mut small = Uint256::from(1 as u32);
        small -= 2;
    }

    #[test]
    #[should_panic]
    fn test_uint_from_sub_panic() {
        Uint256::from(1 as u32) - 2;
    }

    #[test]
    fn test_uint_from_sub_no_panic() {
        assert_eq!(Uint256::from(1 as u32) - 1, Uint256::from(0 as u32));
    }

    #[test]
    #[should_panic]
    fn test_uint_mul_panic() {
        BIGGEST_UINT.clone() * Int256::from(2);
    }

    #[test]
    fn test_uint_mul_no_panic() {
        assert_eq!(Uint256::from(3) * Uint256::from(2), Uint256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_uint_mul_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big *= Int256::from(2);
    }

    #[test]
    fn test_uint_mul_assign_no_panic() {
        let mut num = Uint256::from(3);
        num *= Uint256::from(2);
        assert_eq!(num, Uint256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_uint_from_mul_panic() {
        BIGGEST_UINT.clone() * 2;
    }

    #[test]
    fn test_uint_from_mul_no_panic() {
        assert_eq!(Uint256::from(3) * 2, Uint256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_uint_from_mul_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big *= 2;
    }

    #[test]
    fn test_uint_from_mul_assign_no_panic() {
        let mut num = Uint256::from(3);
        num *= 2;
        assert_eq!(num, Uint256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_uint_div_panic() {
        BIGGEST_UINT.clone() / Uint256::from(0);
    }

    #[test]
    fn test_uint_div_no_panic() {
        assert_eq!(Uint256::from(6) / Uint256::from(2), Uint256::from(3));
    }

    #[test]
    #[should_panic]
    fn test_uint_div_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big /= Uint256::from(0);
    }

    #[test]
    fn test_uint_from_div_assign_no_panic() {
        assert_eq!(Uint256::from(6) / 2, Uint256::from(3));
    }

    #[test]
    #[should_panic]
    fn test_uint_from_div_panic() {
        BIGGEST_UINT.clone() / 0;
    }

    #[test]
    fn test_uint_from_div_no_panic() {
        assert_eq!(Uint256::from(6) / 2, Uint256::from(3));
    }

    #[test]
    #[should_panic]
    fn test_uint_from_div_assign_panic() {
        let mut big = BIGGEST_UINT.clone();
        big /= 0;
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
        SMALLEST_INT.clone() - Int256::from(1);
    }

    #[test]
    fn test_int_sub_no_panic() {
        assert_eq!(Int256::from(1) - Int256::from(1), Int256::from(0));
    }

    #[test]
    #[should_panic]
    fn test_int_mul_panic() {
        SMALLEST_INT.clone() * Int256::from(2);
    }

    #[test]
    fn test_int_mul_no_panic() {
        assert_eq!(Int256::from(3) * Int256::from(2), Int256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_int_div_panic() {
        SMALLEST_INT.clone() / Int256::from(0);
    }

    #[test]
    fn test_int_div_no_panic() {
        assert_eq!(Int256::from(6) / Int256::from(2), Int256::from(3));
    }

    #[test]
    #[should_panic]
    fn test_int_from_add_panic() {
        BIGGEST_INT.clone() + 1;
    }

    #[test]
    fn test_int_from_add_no_panic() {
        BIGGEST_INT.clone() + 0;
    }

    #[test]
    #[should_panic]
    fn test_int_from_sub_panic() {
        SMALLEST_INT.clone() - 1;
    }

    #[test]
    fn test_int_from_sub_no_panic() {
        assert_eq!(Int256::from(1) - 1, Int256::from(0));
    }

    #[test]
    #[should_panic]
    fn test_int_from_mul_panic() {
        SMALLEST_INT.clone() * 2;
    }

    #[test]
    fn test_int_from_mul_no_panic() {
        assert_eq!(Int256::from(3) * 2, Int256::from(6));
    }

    #[test]
    #[should_panic]
    fn test_int_from_div_panic() {
        SMALLEST_INT.clone() / 0;
    }

    #[test]
    fn test_int_from_div_no_panic() {
        assert_eq!(Int256::from(6) / 2, Int256::from(3));
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
