use crate::{
    UnitId,
    kernel::{checked_add_u64, checked_div_u64, checked_mul_u64, checked_sub_u64},
};

/// Exact, dimensioned non-negative integer quantity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitQuantity {
    unit: UnitId,
    amount: u64,
}

impl UnitQuantity {
    /// Constructs an exact quantity.
    #[must_use]
    pub const fn new(unit: UnitId, amount: u64) -> Self {
        Self { unit, amount }
    }

    /// Returns the explicit dimension.
    #[must_use]
    pub const fn unit(&self) -> &UnitId {
        &self.unit
    }

    /// Returns the exact integer amount.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Adds same-dimension quantities with overflow rejection.
    pub fn checked_add(&self, right: &Self) -> Result<Self, ArithmeticError> {
        self.ensure_same_unit(right)?;
        let amount = checked_add_u64(self.amount, right.amount).ok_or(ArithmeticError::Overflow)?;
        Ok(Self::new(self.unit.clone(), amount))
    }

    /// Subtracts same-dimension quantities with underflow rejection.
    pub fn checked_sub(&self, right: &Self) -> Result<Self, ArithmeticError> {
        self.ensure_same_unit(right)?;
        let amount =
            checked_sub_u64(self.amount, right.amount).ok_or(ArithmeticError::Underflow)?;
        Ok(Self::new(self.unit.clone(), amount))
    }

    /// Multiplies by an exact scalar with overflow rejection.
    pub fn checked_mul(&self, scalar: u64) -> Result<Self, ArithmeticError> {
        let amount = checked_mul_u64(self.amount, scalar).ok_or(ArithmeticError::Overflow)?;
        Ok(Self::new(self.unit.clone(), amount))
    }

    /// Divides by an exact scalar, rejecting division by zero.
    pub fn checked_div(&self, scalar: u64) -> Result<Self, ArithmeticError> {
        let amount = checked_div_u64(self.amount, scalar).ok_or(ArithmeticError::DivisionByZero)?;
        Ok(Self::new(self.unit.clone(), amount))
    }

    fn ensure_same_unit(&self, right: &Self) -> Result<(), ArithmeticError> {
        if self.unit == right.unit {
            Ok(())
        } else {
            Err(ArithmeticError::IncompatibleUnit)
        }
    }
}

/// Closed basis-point percentage in the inclusive range 0..=10_000.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BasisPoints(u16);

impl BasisPoints {
    /// Constructs a V1 basis-point value.
    pub const fn new(value: u16) -> Result<Self, ArithmeticError> {
        if value <= 10_000 {
            Ok(Self(value))
        } else {
            Err(ArithmeticError::BasisPointsOutOfRange)
        }
    }

    /// Returns the exact number of basis points.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Explicit direction for a non-integral bounded result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundingDirection {
    /// Round toward zero.
    Down,
    /// Round away from zero when a remainder exists.
    Up,
}

/// Computes a basis-point fraction using a widened intermediate.
pub fn checked_basis_points(
    denominator: u64,
    basis_points: BasisPoints,
    rounding: RoundingDirection,
) -> Result<u64, ArithmeticError> {
    let numerator = u128::from(denominator)
        .checked_mul(u128::from(basis_points.value()))
        .ok_or(ArithmeticError::Overflow)?;
    let divisor = 10_000_u128;
    let quotient = numerator / divisor;
    let remainder = numerator % divisor;
    let rounded = match rounding {
        RoundingDirection::Down => quotient,
        RoundingDirection::Up if remainder > 0 => {
            quotient.checked_add(1).ok_or(ArithmeticError::Overflow)?
        }
        RoundingDirection::Up => quotient,
    };
    u64::try_from(rounded).map_err(|_| ArithmeticError::Overflow)
}

/// Stable checked-arithmetic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticError {
    /// Addition, multiplication, or rounding overflowed.
    Overflow,
    /// Subtraction would become negative.
    Underflow,
    /// Division by zero was requested.
    DivisionByZero,
    /// Quantities have different explicit dimensions.
    IncompatibleUnit,
    /// Percentage exceeds 100%.
    BasisPointsOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn quantity(unit: &str, amount: u64) -> UnitQuantity {
        UnitQuantity::new(UnitId::parse(unit).unwrap(), amount)
    }

    #[test]
    fn rejects_every_arithmetic_escape_hatch() {
        assert_eq!(
            quantity("usd-minor", u64::MAX).checked_add(&quantity("usd-minor", 1)),
            Err(ArithmeticError::Overflow)
        );
        assert_eq!(
            quantity("usd-minor", 0).checked_sub(&quantity("usd-minor", 1)),
            Err(ArithmeticError::Underflow)
        );
        assert_eq!(
            quantity("usd-minor", 1).checked_div(0),
            Err(ArithmeticError::DivisionByZero)
        );
        assert_eq!(
            quantity("usd-minor", 1).checked_add(&quantity("rows", 1)),
            Err(ArithmeticError::IncompatibleUnit)
        );
    }

    #[test]
    fn rounding_is_explicit_at_exact_and_fractional_boundaries() {
        let half = BasisPoints::new(5_000).unwrap();
        assert_eq!(
            checked_basis_points(5, half, RoundingDirection::Down),
            Ok(2)
        );
        assert_eq!(checked_basis_points(5, half, RoundingDirection::Up), Ok(3));
        assert_eq!(
            checked_basis_points(
                u64::MAX,
                BasisPoints::new(10_000).unwrap(),
                RoundingDirection::Up
            ),
            Ok(u64::MAX)
        );
    }

    proptest! {
        #[test]
        fn checked_add_agrees_with_widened_integer(left in any::<u64>(), right in any::<u64>()) {
            let result = quantity("units", left).checked_add(&quantity("units", right));
            let widened = u128::from(left) + u128::from(right);
            match result {
                Ok(value) => {
                    prop_assert_eq!(u128::from(value.amount()), widened);
                    prop_assert!(widened <= u128::from(u64::MAX));
                }
                Err(ArithmeticError::Overflow) => {
                    prop_assert!(widened > u128::from(u64::MAX));
                }
                Err(other) => prop_assert!(false, "unexpected arithmetic failure: {other:?}"),
            }
        }

        #[test]
        fn basis_points_is_always_within_denominator(
            denominator in any::<u64>(),
            points in 0_u16..=10_000,
        ) {
            let result = checked_basis_points(
                denominator,
                BasisPoints::new(points).unwrap(),
                RoundingDirection::Down,
            )
            .unwrap();
            prop_assert!(result <= denominator);
        }
    }
}
