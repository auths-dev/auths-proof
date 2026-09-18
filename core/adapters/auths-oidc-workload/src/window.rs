use auths_model::Timestamp;

use crate::{ClaimError, OidcError};

pub const CLOCK_SKEW: u64 = 300;
pub const MAX_TOKEN_LIFETIME: u64 = 86_400;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TokenLifetime(u64);
impl TokenLifetime {
    /// Constructs a bounded maximum token lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ConfigurationError`] when `seconds` is zero or exceeds
    /// the adapter maximum.
    pub fn new(seconds: u64) -> Result<Self, crate::ConfigurationError> {
        if seconds == 0 || seconds > MAX_TOKEN_LIFETIME {
            return Err(crate::ConfigurationError::Lifetime);
        }
        Ok(Self(seconds))
    }
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenWindow {
    issued: Timestamp,
    expires: Timestamp,
    not_before: Option<Timestamp>,
}
impl TokenWindow {
    /// Constructs and validates a token validity window.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when timestamps are inconsistent, exceed the
    /// configured lifetime, or cannot be evaluated safely.
    pub fn new(
        iat: u64,
        exp: u64,
        nbf: Option<u64>,
        lifetime: TokenLifetime,
    ) -> Result<Self, ClaimError> {
        if iat > exp
            || exp
                .checked_sub(iat)
                .is_none_or(|duration| duration > lifetime.get())
            || nbf.is_some_and(|value| value > exp)
            || exp.checked_add(CLOCK_SKEW).is_none()
        {
            return Err(ClaimError::Window);
        }
        Ok(Self {
            issued: Timestamp::new(iat),
            expires: Timestamp::new(exp),
            not_before: nbf.map(Timestamp::new),
        })
    }
    /// Admits an evaluation instant against this token window.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] when `now` falls outside the skew-adjusted window
    /// or a bound overflows.
    pub fn admits_live(self, now: Timestamp) -> Result<AdmittedLiveTime, OidcError> {
        let earliest = self.issued.get().saturating_sub(CLOCK_SKEW);
        if now.get() < earliest {
            return Err(OidcError::OutsideWindow(WindowViolation::Issued));
        }
        let latest = self
            .expires
            .get()
            .checked_add(CLOCK_SKEW)
            .ok_or(OidcError::OutsideWindow(WindowViolation::Overflow))?;
        if now.get() >= latest {
            return Err(OidcError::OutsideWindow(WindowViolation::Expired));
        }
        if self
            .not_before
            .is_some_and(|nbf| nbf.get() > now.get().saturating_add(CLOCK_SKEW))
        {
            return Err(OidcError::OutsideWindow(WindowViolation::NotBefore));
        }
        Ok(AdmittedLiveTime { now })
    }
    #[must_use]
    pub const fn issued(self) -> Timestamp {
        self.issued
    }
    #[must_use]
    pub const fn expires(self) -> Timestamp {
        self.expires
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowViolation {
    Issued,
    NotBefore,
    Expired,
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedLiveTime {
    now: Timestamp,
}
impl AdmittedLiveTime {
    #[must_use]
    pub const fn now(self) -> Timestamp {
        self.now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_are_checked_without_overflow() {
        let lifetime = TokenLifetime::new(MAX_TOKEN_LIFETIME).unwrap();
        let window = TokenWindow::new(100, 200, Some(120), lifetime).unwrap();
        assert!(window.admits_live(Timestamp::new(0)).is_ok());
        assert!(window.admits_live(Timestamp::new(499)).is_ok());
        assert_eq!(
            window.admits_live(Timestamp::new(500)),
            Err(OidcError::OutsideWindow(WindowViolation::Expired))
        );
        assert_eq!(
            TokenWindow::new(u64::MAX - 1, u64::MAX, None, lifetime),
            Err(ClaimError::Window)
        );
    }
}
