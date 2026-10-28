//! Deployment-owned time acquisition. Historical evidence and provider
//! freshness meanings remain outside this clock boundary.

use crate::ClockTrustState;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod sealed {
    pub trait Sealed {}
}

/// One deployment-clock observation and the trust of that same observation.
/// Fields are private: only maintained clock adapters can create a sample.
#[derive(Clone, Copy, Debug)]
pub struct DeploymentTime {
    unix: Duration,
    monotonic: Instant,
    trust: ClockTrustState,
}

impl DeploymentTime {
    /// Unix seconds used by the portable validity and freshness contracts.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.unix.as_secs()
    }

    /// Whether the maintained adapter established clock synchronization.
    #[must_use]
    pub const fn trust_state(self) -> ClockTrustState {
        self.trust
    }

    /// Converts an exact Unix expiry into a conservative process deadline.
    /// The monotonic reference precedes wall-clock sampling, and fractional
    /// seconds are retained so rounding cannot extend the permitted lifetime.
    pub(crate) fn lease_deadline(self, expires_at: u64, source: Instant) -> Option<Instant> {
        if self.trust != ClockTrustState::Trusted {
            return None;
        }
        let remaining = Duration::from_secs(expires_at).checked_sub(self.unix)?;
        if remaining.is_zero() {
            return None;
        }
        let deadline = source.min(self.monotonic.checked_add(remaining)?);
        (deadline > self.monotonic).then_some(deadline)
    }
}

/// The deployment's maintained source of time and synchronization evidence.
///
/// The trait is sealed. Proofs, recipes and applications cannot implement a
/// clock or manufacture a trusted sample. Each boundary takes a fresh sample;
/// this interface does not claim distributed time or durable rollback detection.
pub trait DeploymentClock: sealed::Sealed + Send + Sync {
    /// Samples wall time, monotonic reference and trust together. Returns
    /// `None` if the host clock cannot be represented as a Unix timestamp.
    fn sample(&self) -> Option<DeploymentTime>;
}

fn system_sample(trust: impl FnOnce(SystemTime) -> ClockTrustState) -> Option<DeploymentTime> {
    let monotonic = Instant::now();
    let wall = SystemTime::now();
    let unix = wall.duration_since(UNIX_EPOCH).ok()?;
    Some(DeploymentTime {
        unix,
        monotonic,
        trust: trust(wall),
    })
}

/// The production clock adapter: trusted while the host's synchronization
/// marker records a sample no more than fifteen minutes old.
///
/// Missing, future-dated, stale, symlinked or nonregular markers refuse. On
/// Unix, group/world-writable markers also refuse. The service updates the
/// fixed file after each synchronization; mere existence cannot establish
/// freshness. Neither the path nor the age bound is configurable.
#[derive(Clone, Copy, Debug, Default)]
pub struct SynchronizedHostClock;

impl SynchronizedHostClock {
    /// The marker the host's time synchronization service creates once the
    /// clock is synchronized.
    pub const MARKER: &'static str = "/run/systemd/timesync/synchronized";
}

impl sealed::Sealed for SynchronizedHostClock {}

const MAX_SYNCHRONIZATION_AGE: Duration = Duration::from_mins(15);

fn synchronization_marker_trust(path: &std::path::Path, now: SystemTime) -> ClockTrustState {
    let Ok(marker) = std::fs::symlink_metadata(path) else {
        return ClockTrustState::Untrusted;
    };
    if !marker.is_file() {
        return ClockTrustState::Untrusted;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if marker.permissions().mode() & 0o022 != 0 {
            return ClockTrustState::Untrusted;
        }
    }
    let age = marker
        .modified()
        .ok()
        .and_then(|sample| now.duration_since(sample).ok());
    if age.is_some_and(|age| age <= MAX_SYNCHRONIZATION_AGE) {
        ClockTrustState::Trusted
    } else {
        ClockTrustState::Untrusted
    }
}

impl DeploymentClock for SynchronizedHostClock {
    fn sample(&self) -> Option<DeploymentTime> {
        system_sample(|now| synchronization_marker_trust(std::path::Path::new(Self::MARKER), now))
    }
}

/// Local host time for explicitly developmental installations. This adapter
/// supplies no production synchronization evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct DevelopmentClock;
impl sealed::Sealed for DevelopmentClock {}
impl DeploymentClock for DevelopmentClock {
    fn sample(&self) -> Option<DeploymentTime> {
        system_sample(|_| ClockTrustState::Trusted)
    }
}

/// Deterministic wall time and trust for test builds only.
#[cfg(any(test, feature = "testkit-harness"))]
#[derive(Debug)]
pub struct FixedClock {
    state: std::sync::Mutex<(Option<Duration>, ClockTrustState)>,
}

#[cfg(any(test, feature = "testkit-harness"))]
impl FixedClock {
    /// A readable, trusted test clock at `now` Unix seconds.
    #[must_use]
    pub const fn at(now: u64) -> Self {
        Self {
            state: std::sync::Mutex::new((
                Some(Duration::from_secs(now)),
                ClockTrustState::Trusted,
            )),
        }
    }
    /// Replaces the test clock's wall observation, including after failure.
    pub fn set(&self, now: u64) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = Some(Duration::from_secs(now));
    }
    /// Simulates loss of the wall-clock observation.
    pub fn unavailable(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = None;
    }
    /// Replaces the test synchronization state.
    pub fn trust_is(&self, trusted: bool) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .1 = if trusted {
            ClockTrustState::Trusted
        } else {
            ClockTrustState::Untrusted
        };
    }
}

#[cfg(any(test, feature = "testkit-harness"))]
impl sealed::Sealed for std::sync::Arc<FixedClock> {}
#[cfg(any(test, feature = "testkit-harness"))]
impl DeploymentClock for std::sync::Arc<FixedClock> {
    fn sample(&self) -> Option<DeploymentTime> {
        let (unix, trust) = *self.state.lock().ok()?;
        Some(DeploymentTime {
            unix: unix?,
            monotonic: Instant::now(),
            trust,
        })
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use std::fs::{File, FileTimes};

    #[test]
    fn lease_conversion_retains_fractional_expiry_and_source_bound() {
        let monotonic = Instant::now();
        let sample = DeploymentTime {
            unix: Duration::from_millis(12_900),
            monotonic,
            trust: ClockTrustState::Trusted,
        };
        assert_eq!(
            sample.lease_deadline(13, monotonic + Duration::from_secs(10)),
            Some(monotonic + Duration::from_millis(100))
        );
        assert_eq!(
            sample.lease_deadline(13, monotonic + Duration::from_millis(50)),
            Some(monotonic + Duration::from_millis(50))
        );
        assert!(sample.lease_deadline(13, monotonic).is_none());
        for unix in [Duration::from_secs(13), Duration::from_millis(13_001)] {
            assert!(
                DeploymentTime { unix, ..sample }
                    .lease_deadline(13, monotonic + Duration::from_secs(10))
                    .is_none()
            );
        }
        assert!(
            DeploymentTime {
                trust: ClockTrustState::Untrusted,
                ..sample
            }
            .lease_deadline(13, monotonic + Duration::from_secs(10))
            .is_none()
        );
    }

    #[test]
    fn clock_failure_is_absent_and_trust_is_part_of_the_sample() {
        let clock = std::sync::Arc::new(FixedClock::at(50));
        let sample = clock.sample().expect("sample");
        assert_eq!(sample.unix_seconds(), 50);
        assert_eq!(sample.trust_state(), ClockTrustState::Trusted);
        clock.trust_is(false);
        assert_eq!(
            clock.sample().expect("untrusted sample").trust_state(),
            ClockTrustState::Untrusted
        );
        clock.unavailable();
        assert!(clock.sample().is_none());
        clock.set(49);
        assert_eq!(
            clock.sample().expect("backward wall sample").unix_seconds(),
            49
        );
        assert_eq!(
            clock.sample().expect("trust remains lost").trust_state(),
            ClockTrustState::Untrusted
        );
        clock.set(80);
        clock.trust_is(true);
        assert_eq!(clock.sample().expect("restored sample").unix_seconds(), 80);
    }

    #[test]
    fn synchronization_marker_requires_a_recent_nonfuture_sample() {
        let directory = tempfile::tempdir().expect("temporary clock state");
        let path = directory.path().join("synchronized");
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        assert_eq!(
            synchronization_marker_trust(&path, now),
            ClockTrustState::Untrusted
        );
        let marker = File::create(&path).expect("marker");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            marker
                .set_permissions(std::fs::Permissions::from_mode(0o644))
                .expect("marker permissions");
        }
        for (sample, expected) in [
            (now, ClockTrustState::Trusted),
            (now - MAX_SYNCHRONIZATION_AGE, ClockTrustState::Trusted),
            (
                now - MAX_SYNCHRONIZATION_AGE - Duration::from_secs(1),
                ClockTrustState::Untrusted,
            ),
            (now + Duration::from_secs(1), ClockTrustState::Untrusted),
        ] {
            marker
                .set_times(FileTimes::new().set_modified(sample))
                .expect("set sample time");
            assert_eq!(synchronization_marker_trust(&path, now), expected);
        }
        assert_eq!(
            synchronization_marker_trust(directory.path(), now),
            ClockTrustState::Untrusted
        );
    }

    #[cfg(unix)]
    #[test]
    fn synchronization_marker_refuses_links_and_untrusted_write_permissions() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let directory = tempfile::tempdir().expect("temporary clock state");
        let path = directory.path().join("synchronized");
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let marker = File::create(&path).expect("marker");
        marker
            .set_times(FileTimes::new().set_modified(now))
            .expect("set sample time");
        for mode in [0o644, 0o664, 0o646] {
            marker
                .set_permissions(std::fs::Permissions::from_mode(mode))
                .expect("set permissions");
            let expected = if mode == 0o644 {
                ClockTrustState::Trusted
            } else {
                ClockTrustState::Untrusted
            };
            assert_eq!(synchronization_marker_trust(&path, now), expected);
        }
        marker
            .set_permissions(std::fs::Permissions::from_mode(0o644))
            .expect("private marker");
        let link = directory.path().join("link");
        symlink(&path, &link).expect("link");
        assert_eq!(
            synchronization_marker_trust(&link, now),
            ClockTrustState::Untrusted
        );
    }
}
