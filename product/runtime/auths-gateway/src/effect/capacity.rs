//! Shared fixed-size source allocation declarations, without admission or I/O.
use super::{Reservation, ReservationWindow, Unit};

/// Bounded append-only source allowance; protocol owners supply distinct units.
pub(crate) struct SourceCapacity {
    pub(crate) count_key: [u8; 32],
    pub(crate) bytes_key: [u8; 32],
    pub(crate) maximum_bytes: u64,
    pub(crate) attempts: u64,
}

impl SourceCapacity {
    pub(super) fn reservations(&self, count: Unit, bytes: Unit) -> Vec<Reservation> {
        let mut reservations = vec![
            Reservation {
                key: self.count_key,
                unit: count,
                amount: 1,
                ceiling: self.attempts,
                window: ReservationWindow::SourceLifetime,
            },
            Reservation {
                key: self.bytes_key,
                unit: bytes,
                amount: self.maximum_bytes,
                ceiling: self.attempts * self.maximum_bytes.max(1),
                window: ReservationWindow::SourceLifetime,
            },
        ];
        reservations.sort_by_key(|entry| (entry.key, entry.unit));
        reservations
    }
}
