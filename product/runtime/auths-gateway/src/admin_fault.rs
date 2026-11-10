//! Test-only interruption points at administrative durability boundaries.

#[cfg(feature = "testkit-harness")]
pub fn boundary(point: &'static str) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let interruption = std::env::var("AUTHS_TEST_ADMIN_INTERRUPT_AT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let trace = std::env::var_os("AUTHS_TEST_ADMIN_TRACE").is_some();
    if interruption.is_none() && !trace {
        return;
    }
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1;
    if trace {
        eprintln!("auths-test-admin-boundary:{sequence}:{point}");
    }
    if interruption == Some(sequence) {
        // No destructors: model process termination after exactly this boundary.
        std::process::exit(79);
    }
}

#[cfg(not(feature = "testkit-harness"))]
#[inline]
pub(crate) const fn boundary(_point: &'static str) {}
