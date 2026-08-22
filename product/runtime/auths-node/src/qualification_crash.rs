//! Qualification-only durable journal-boundary gate.
//!
//! This module is absent from the production build. The isolated
//! qualification agent publishes only bounded capability-free commitments,
//! then blocks before exposing a later projection until the independently
//! built protected controller has durably appended the corresponding source
//! evidence. For a crash phase the protected controller withholds the release
//! at the selected boundary and owns the exact kill; candidate code never
//! decides when a crash is delivered.

#![forbid(unsafe_code)]

use auths_profile_kit::{QualificationDurableDecisionAckV1, QualificationFailpoint};
use auths_stores::JournalRecordV1;
use sha2::{Digest as _, Sha256};
use std::{
    fs::File,
    io::{ErrorKind, Read as _, Write as _},
    sync::{Mutex, MutexGuard, atomic::AtomicBool},
    time::{Duration, Instant},
};

const BOUNDARY_GATE_SECONDS: u64 = 60;
const MAX_GATE_FRAME_BYTES: usize = 4_096;
const FLUSH_BOUNDARIES: &[u8] = b"AUTHS-QUALIFICATION-JOURNAL-FLUSH/1";
const BEFORE_DECISION: &[u8] = b"AUTHS-QUALIFICATION-BEFORE-DECISION/1";
const AFTER_RESERVATION: &[u8] = b"AUTHS-QUALIFICATION-AFTER-RESERVATION/1";

struct QualificationJournalChannel {
    output: File,
    release: File,
}

/// Serialized gate installed only in the qualification-agent build.
pub(crate) struct QualificationJournalBoundaryGate {
    channel: Mutex<QualificationJournalChannel>,
    agent_generation: u32,
    control_operation_id: Option<String>,
    controller_nonce_sha256: Option<String>,
    failpoint: Option<QualificationFailpoint>,
    armed: AtomicBool,
}

/// Linear capability proving that this request won the one qualification
/// decision slot before it performed any durable preparation work.
pub(crate) struct QualificationDecisionClaim<'a> {
    gate: &'a QualificationJournalBoundaryGate,
    channel: MutexGuard<'a, QualificationJournalChannel>,
}

/// Linear reservation serializing one qualification journal transaction
/// through any resulting protected evidence drain.
pub(crate) struct QualificationBoundaryClaim<'a> {
    channel: MutexGuard<'a, QualificationJournalChannel>,
}

impl QualificationJournalBoundaryGate {
    pub(crate) fn new(
        output: File,
        release: File,
        agent_generation: u32,
        failpoint: Option<QualificationFailpoint>,
        control_operation_id: Option<String>,
        controller_nonce_sha256: Option<String>,
        controller_pid: u32,
    ) -> Result<Self, ()> {
        let crash_identity_valid = match (
            failpoint,
            control_operation_id.as_deref(),
            controller_nonce_sha256.as_deref(),
        ) {
            (Some(_), Some(operation), Some(nonce)) => registered_token(operation) && digest(nonce),
            (None, None, None) => true,
            _ => return Err(()),
        };
        if !crash_identity_valid
            || agent_generation == 0
            || controller_pid == 0
            || rustix::process::Pid::as_raw(rustix::process::getppid()) != controller_pid as i32
        {
            return Err(());
        }
        rustix::fs::fcntl_setfl(&output, rustix::fs::OFlags::NONBLOCK).map_err(|_| ())?;
        rustix::fs::fcntl_setfl(&release, rustix::fs::OFlags::NONBLOCK).map_err(|_| ())?;
        Ok(Self {
            channel: Mutex::new(QualificationJournalChannel { output, release }),
            agent_generation,
            control_operation_id,
            controller_nonce_sha256,
            failpoint,
            armed: AtomicBool::new(true),
        })
    }

    /// Serializes only fresh decision creation through its durable evidence
    /// append. Ordinary qualification may create later decisions; the exact
    /// crash row admits one and never releases it.
    pub(crate) fn claim(&self) -> Result<QualificationDecisionClaim<'_>, ()> {
        if matches!(
            self.failpoint,
            Some(QualificationFailpoint::BeforeDecision | QualificationFailpoint::AfterDecision)
        ) {
            self.armed
                .compare_exchange(
                    true,
                    false,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .map_err(|_| ())?;
        }
        let mut channel = self.channel.lock().map_err(|_| ())?;
        if self.failpoint == Some(QualificationFailpoint::BeforeDecision) {
            let deadline = Instant::now() + Duration::from_secs(BOUNDARY_GATE_SECONDS);
            write_frame_before(&mut channel.output, BEFORE_DECISION, deadline)?;
            if read_frame_before(&mut channel.release, deadline)? != [1] {
                return Err(());
            }
        }
        Ok(QualificationDecisionClaim {
            gate: self,
            channel,
        })
    }

    /// Reserves the one ordinary journal/evidence ordering lane before a
    /// transaction can extend the durable boundary roster.
    pub(crate) fn reserve(&self) -> Result<QualificationBoundaryClaim<'_>, ()> {
        Ok(QualificationBoundaryClaim {
            channel: self.channel.lock().map_err(|_| ())?,
        })
    }

    /// Blocks after the domain sealer has durably acquired its private
    /// reservation but before the common journal can persist a command.
    pub(crate) fn checkpoint_after_reservation(&self) -> Result<(), ()> {
        if self.failpoint != Some(QualificationFailpoint::AfterReservation) {
            return Ok(());
        }
        let mut channel = self.channel.lock().map_err(|_| ())?;
        let deadline = Instant::now() + Duration::from_secs(BOUNDARY_GATE_SECONDS);
        write_frame_before(&mut channel.output, AFTER_RESERVATION, deadline)?;
        if read_frame_before(&mut channel.release, deadline)? != [1] {
            return Err(());
        }
        Ok(())
    }
}

impl QualificationBoundaryClaim<'_> {
    /// Flushes every store-owned boundary persisted by the reserved
    /// transaction. The wake carries no caller-selected ordinal; the
    /// controller must reopen and drain its complete authenticated suffix.
    pub(crate) fn flush_and_wait(mut self) -> Result<(), ()> {
        let deadline = Instant::now() + Duration::from_secs(BOUNDARY_GATE_SECONDS);
        write_frame_before(&mut self.channel.output, FLUSH_BOUNDARIES, deadline)?;
        if read_frame_before(&mut self.channel.release, deadline)? != [1] {
            return Err(());
        }
        Ok(())
    }
}

impl QualificationDecisionClaim<'_> {
    /// Releases a reservation that did not create a fresh durable decision.
    pub(crate) fn cancel(self) {
        if matches!(
            self.gate.failpoint,
            Some(QualificationFailpoint::BeforeDecision | QualificationFailpoint::AfterDecision)
        ) {
            self.gate
                .armed
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    /// Publishes the exact durable commitment and waits until the protected
    /// controller has appended the corresponding journal source event.
    pub(crate) fn acknowledge_and_wait(mut self, record: &JournalRecordV1) -> Result<(), ()> {
        record.validate_exact_decision_snapshot().map_err(|_| ())?;
        let private_record = serde_json_canonicalizer::to_vec(record).map_err(|_| ())?;
        let ack = QualificationDurableDecisionAckV1::new(
            record.operation_id().as_str().to_owned(),
            hex::encode(Sha256::digest(private_record)),
            self.gate.agent_generation,
            self.gate.control_operation_id.clone(),
            self.gate.controller_nonce_sha256.clone(),
        )
        .map_err(|_| ())?
        .to_json()
        .map_err(|_| ())?;
        let deadline = Instant::now() + Duration::from_secs(BOUNDARY_GATE_SECONDS);
        write_frame_before(&mut self.channel.output, &ack, deadline)?;
        if read_frame_before(&mut self.channel.release, deadline)? != [1] {
            return Err(());
        }
        Ok(())
    }
}

fn write_frame_before(file: &mut File, bytes: &[u8], deadline: Instant) -> Result<(), ()> {
    if bytes.is_empty() || bytes.len() > MAX_GATE_FRAME_BYTES {
        return Err(());
    }
    let length = u32::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes();
    write_all_before(file, &length, deadline)?;
    write_all_before(file, bytes, deadline)
}

fn read_frame_before(file: &mut File, deadline: Instant) -> Result<Vec<u8>, ()> {
    let mut length = [0_u8; 4];
    read_exact_before(file, &mut length, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| ())?;
    if length == 0 || length > MAX_GATE_FRAME_BYTES {
        return Err(());
    }
    let mut bytes = vec![0; length];
    read_exact_before(file, &mut bytes, deadline)?;
    Ok(bytes)
}

fn write_all_before(file: &mut File, mut bytes: &[u8], deadline: Instant) -> Result<(), ()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(());
        }
        match file.write(bytes) {
            Ok(0) => return Err(()),
            Ok(written) => bytes = &bytes[written..],
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(()),
        }
    }
    file.flush().map_err(|_| ())
}

fn read_exact_before(file: &mut File, mut bytes: &mut [u8], deadline: Instant) -> Result<(), ()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(());
        }
        match file.read(bytes) {
            Ok(0) => return Err(()),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::QualificationJournalBoundaryGate;
    use auths_profile_kit::QualificationFailpoint;
    use std::{
        fs::File,
        sync::{Arc, Barrier},
        thread,
    };

    #[test]
    fn exactly_one_concurrent_request_claims_the_decision_slot() {
        let output = File::options()
            .write(true)
            .open("/dev/null")
            .expect("null output");
        let release = File::open("/dev/null").expect("null release");
        let parent_pid = u32::try_from(rustix::process::Pid::as_raw(rustix::process::getppid()))
            .expect("parent pid");
        let checkpoint = Arc::new(
            QualificationJournalBoundaryGate::new(
                output,
                release,
                1,
                Some(QualificationFailpoint::AfterDecision),
                Some("ctl_0123456789abcdef0123456789abcdef".into()),
                Some("a".repeat(64)),
                parent_pid,
            )
            .expect("checkpoint"),
        );
        let barrier = Arc::new(Barrier::new(9));
        let workers = (0..8)
            .map(|_| {
                let checkpoint = Arc::clone(&checkpoint);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    checkpoint.claim().is_ok()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let winners = workers
            .into_iter()
            .map(|worker| worker.join().expect("claim worker must finish"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
