use std::{
    fs::{File, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use auths_stripe::{
    DigestHex, PaymentMandateReceipt, PortError, ReceiptSink,
    canonical::{canonical_json, sha256},
};

const MAX_RECEIPT_BYTES: usize = 512 * 1024;
const MAX_RECEIPTS: usize = 4_096;

/// Append-only canonical mandate receipt journal.
pub struct ReceiptJournal {
    path: PathBuf,
    process_lock: Mutex<()>,
}

impl ReceiptJournal {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PortError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|_| PortError::Persistence)?;
        let journal = Self {
            path,
            process_lock: Mutex::new(()),
        };
        journal.read_all()?;
        Ok(journal)
    }

    pub fn get(&self, receipt_id: &DigestHex) -> Result<Option<PaymentMandateReceipt>, PortError> {
        Ok(self.read_all()?.into_iter().find(|receipt| {
            canonical_json(receipt).is_ok_and(|bytes| sha256(&bytes) == *receipt_id)
        }))
    }

    pub fn read_all(&self) -> Result<Vec<PaymentMandateReceipt>, PortError> {
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| PortError::Persistence)?;
        read_all_unlocked(&self.path)
    }
}

impl ReceiptSink<PaymentMandateReceipt> for ReceiptJournal {
    fn append(&self, receipt: &PaymentMandateReceipt) -> Result<(), PortError> {
        let bytes = canonical_json(receipt).map_err(|_| PortError::Malformed)?;
        if bytes.len() > MAX_RECEIPT_BYTES || bytes.contains(&b'\n') {
            return Err(PortError::LimitExceeded);
        }
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| PortError::Persistence)?;
        let receipts = read_all_unlocked(&self.path)?;
        if receipts.len() >= MAX_RECEIPTS {
            return Err(PortError::LimitExceeded);
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| PortError::Persistence)
    }
}

pub fn receipt_id(receipt: &PaymentMandateReceipt) -> Result<DigestHex, PortError> {
    canonical_json(receipt)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| PortError::Malformed)
}

fn read_all_unlocked(path: &Path) -> Result<Vec<PaymentMandateReceipt>, PortError> {
    let file = File::open(path).map_err(|_| PortError::Persistence)?;
    let mut receipts = Vec::new();
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|_| PortError::Persistence)?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_RECEIPT_BYTES || receipts.len() >= MAX_RECEIPTS {
            return Err(PortError::LimitExceeded);
        }
        let receipt: PaymentMandateReceipt =
            serde_json::from_slice(&line).map_err(|_| PortError::Malformed)?;
        if canonical_json(&receipt).map_err(|_| PortError::Malformed)? != line {
            return Err(PortError::Malformed);
        }
        receipts.push(receipt);
    }
    Ok(receipts)
}
