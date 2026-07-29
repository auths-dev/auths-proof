use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use auths_stripe::{
    DigestHex, PortError, ReceiptSink, StripeReceipt,
    canonical::{canonical_json, sha256},
};

const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECEIPTS: usize = 100_000;

/// Append-only canonical receipt journal with digest-addressed reads.
pub struct ReceiptJournal {
    path: PathBuf,
    process_lock: Mutex<()>,
}

impl ReceiptJournal {
    /// Opens or creates the durable journal and validates every existing line.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PortError> {
        let path = path.into();
        let parent = path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
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

    /// Returns one exact receipt by canonical digest.
    pub fn get(&self, receipt_id: &DigestHex) -> Result<Option<StripeReceipt>, PortError> {
        Ok(self.read_all()?.into_iter().find(|receipt| {
            canonical_json(receipt)
                .map(|bytes| sha256(&bytes) == *receipt_id)
                .unwrap_or(false)
        }))
    }

    /// Returns the complete bounded journal in append order.
    pub fn read_all(&self) -> Result<Vec<StripeReceipt>, PortError> {
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| PortError::Persistence)?;
        read_all_unlocked(&self.path)
    }
}

impl ReceiptSink for ReceiptJournal {
    fn append(&self, receipt: &StripeReceipt) -> Result<(), PortError> {
        let bytes = canonical_json(receipt).map_err(|_| PortError::Malformed)?;
        if bytes.len() > MAX_RECEIPT_BYTES || bytes.contains(&b'\n') {
            return Err(PortError::LimitExceeded);
        }
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.lock().map_err(|_| PortError::Persistence)?;
        if read_all_from(&file)?.len() >= MAX_RECEIPTS {
            let _ = file.unlock();
            return Err(PortError::LimitExceeded);
        }
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| PortError::Persistence)?;
        file.unlock().map_err(|_| PortError::Persistence)
    }
}

/// Computes the public digest address for a receipt.
pub fn receipt_id(receipt: &StripeReceipt) -> Result<DigestHex, PortError> {
    canonical_json(receipt)
        .map(|bytes| sha256(&bytes))
        .map_err(|_| PortError::Malformed)
}

fn read_all_unlocked(path: &Path) -> Result<Vec<StripeReceipt>, PortError> {
    let file = File::open(path).map_err(|_| PortError::Persistence)?;
    file.lock_shared().map_err(|_| PortError::Persistence)?;
    let result = read_all_from(&file);
    file.unlock().map_err(|_| PortError::Persistence)?;
    result
}

fn read_all_from(file: &File) -> Result<Vec<StripeReceipt>, PortError> {
    let clone = file.try_clone().map_err(|_| PortError::Persistence)?;
    let mut receipts = Vec::new();
    for line in BufReader::new(clone).split(b'\n') {
        let line = line.map_err(|_| PortError::Persistence)?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_RECEIPT_BYTES || receipts.len() >= MAX_RECEIPTS {
            return Err(PortError::LimitExceeded);
        }
        let receipt: StripeReceipt =
            serde_json::from_slice(&line).map_err(|_| PortError::Malformed)?;
        let canonical = canonical_json(&receipt).map_err(|_| PortError::Malformed)?;
        if canonical != line {
            return Err(PortError::Malformed);
        }
        receipts.push(receipt);
    }
    Ok(receipts)
}
