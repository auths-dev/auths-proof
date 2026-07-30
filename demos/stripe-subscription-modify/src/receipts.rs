use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

use auths_stripe::{
    DigestHex, PortError, ReceiptSink, SubscriptionModifyReceipt,
    canonical::{canonical_json, sha256},
};

pub struct ReceiptJournal {
    path: PathBuf,
    entries: Mutex<Vec<SubscriptionModifyReceipt>>,
}

impl ReceiptJournal {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PortError> {
        let path = path.into();
        let entries = read(&path)?;
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    pub fn get(&self, id: &DigestHex) -> Result<Option<SubscriptionModifyReceipt>, PortError> {
        let entries = self.entries.lock().map_err(|_| PortError::Persistence)?;
        for receipt in entries.iter().rev() {
            if receipt_id(receipt)? == *id {
                return Ok(Some(receipt.clone()));
            }
        }
        Ok(None)
    }

    pub fn latest_for(
        &self,
        workflow_id: &str,
    ) -> Result<Option<(DigestHex, SubscriptionModifyReceipt)>, PortError> {
        let entries = self.entries.lock().map_err(|_| PortError::Persistence)?;
        entries
            .iter()
            .rev()
            .find_map(|receipt| {
                let matches = match receipt {
                    SubscriptionModifyReceipt::Decision(value) => value.workflow_id == workflow_id,
                    SubscriptionModifyReceipt::Transition(value) => {
                        value.modification.workflow_id() == workflow_id
                    }
                    SubscriptionModifyReceipt::Observation(value) => {
                        value.workflow_id == workflow_id
                    }
                };
                matches.then(|| receipt_id(receipt).map(|id| (id, receipt.clone())))
            })
            .transpose()
    }
}

impl ReceiptSink<SubscriptionModifyReceipt> for ReceiptJournal {
    fn append(&self, receipt: &SubscriptionModifyReceipt) -> Result<(), PortError> {
        let parent = self.path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(
            &receipt
                .canonical_bytes()
                .map_err(|_| PortError::Persistence)?,
        )
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| PortError::Persistence)?;
        self.entries
            .lock()
            .map_err(|_| PortError::Persistence)?
            .push(receipt.clone());
        Ok(())
    }
}

pub fn receipt_id(receipt: &SubscriptionModifyReceipt) -> Result<DigestHex, PortError> {
    Ok(sha256(
        &receipt
            .canonical_bytes()
            .map_err(|_| PortError::Persistence)?,
    ))
}

fn read(path: &Path) -> Result<Vec<SubscriptionModifyReceipt>, PortError> {
    let bytes = match fs::read(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(PortError::Persistence),
    };
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| PortError::Malformed))
        .collect()
}

#[allow(dead_code)]
fn _canonical(receipt: &SubscriptionModifyReceipt) -> Result<Vec<u8>, PortError> {
    canonical_json(receipt).map_err(|_| PortError::Malformed)
}
