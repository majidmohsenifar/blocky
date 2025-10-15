use crate::block::Hash;
use alloy::{primitives::Address, signers::Signature};
use axum::BoxError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub from: Address,
    pub to: Address,
    pub value: u64,
    pub nonce: u64,
    pub data: String,
    pub time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTx {
    pub tx: Tx,
    pub sig: Vec<u8>,
}

impl Tx {
    pub fn new(from: Address, to: Address, value: u64, nonce: u64, data: String) -> Self {
        Self {
            from,
            to,
            value,
            nonce,
            data,
            time: Utc::now().timestamp() as u64,
        }
    }

    pub fn hash(&self) -> Result<Hash, BoxError> {
        let res = serde_json::to_string(self)?;
        let hash = Sha256::digest(res);
        Ok(hash.into())
    }

    pub fn is_reward(&self) -> bool {
        self.data.as_str() == "reward"
    }
}

impl SignedTx {
    pub fn new(tx: Tx, sig: Vec<u8>) -> Self {
        Self { tx, sig }
    }

    pub fn hash(&self) -> Result<Hash, BoxError> {
        let res = serde_json::to_string(self)?;
        let hash = Sha256::digest(res);
        Ok(hash.into())
    }

    pub fn is_authentic(&self) -> Result<(), BoxError> {
        let signature = Signature::from_raw(self.sig.as_slice())?;

        let tx_serialized = serde_json::to_vec(&self.tx)?;

        let address = signature.recover_address_from_msg(tx_serialized)?;

        if self.tx.from != address {
            return Err("invalid signature".into());
        }
        Ok(())
    }
}
