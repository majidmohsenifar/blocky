use crate::block::Hash;
use axum::BoxError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Account = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub from: Account,
    pub to: Account,
    pub value: u64,
    pub data: String,
}

impl Tx {
    pub fn new(from: Account, to: Account, value: u64, data: String) -> Self {
        Self {
            from,
            to,
            value,
            data,
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
