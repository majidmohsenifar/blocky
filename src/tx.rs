use serde::{Deserialize, Serialize};

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
    pub fn is_reward(&self) -> bool {
        self.data.as_str() == "reward"
    }
}
