use std::collections::HashMap;

use alloy::primitives::Address;
use serde::Deserialize;

use crate::BoxError;

pub const GENESIS_JSON: &str = r#"
{
  "genesis_time": "2019-03-18T00:00:00.000000000Z",
  "chain_id": "the-blockchain-bar-ledger",
  "balances": {
    "0x20a1c88869FC0245E9AdBC76AaBbfcEDFcD08E0F": 1000000
  }
}"#;

#[derive(Deserialize)]
pub struct Genesis {
    pub balances: HashMap<Address, u64>,
}

impl Genesis {
    pub fn new_from_file_path(path: &str) -> Result<Genesis, BoxError> {
        let file_content = std::fs::read_to_string(path)?;
        let genesis: Genesis = serde_json::from_str(&file_content)?;
        Ok(genesis)
    }
}
