use std::collections::HashMap;

use serde::Deserialize;

use crate::{BoxError, tx::Account};

#[derive(Deserialize)]
pub struct Genesis {
    pub balances: HashMap<Account, u64>,
}

impl Genesis {
    pub fn new_from_file_path(path: &str) -> Result<Genesis, BoxError> {
        let file_content = std::fs::read_to_string(path)?;
        let genesis: Genesis = serde_json::from_str(&file_content)?;
        Ok(genesis)
    }
}
