use std::collections::HashMap;

use crate::tx::Account;

pub struct Genesis {
    pub balances: HashMap<Account, u64>,
}

impl Genesis {
    pub fn new_from_file_path(
        path: String,
    ) -> Result<Genesis, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!()
    }
}
