use std::collections::HashMap;

use crate::tx::{Account, Tx};

pub struct State {
    pub balances: HashMap<Account, u64>,
    pub tx_mempool: Vec<Tx>,
    pub db_file: std::fs::File,
}

impl State {
    pub fn new_state_from_disk() -> Result<State, Box<dyn std::error::Error + Send + Sync>> {
        unimplemented!()
        // let file_content = std::fs::read_to_string("database/genesis.json")?;
    }
}
