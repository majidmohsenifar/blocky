use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
};

use crate::{
    BoxError,
    genesis::Genesis,
    tx::{Account, Tx},
};

#[derive(Debug)]
pub struct State {
    pub balances: HashMap<Account, u64>,
    pub tx_mempool: Vec<Tx>,
    pub db_file: std::fs::File,
}

impl State {
    pub fn new_state_from_disk() -> Result<State, BoxError> {
        let genesis = Genesis::new_from_file_path("database/genesis.json")?;
        let mut balances = HashMap::new();
        for (acc, b) in &genesis.balances {
            balances.insert(acc.to_string(), *b);
        }

        let db_file = File::open("database/tx.db")?;

        let mut state = State {
            balances,
            tx_mempool: vec![],
            db_file: db_file.try_clone()?,
        };

        let reader = BufReader::new(db_file);
        for line in reader.lines() {
            let line = line?;
            let tx = serde_json::from_str(&line)?;
            state.apply(tx)?;
        }
        Ok(state)
    }

    pub fn close(&mut self) {
        unimplemented!()
        // let _ = self.db_file;
    }

    pub fn add(&mut self, tx: Tx) -> Result<(), BoxError> {
        self.apply(tx.clone())?;
        self.tx_mempool.push(tx);
        Ok(())
    }

    pub fn persist(&mut self) -> Result<(), BoxError> {
        for tx in self.tx_mempool.drain(..) {
            let tx_string = serde_json::to_string(&tx)?;
            writeln!(self.db_file, "{}", tx_string)?;
        }
        Ok(())
    }

    pub fn apply(&mut self, tx: Tx) -> Result<(), BoxError> {
        if tx.is_reward() {
            self.balances
                .entry(tx.to)
                .and_modify(|b| *b += tx.value)
                .or_insert(tx.value);
            return Ok(());
        }

        if let Some(b) = self.balances.get_mut(&tx.from) {
            if *b < tx.value {
                return Err("insufficient balance".into());
            }
            *b -= tx.value;
        } else {
            return Err("insufficient balance".into());
        };
        self.balances
            .entry(tx.to)
            .and_modify(|b| *b += tx.value)
            .or_insert(tx.value);
        Ok(())
    }
}
