use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Seek, Write},
};

use sha2::{Digest, Sha256};

use crate::{
    BoxError,
    genesis::Genesis,
    tx::{Account, Tx},
};

pub type Snapshot = [u8; 32];

#[derive(Debug)]
pub struct State {
    pub balances: HashMap<Account, u64>,
    pub tx_mempool: Vec<Tx>,
    pub db_file: std::fs::File,
    pub snapshot: Snapshot,
}

impl State {
    pub fn new_state_from_disk() -> Result<State, BoxError> {
        let genesis = Genesis::new_from_file_path("database/genesis.json")?;
        let mut balances = HashMap::new();
        for (acc, b) in &genesis.balances {
            balances.insert(acc.to_string(), *b);
        }

        let db_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open("database/tx.db")?;

        let mut state = State {
            balances,
            tx_mempool: vec![],
            db_file: db_file.try_clone()?,
            snapshot: [0; 32],
        };

        let reader = BufReader::new(db_file);
        for line in reader.lines() {
            let line = line?;
            let tx = serde_json::from_str(&line)?;
            state.apply(tx)?;
        }
        state.do_snapshot()?;
        Ok(state)
    }

    // pub fn close(&mut self) {
    //     unimplemented!()
    //     // let _ = self.db_file;
    // }

    pub fn add(&mut self, tx: Tx) -> Result<(), BoxError> {
        self.apply(tx.clone())?;
        self.tx_mempool.push(tx);
        Ok(())
    }

    pub fn persist(&mut self) -> Result<Snapshot, BoxError> {
        let tx_mempool = self.tx_mempool.clone();
        for (i, tx) in tx_mempool.iter().enumerate() {
            let tx_string = serde_json::to_string(&tx)?;
            writeln!(self.db_file, "{}", tx_string)?;
            self.do_snapshot()?;
            println!("snapshot is {:?}", hex::encode(self.snapshot));
            self.tx_mempool = tx_mempool[i + 1..].to_vec();
        }
        self.do_snapshot()?;
        Ok(self.snapshot)
    }

    pub fn latest_snapshopt(&self) -> Snapshot {
        self.snapshot
    }

    pub fn do_snapshot(&mut self) -> Result<(), BoxError> {
        let _ = self.db_file.seek(std::io::SeekFrom::Start(0))?;
        let mut contents = String::new();
        self.db_file.read_to_string(&mut contents)?;
        let hash = Sha256::digest(contents);
        self.snapshot = hash.into();
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
