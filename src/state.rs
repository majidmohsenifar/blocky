use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
};

use chrono::Utc;

use crate::{
    BoxError,
    block::{Block, BlockFs, Hash},
    genesis::Genesis,
    tx::{Account, Tx},
};

#[derive(Debug)]
pub struct State {
    pub balances: HashMap<Account, u64>,
    pub tx_mempool: Vec<Tx>,
    pub db_file: std::fs::File,
    pub latest_block_hash: Hash,
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
            .open("database/block.db")?;

        let mut state = State {
            balances,
            tx_mempool: vec![],
            db_file: db_file.try_clone()?,
            latest_block_hash: [0; 32],
        };

        let reader = BufReader::new(db_file);
        for line in reader.lines() {
            let line = line?;
            let block_fs: BlockFs = serde_json::from_str(&line)?;
            state.apply_block(block_fs.value)?;
            state.latest_block_hash = block_fs.key;
        }
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

    pub fn add_block(&mut self, b: Block) -> Result<(), BoxError> {
        for tx in b.txs {
            self.add(tx)?;
        }
        Ok(())
    }

    pub fn persist(&mut self) -> Result<Hash, BoxError> {
        let block = Block::new(
            self.latest_block_hash(),
            Utc::now().timestamp() as u64,
            &self.tx_mempool,
        );

        let hash = block.hash()?;
        let block_fs = BlockFs {
            key: hash,
            value: block,
        };

        let block_fs_json = serde_json::to_string(&block_fs)?;

        println!("persisiting new block to fs");
        println!("{}", block_fs_json);

        writeln!(self.db_file, "{}", block_fs_json)?;
        self.latest_block_hash = hash;

        self.tx_mempool = vec![];

        Ok(self.latest_block_hash)

        // let tx_mempool = self.tx_mempool.clone();
        // for (i, tx) in tx_mempool.iter().enumerate() {
        //     let tx_string = serde_json::to_string(&tx)?;
        //     writeln!(self.db_file, "{}", tx_string)?;
        //     self.do_snapshot()?;
        //     println!("snapshot is {:?}", hex::encode(self.hash));
        //     self.tx_mempool = tx_mempool[i + 1..].to_vec();
        // }
        // self.do_snapshot()?;
        // Ok(self.hash)
    }

    pub fn latest_block_hash(&self) -> Hash {
        self.latest_block_hash
    }

    // pub fn do_snapshot(&mut self) -> Result<(), BoxError> {
    //     let _ = self.db_file.seek(std::io::SeekFrom::Start(0))?;
    //     let mut contents = String::new();
    //     self.db_file.read_to_string(&mut contents)?;
    //     let hash = Sha256::digest(contents);
    //     self.hash = hash.into();
    //     Ok(())
    // }

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

    pub fn apply_block(&mut self, b: Block) -> Result<(), BoxError> {
        for tx in b.txs {
            self.apply(tx)?;
        }
        Ok(())
    }
}
