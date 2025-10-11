use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    sync::Arc,
};

use crate::{
    BoxError,
    block::{BLOCK_REWARD, Block, BlockFs, BlockHeader, Hash, is_block_hash_valid},
    fs,
    genesis::Genesis,
    tx::{Account, Tx},
};

#[derive(Debug, Clone)]
pub struct State {
    pub balances: HashMap<Account, u64>,
    pub tx_mempool: Vec<Tx>,
    pub db_file: Arc<std::fs::File>,
    pub latest_block: Block,
    pub latest_block_hash: Hash,
    has_genesis_block: bool,
}

impl State {
    pub fn new_state_from_disk(data_dir: &str) -> Result<State, BoxError> {
        fs::init_data_dir_if_not_exists(data_dir)?;
        let genesis = Genesis::new_from_file_path(&fs::get_genesis_json_file_path(data_dir))?;
        let mut balances = HashMap::new();
        for (acc, b) in &genesis.balances {
            balances.insert(acc.to_string(), *b);
        }

        let db_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(fs::get_blocks_db_file_path(data_dir))?;

        let mut state = State {
            balances,
            tx_mempool: vec![],
            db_file: Arc::new(db_file.try_clone()?),
            latest_block: Block {
                header: BlockHeader {
                    parent: [0; 32],
                    number: 0,
                    nonce: 0, //TODO: today is this correct
                    time: 0,
                    miner: "".to_string(),
                },
                txs: vec![],
            },
            latest_block_hash: [0; 32],
            has_genesis_block: false,
        };

        let reader = BufReader::new(db_file);
        for line in reader.lines() {
            let line = line?;
            let block_fs: BlockFs = serde_json::from_str(&line)?;

            apply_txs(&mut state, block_fs.value.clone().txs)?;

            state.latest_block_hash = block_fs.key;
            state.latest_block = block_fs.value;
            state.has_genesis_block = true;
        }
        Ok(state)
    }

    pub fn add_block(&mut self, b: Block) -> Result<Hash, BoxError> {
        let mut state = self.clone();
        apply_block(&mut state, b.clone())?;
        let block_hash = b.hash()?;
        let block_fs = BlockFs {
            key: block_hash,
            value: b.clone(),
        };
        let block_fs_json = serde_json::to_string(&block_fs)?;
        writeln!(self.db_file, "{}", block_fs_json)?;
        self.balances = state.balances;
        self.latest_block_hash = block_hash;
        self.latest_block = b;
        self.has_genesis_block = true;

        Ok(block_hash)
    }

    pub fn add_blocks(&mut self, blocks: Vec<Block>) -> Result<(), BoxError> {
        for b in blocks {
            self.add_block(b)?;
        }
        Ok(())
    }

    pub fn latest_block_hash(&self) -> Hash {
        self.latest_block_hash
    }

    pub fn next_block_number(&self) -> u64 {
        if !self.has_genesis_block {
            return 0;
        }
        self.latest_block.header.number + 1
    }
}

pub fn apply_block(state: &mut State, b: Block) -> Result<(), BoxError> {
    let next_expected_block_number = state.latest_block.header.number + 1;
    if state.has_genesis_block && b.header.number != next_expected_block_number {
        return Err(format!(
            "next expected block must be {} not {}",
            next_expected_block_number, b.header.number
        )
        .into());
    }

    if state.has_genesis_block
        && state.latest_block.header.number > 0
        && b.header.parent != state.latest_block_hash()
    {
        return Err(format!(
            "next block parent hash must be {} not {}",
            hex::encode(state.latest_block_hash),
            hex::encode(b.header.parent)
        )
        .into());
    }

    if !is_block_hash_valid(b.hash()?) {
        return Err("invalid block hash".into());
    };

    apply_txs(state, b.txs)?;

    state
        .balances
        .entry(b.header.miner)
        .and_modify(|v| *v += BLOCK_REWARD)
        .or_insert(BLOCK_REWARD);
    Ok(())
}

pub fn apply_txs(state: &mut State, txs: Vec<Tx>) -> Result<(), BoxError> {
    for tx in txs {
        apply_tx(state, tx)?;
    }
    Ok(())
}

pub fn apply_tx(state: &mut State, tx: Tx) -> Result<(), BoxError> {
    if tx.is_reward() {
        state
            .balances
            .entry(tx.to)
            .and_modify(|b| *b += tx.value)
            .or_insert(tx.value);
        return Ok(());
    }

    if let Some(b) = state.balances.get_mut(&tx.from) {
        if *b < tx.value {
            return Err("insufficient balance".into());
        }
        *b -= tx.value;
    } else {
        return Err("insufficient balance".into());
    };
    state
        .balances
        .entry(tx.to)
        .and_modify(|b| *b += tx.value)
        .or_insert(tx.value);
    Ok(())
}
