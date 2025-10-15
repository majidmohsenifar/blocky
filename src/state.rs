use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    sync::Arc,
};

use alloy::primitives::Address;

use crate::{
    BoxError,
    block::{BLOCK_REWARD, Block, BlockFs, BlockHeader, Hash, is_block_hash_valid},
    fs,
    genesis::Genesis,
    tx::SignedTx,
};

#[derive(Debug, Clone)]
pub struct State {
    pub balances: HashMap<Address, u64>,
    pub account_to_nonces: HashMap<Address, u64>,

    pub db_file: Arc<std::fs::File>,
    pub latest_block: Block,
    pub latest_block_hash: Hash,
    pub has_genesis_block: bool,
}

impl State {
    pub fn new_state_from_disk(data_dir: &str) -> Result<State, BoxError> {
        fs::init_data_dir_if_not_exists(data_dir)?;
        let genesis = Genesis::new_from_file_path(&fs::get_genesis_json_file_path(data_dir))?;
        let mut balances = HashMap::new();
        for (addr, b) in genesis.balances {
            balances.insert(addr, b);
        }

        let db_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(fs::get_blocks_db_file_path(data_dir))?;

        let mut state = State {
            balances,
            account_to_nonces: HashMap::new(),
            db_file: Arc::new(db_file.try_clone()?),
            latest_block: Block {
                header: BlockHeader {
                    parent: [0; 32],
                    number: 0,
                    nonce: 0, //TODO: is this correct
                    time: 0,
                    miner: Address::ZERO, //TODO: is this correct
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

    pub fn latest_block_hash(&self) -> Hash {
        self.latest_block_hash
    }

    pub fn next_block_number(&self) -> u64 {
        if !self.has_genesis_block {
            return 0;
        }
        self.latest_block.header.number + 1
    }

    pub fn next_account_nonce(&self, account: Address) -> u64 {
        self.account_to_nonces
            .get(&account)
            .map(|n| n + 1)
            .unwrap_or(1)
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

pub fn apply_txs(state: &mut State, mut txs: Vec<SignedTx>) -> Result<(), BoxError> {
    txs.sort_by_key(|item| item.tx.time);
    for tx in txs {
        apply_tx(state, tx)?;
    }
    Ok(())
}

pub fn apply_tx(state: &mut State, signed_tx: SignedTx) -> Result<(), BoxError> {
    signed_tx.is_authentic()?;
    let tx = signed_tx.tx;

    println!("balances before tx: {:?}", state.balances);

    if let Some(b) = state.balances.get_mut(&tx.from) {
        if *b < tx.value {
            println!(
                "or here you mean b: {},v: {}, from {}",
                &tx.from, *b, tx.value
            );
            return Err("insufficient balance".into());
        }
        *b -= tx.value;
    } else {
        println!("here you mean");
        return Err("insufficient balance".into());
    };
    state
        .balances
        .entry(tx.to)
        .and_modify(|b| *b += tx.value)
        .or_insert(tx.value);

    state.account_to_nonces.insert(tx.from, tx.nonce);

    Ok(())
}
