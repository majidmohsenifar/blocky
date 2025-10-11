use std::time::Duration;

use chrono::Utc;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;

use crate::{
    BoxError,
    block::{Block, Hash, is_block_hash_valid},
    tx::{Account, Tx},
};

pub struct PendingBlock {
    parent: Hash,
    number: u64,
    time: u64,
    miner: Account,
    txs: Vec<Tx>,
}

impl PendingBlock {
    pub fn new(parent: Hash, number: u64, miner: Account, txs: Vec<Tx>) -> Self {
        Self {
            parent,
            number,
            time: Utc::now().timestamp() as u64,
            miner,
            txs,
        }
    }
}

pub async fn mine(
    cancellation_token: CancellationToken,
    pb: PendingBlock,
) -> Result<Block, BoxError> {
    if pb.txs.len() == 0 {
        return Err("mining empty blocks is not allowed".into());
    }

    let mut attempt = 0;

    loop {
        select! {
            _ = cancellation_token.cancelled()=>{
                return Err("mining canceled".into());

            }
            _ = sleep(Duration::from_secs(0)) => {},
        }
        attempt += 1;
        let nonce = generate_nonce();
        if attempt % 100_000 == 0 || attempt == 1 {
            println!("mining {} pending txs, attempt: {attempt}", pb.txs.len());
        }
        let block = Block::new(
            pb.parent,
            pb.number,
            nonce,
            pb.time,
            pb.miner.clone(),
            &pb.txs,
        );
        let hash = block.hash()?;
        if is_block_hash_valid(hash) {
            return Ok(block);
        }
    }
}

pub fn generate_nonce() -> u32 {
    rand::random()
}
