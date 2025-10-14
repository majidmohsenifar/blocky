use std::time::Duration;

use alloy::primitives::Address;
use chrono::Utc;
use tokio::{select, time::sleep};
use tokio_util::sync::CancellationToken;

use crate::{
    BoxError,
    block::{Block, Hash, is_block_hash_valid},
    tx::SignedTx,
};

pub struct PendingBlock {
    parent: Hash,
    number: u64,
    time: u64,
    miner: Address,
    txs: Vec<SignedTx>,
}

impl PendingBlock {
    pub fn new(parent: Hash, number: u64, miner: Address, txs: Vec<SignedTx>) -> Self {
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
    if pb.txs.is_empty() {
        return Err("mining empty blocks is not allowed".into());
    }

    //TODO: today, what if we have new pending tx in the middle of mining
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
        let block = Block::new(pb.parent, pb.number, nonce, pb.time, pb.miner, &pb.txs);
        let hash = block.hash()?;
        if is_block_hash_valid(hash) {
            return Ok(block);
        }
    }
}

pub fn generate_nonce() -> u32 {
    rand::random()
}
