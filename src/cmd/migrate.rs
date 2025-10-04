use chrono::Utc;
use clap::Parser;

use crate::{block::Block, state::State, tx::Tx};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct MigrateCommandArgs {}

#[derive(Default)]
pub struct MigrateCommand {}

impl MigrateCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, _args: MigrateCommandArgs) {
        let state = State::new_state_from_disk();
        let mut state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        let block_0 = Block::new(
            [0; 32],
            Utc::now().timestamp() as u64,
            &[
                Tx::new(
                    "andrej".to_string(),
                    "andrej".to_string(),
                    3,
                    "".to_string(),
                ),
                Tx::new(
                    "andrej".to_string(),
                    "andrej".to_string(),
                    700,
                    "reward".to_string(),
                ),
            ],
        );
        let res = state.add_block(block_0);
        if let Err(e) = res {
            panic!("cannot add block_0: {e:?}");
        }
        let block_0_hash = state.persist();
        let block_0_hash = match block_0_hash {
            Ok(hash) => hash,
            Err(e) => {
                panic!("cannot persist block 0: {e:?}");
            }
        };

        let block_1 = Block::new(
            block_0_hash,
            Utc::now().timestamp() as u64,
            &[
                Tx::new(
                    "andrej".to_string(),
                    "babayaga".to_string(),
                    2000,
                    "".to_string(),
                ),
                Tx::new(
                    "andrej".to_string(),
                    "andrej".to_string(),
                    100,
                    "reward".to_string(),
                ),
                Tx::new(
                    "babayaga".to_string(),
                    "andrej".to_string(),
                    1,
                    "".to_string(),
                ),
                Tx::new(
                    "babayaga".to_string(),
                    "caesar".to_string(),
                    1000,
                    "".to_string(),
                ),
                Tx::new(
                    "babayaga".to_string(),
                    "andrej".to_string(),
                    50,
                    "".to_string(),
                ),
                Tx::new(
                    "andrej".to_string(),
                    "andrej".to_string(),
                    600,
                    "reward".to_string(),
                ),
            ],
        );

        let res = state.add_block(block_1);
        if let Err(e) = res {
            panic!("cannot add block_1: {e:?}");
        }
        let _ = state.persist();
    }
}
