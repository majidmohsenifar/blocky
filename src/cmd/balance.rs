use clap::Parser;

use crate::state::State;

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct BalanceCommandArgs {}

#[derive(Default)]
pub struct BalanceCommand {}

impl BalanceCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, _args: BalanceCommandArgs) {
        let state = State::new_state_from_disk();
        let state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        println!(
            "Accounts balances at {:?}:\n",
            hex::encode(state.latest_block_hash())
        );
        state.balances.iter().for_each(|(a, b)| {
            println!("account:{}, balance:{}", a, b);
        });
    }
}
