use clap::Parser;

use crate::{
    state::State,
    tx::{Account, Tx},
};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct TxCommandArgs {
    #[arg(short, long)]
    pub from: String,
    #[arg(short, long)]
    pub to: String,
    #[arg(short, long)]
    pub value: u64,
    #[arg(short, long)]
    pub data: Option<String>,
    #[arg(long)]
    pub data_dir: String,
}

#[derive(Default)]
pub struct TxCommand {}

impl TxCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, args: TxCommandArgs) {
        let from_acc: Account = args.from;
        let to_acc: Account = args.to;
        let tx = Tx::new(
            from_acc,
            to_acc,
            args.value,
            args.data.unwrap_or("".to_string()),
        );
        let state = State::new_state_from_disk(&args.data_dir);
        let mut state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        let res = state.add(tx);
        if let Err(e) = res {
            panic!("cannot add tx: {e:?}");
        }
        let res = state.persist();
        if let Err(e) = res {
            panic!("cannot persist tx: {e:?}");
        }

        println!("snapshot {}", hex::encode(state.latest_block_hash()));
    }
}
