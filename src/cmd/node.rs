use alloy::primitives::Address;
use clap::Parser;
use std::str::FromStr;
use tokio::sync::mpsc;

use crate::{
    node::{HttpServer, Node, PeerNode},
    state::State,
};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct NodeCommandArgs {
    #[arg(short, long)]
    pub data_dir: String,
    #[arg(short, long)]
    pub ip: String,
    #[arg(short, long)]
    pub port: Option<u16>,
    #[arg(short, long)]
    pub miner: String,
    #[arg(long)]
    pub bootstrap_account: String,
    #[arg(long)]
    pub bootstrap_ip: String,
    #[arg(long)]
    pub bootstrap_port: Option<u16>,
}

#[derive(Default)]
pub struct NodeCommand {}

impl NodeCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, args: NodeCommandArgs) {
        let state = State::new_state_from_disk(&args.data_dir);
        let state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        let port = args.port.unwrap_or(8083);
        let bootstrap_node = PeerNode::new(
            args.bootstrap_ip,
            args.bootstrap_port.unwrap_or(8083), //must be always the known one,
            true,
            Address::from_str(&args.bootstrap_account).unwrap(),
            false,
        );

        let (pending_tx_sender, _pending_tx_receiver) = mpsc::channel(100);
        let (new_synced_blocks_sender, new_synced_blocks_receiver) = mpsc::channel(100);

        let node = Node::new(
            state,
            args.data_dir,
            args.ip,
            port,
            Address::from_str(&args.miner).unwrap(),
            bootstrap_node,
            pending_tx_sender,
            new_synced_blocks_sender,
            new_synced_blocks_receiver,
        );

        let server = HttpServer::build(node).await;
        server.run().await.unwrap();
    }
}
