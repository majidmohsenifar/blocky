use clap::Parser;
use tokio::sync::mpsc;

use crate::{
    node::{HttpServer, Node, PeerNode},
    state::State,
    tx::Tx,
};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct MigrateCommandArgs {
    #[arg(short, long)]
    pub data_dir: String,
    #[arg(short, long)]
    pub ip: String,
    #[arg(short, long)]
    port: Option<u16>,
    #[arg(short, long)]
    pub miner: String,
}

#[derive(Default)]
pub struct MigrateCommand {}

impl MigrateCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, args: MigrateCommandArgs) {
        let state = State::new_state_from_disk(&args.data_dir);
        let state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };

        let bootstrap_node = PeerNode::new(
            "127.0.0.1".to_string(),
            8083, //must be always the known one,
            true,
            "andrej".to_string(),
            false,
        );

        let (pending_tx_sender, _pending_tx_receiver) = mpsc::channel(100);
        let (synced_block_sender, _synced_block_receiver) = mpsc::channel(100);

        let mut node = Node::new(
            state,
            args.data_dir,
            args.ip,
            args.port.unwrap_or(8083),
            args.miner,
            bootstrap_node,
            pending_tx_sender,
            synced_block_sender,
        );
        node.add_pending_tx(Tx::new(
            "andrej".to_string(),
            "andrej".to_string(),
            3,
            "".to_string(),
        ))
        .await
        .unwrap();

        node.add_pending_tx(Tx::new(
            "andrej".to_string(),
            "babayaga".to_string(),
            2000,
            "".to_string(),
        ))
        .await
        .unwrap();

        node.add_pending_tx(Tx::new(
            "babayaga".to_string(),
            "andrej".to_string(),
            1,
            "".to_string(),
        ))
        .await
        .unwrap();

        node.add_pending_tx(Tx::new(
            "babayaga".to_string(),
            "caesar".to_string(),
            1000,
            "".to_string(),
        ))
        .await
        .unwrap();

        node.add_pending_tx(Tx::new(
            "babayaga".to_string(),
            "andrej".to_string(),
            50,
            "".to_string(),
        ))
        .await
        .unwrap();
        let server = HttpServer::build(node).await;
        server.run().await.unwrap();
    }
}
