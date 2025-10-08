use clap::Parser;

use crate::node::{HttpServer, PeerNode};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct NodeCommandArgs {
    #[arg(short, long)]
    pub data_dir: String,
    #[arg(short, long)]
    port: Option<u16>,
}

#[derive(Default)]
pub struct NodeCommand {}

impl NodeCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, args: NodeCommandArgs) {
        let port = args.port.unwrap_or(8080);
        let bootstrap_node = PeerNode {
            ip: "127.0.0.1".to_string(),
            port: 8083, //must be always the known one,
            is_bootstrap: true,
            connected: false,
        };
        let server = HttpServer::build(args.data_dir, port, bootstrap_node).await;
        server.run().await.unwrap()
    }
}
