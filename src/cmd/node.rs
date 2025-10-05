use clap::Parser;

use crate::{node::HttpServer, state::State};

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
        let state = State::new_state_from_disk(&args.data_dir);
        let state = match state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        println!("running http server on port {}", port);
        let server = HttpServer::build(state, port).await;
        server.run().await.unwrap()
    }
}
