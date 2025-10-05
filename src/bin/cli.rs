use std::process;

use blocky::cmd::{
    balance::{BalanceCommand, BalanceCommandArgs},
    migrate::{MigrateCommand, MigrateCommandArgs},
    node::{NodeCommand, NodeCommandArgs},
    tx::{TxCommand, TxCommandArgs},
    version::{VersionCommand, VersionCommandArgs},
};
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "cli")]
#[command(about = "Blocky CLI", long_about = None)]
struct Cli {
    #[arg(value_enum)]
    command: Option<Command>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, ValueEnum)]
enum Command {
    Version,
    Balance,
    Tx,
    Node,
    Migrate,
}

#[tokio::main]
async fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        tracing::error!("cannot parse cli due to err: {}", e);
        process::exit(1);
    });

    if let Some(command) = cli.command {
        //we are adding this because clap expect the first argument to be the program name
        let mut args_with_prog = vec!["cli".to_string()];
        args_with_prog.extend(cli.args.clone());
        match command {
            Command::Version => {
                let args = VersionCommandArgs::parse_from(args_with_prog);
                let cmd = VersionCommand::new();
                cmd.run(args).await;
            }
            Command::Balance => {
                let args = BalanceCommandArgs::parse_from(args_with_prog);
                let cmd = BalanceCommand::new();
                cmd.run(args).await;
            }
            Command::Tx => {
                let args = TxCommandArgs::parse_from(args_with_prog);
                let cmd = TxCommand::new();
                cmd.run(args).await;
            }
            Command::Node => {
                let args = NodeCommandArgs::parse_from(args_with_prog);
                let cmd = NodeCommand::new();
                cmd.run(args).await;
            }
            Command::Migrate => {
                let args = MigrateCommandArgs::parse_from(args_with_prog);
                let cmd = MigrateCommand::new();
                cmd.run(args).await;
            }
        }
        return;
    }
}
