use blocky::cmd::{
    balance::{BalanceCommand, BalanceCommandArgs},
    migrate::{MigrateCommand, MigrateCommandArgs},
    node::{NodeCommand, NodeCommandArgs},
    version::{VersionCommand, VersionCommandArgs},
    wallet::{WalletCommand, WalletCommandArgs},
};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "cli")]
#[command(about = "Blocky CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    args: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Version(VersionCommandArgs),
    Balance(BalanceCommandArgs),
    Node(NodeCommandArgs),
    Migrate(MigrateCommandArgs),
    #[command(subcommand)]
    Wallet(WalletCmd),
}

#[derive(Debug, Subcommand)]
enum WalletCmd {
    New(WalletCommandArgs),
    Print(WalletCommandArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::try_parse().unwrap_or_else(|e| {
        panic!("cannot parse cli due to err: {}", e);
    });

    if let Some(command) = cli.command {
        //we are adding this because clap expect the first argument to be the program name
        let mut args_with_prog = vec!["cli".to_string()];
        args_with_prog.extend(cli.args.clone());
        match command {
            Command::Version(args) => {
                let cmd = VersionCommand::new();
                cmd.run(args).await;
            }
            Command::Balance(args) => {
                let cmd = BalanceCommand::new();
                cmd.run(args).await;
            }
            Command::Node(args) => {
                let cmd = NodeCommand::new();
                cmd.run(args).await;
            }
            Command::Migrate(args) => {
                let cmd = MigrateCommand::new();
                cmd.run(args).await;
            }
            Command::Wallet(wallet_cmd) => match wallet_cmd {
                WalletCmd::New(args) => {
                    let cmd = WalletCommand::new();
                    cmd.new_account(args).await;
                }
                WalletCmd::Print(args) => {
                    let cmd = WalletCommand::new();
                    cmd.print(args).await;
                }
            },
        }
        return;
    }
}
