use clap::Parser;

const MAJOR: &str = "0";
const MINOR: &str = "1";
const FIX: &str = "0";
const VERBAL: &str = "TX Add && Balances List";

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct VersionCommandArgs {}

#[derive(Default)]
pub struct VersionCommand {}

impl VersionCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn run(&self, _args: VersionCommandArgs) {
        println!("Version:{}.{}.{}-beta {}", MAJOR, MINOR, FIX, VERBAL);
    }
}
