use alloy::signers::local::LocalSigner;
use clap::Parser;

use crate::{BoxError, wallet};

#[derive(Debug, Default, Parser)]
#[command(flatten_help = true)]
pub struct WalletCommandArgs {
    #[arg(short, long)]
    pub data_dir: String,
}

#[derive(Default)]
pub struct WalletCommand {}

impl WalletCommand {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn new_account(&self, args: WalletCommandArgs) {
        let password = rpassword::prompt_password("Your password: ").unwrap();
        let repeated_password = rpassword::prompt_password("repeat password: ").unwrap();
        if password != repeated_password {
            panic!("password and repeated_password are not the same");
        }

        let address = wallet::new_keystore_account(&args.data_dir, &password).unwrap();
        println!("new account created: {}", address);
        println!(
            "saved in: {}",
            wallet::get_keystore_dir_path(&args.data_dir)
        );
    }

    pub async fn print(&self, args: WalletCommandArgs) {
        let password = rpassword::prompt_password("Your password: ").unwrap();
        let repeated_password = rpassword::prompt_password("repeat password: ").unwrap();
        if password != repeated_password {
            panic!("password and repeated_password are not the same");
        }

        let res =
            LocalSigner::decrypt_keystore(wallet::get_keystore_dir_path(&args.data_dir), password)
                .expect("should have read");
        println!("your address: {}", res.address());
        println!("your privateKey: {}", hex::encode(res.to_bytes()));
    }

    pub async fn get_pass_phrase() -> Result<String, BoxError> {
        //TODO: today
        unimplemented!()
    }
}
