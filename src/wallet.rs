use std::path::PathBuf;

use alloy::{
    primitives::Address,
    signers::{Signature, Signer, local::PrivateKeySigner},
};

use crate::BoxError;

pub fn get_keystore_dir_path(data_dir: &str) -> String {
    PathBuf::from(data_dir)
        .join("keystore")
        .to_string_lossy()
        .to_string()
}

pub async fn sign(msg: &[u8], priv_key: PrivateKeySigner) -> Result<Signature, BoxError> {
    Ok(priv_key.sign_message(msg).await?)
}

pub fn verify(msg: &[u8], sig: Signature) -> Result<Address, BoxError> {
    Ok(sig.recover_address_from_msg(msg)?)
}
