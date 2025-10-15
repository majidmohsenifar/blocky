use std::path::PathBuf;

use alloy::{
    primitives::Address,
    signers::{
        Signature, Signer,
        local::{LocalSigner, PrivateKeySigner},
    },
};

use crate::{
    BoxError,
    tx::{SignedTx, Tx},
};

pub fn get_keystore_dir_path(data_dir: &str) -> String {
    PathBuf::from(data_dir)
        .join("keystore")
        .to_string_lossy()
        .to_string()
}

pub fn new_keystore_account(data_dir: &str, password: &str) -> Result<Address, BoxError> {
    let mut rng = rand::thread_rng();
    let priv_key = PrivateKeySigner::random();

    let _ = LocalSigner::encrypt_keystore(
        data_dir,
        &mut rng,
        priv_key.to_bytes(),
        password,
        Some(&get_keystore_dir_path(data_dir)),
    )?;
    Ok(priv_key.address())
}

pub async fn sign_tx_with_keystore_account(
    tx: Tx,
    password: &str,
    key_store_dir: &str,
) -> Result<SignedTx, BoxError> {
    let signer = LocalSigner::decrypt_keystore(key_store_dir, password)?;
    let tx_serialized = serde_json::to_vec(&tx)?;
    let sig = signer.sign_message(tx_serialized.as_slice()).await?;

    Ok(SignedTx {
        tx,
        sig: sig.into(),
    })
}

pub async fn sign(msg: &[u8], priv_key: PrivateKeySigner) -> Result<Signature, BoxError> {
    Ok(priv_key.sign_message(msg).await?)
}

pub fn verify(msg: &[u8], sig: Signature) -> Result<Address, BoxError> {
    Ok(sig.recover_address_from_msg(msg)?)
}
