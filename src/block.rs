use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::{BoxError, tx::Tx};

pub type Hash = [u8; 32];

#[derive(Serialize, Deserialize)]
pub struct BlockFs {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    pub key: Hash,
    pub value: Block,
}

#[derive(Serialize, Deserialize)]
pub struct BlockHeader {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    parent: Hash,
    time: u64,
}

// Serialization: Hash -> hex string
fn hash_to_hex<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(hash))
}

// Deserialization: hex string -> Hash
fn hash_from_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(&s).map_err(D::Error::custom)?;
    if bytes.len() != 32 {
        return Err(D::Error::custom("invalid hash length"));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

#[derive(Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    #[serde(rename = "payload")]
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn new(parent_hash: Hash, time: u64, txs: &[Tx]) -> Self {
        Self {
            header: BlockHeader {
                parent: parent_hash,
                time,
            },
            txs: txs.to_vec(),
        }
    }

    pub fn hash(&self) -> Result<Hash, BoxError> {
        let res = serde_json::to_string(self)?;
        let hash = Sha256::digest(res);
        Ok(hash.into())
    }
}
