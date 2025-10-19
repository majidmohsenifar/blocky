use crate::BoxError;
use crate::tx::SignedTx;
use alloy::primitives::Address;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

pub type Hash = [u8; 32];
pub const BLOCK_REWARD: u64 = 100;

#[derive(Serialize, Deserialize)]
pub struct BlockFs {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    pub key: Hash,
    pub value: Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BlockHeader {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    #[schema(value_type = String)]
    pub parent: Hash,
    #[serde(default)]
    pub number: u64,
    pub nonce: u32,
    pub time: u64,
    #[schema(value_type = String)]
    pub miner: Address,
}

// Serialization: Hash -> hex string
pub fn hash_to_hex<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(hash))
}

// Deserialization: hex string -> Hash
pub fn hash_from_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Block {
    pub header: BlockHeader,
    #[serde(rename = "payload")]
    pub txs: Vec<SignedTx>,
}

impl Block {
    pub fn new(
        parent_hash: Hash,
        number: u64,
        nonce: u32,
        time: u64,
        miner: Address,
        txs: &[SignedTx],
    ) -> Self {
        Self {
            header: BlockHeader {
                parent: parent_hash,
                number,
                nonce,
                time,
                miner,
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

pub fn is_block_hash_valid(hash: Hash) -> bool {
    hash[..2].iter().all(|&byte| byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_block_hash_valid() {
        let hash_vec =
            hex::decode("000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c")
                .unwrap();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_vec);
        assert!(is_block_hash_valid(hash));
    }
}
