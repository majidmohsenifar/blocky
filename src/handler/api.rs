use crate::{
    block::{Block, Hash, hash_from_hex, hash_to_hex},
    database,
    node::AxumAppState,
    node::PeerNode,
    tx::{SignedTx, Tx},
    wallet,
};
use alloy::primitives::Address;
use axum::{
    Json,
    extract::{Query, Request, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use utoipa::{IntoParams, ToSchema};

#[derive(Serialize, Deserialize, ToSchema)]
pub struct ErrorRes {
    pub message: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddTxReq {
    pub from: String,
    pub from_pwd: String, //password of key_store
    pub to: String,
    pub value: u64,
    pub data: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddTxRes {
    pub success: bool,
}

#[utoipa::path(
        post,
        path = "/tx/add",
        responses(
            (status = OK, description = "", body = AddTxRes),
            (status = BAD_REQUEST, body = ErrorRes),
            (status = INTERNAL_SERVER_ERROR, body = ErrorRes, description = "something went wrong in server"),
        ),
        request_body = AddTxReq,
)]
pub async fn add_tx(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
        Ok(b) => b,
    };
    let params: AddTxReq = match serde_json::from_slice(&body) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
        Ok(p) => p,
    };

    let from_address = match Address::from_str(&params.from.to_lowercase()) {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
    };

    let to_address = match Address::from_str(&params.to.to_lowercase()) {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
    };

    let node = state.node;
    let state = node.state.read().await;
    let nonce = state.next_block_number();

    let tx = Tx::new(from_address, to_address, params.value, nonce, params.data);
    let signed_tx = wallet::sign_tx_with_keystore_account(
        tx,
        &params.from_pwd,
        &wallet::get_keystore_dir_path(&node.data_dir),
    )
    .await;

    let signed_tx = match signed_tx {
        Ok(s_tx) => s_tx,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
    };
    match node.add_pending_tx(signed_tx).await {
        Ok(_) => (StatusCode::OK, Json(AddTxRes { success: true })).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorRes {
                message: format!("error: {}", e),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct BalancesRes {
    pub hash: String,
    #[schema(value_type = HashMap<String, u64>)]
    pub balances: HashMap<Address, u64>,
}

#[utoipa::path(
        get,
        path = "/balances/list",
        responses(
            (status = OK, description = "", body = BalancesRes),
        ),
)]
pub async fn balances(State(state): State<AxumAppState>, _req: Request) -> impl IntoResponse {
    let blockchain_state = state.node.state.read().await;
    let balances = blockchain_state.balances.clone();
    let latest_block_hash = blockchain_state.latest_block_hash;

    (
        StatusCode::OK,
        Json(BalancesRes {
            hash: hex::encode(latest_block_hash),
            balances,
        }),
    )
        .into_response()
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct StatusRes {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    #[schema(value_type = String)]
    pub block_hash: Hash,
    pub block_number: u64,
    pub known_peers: Vec<PeerNode>,
    pub pending_txs: Vec<SignedTx>,
}

#[utoipa::path(
        get,
        path = "/status",
        responses(
            (status = OK, description = "", body = StatusRes),
        ),
)]
pub async fn status(State(state): State<AxumAppState>, _req: Request) -> impl IntoResponse {
    let blockchain_state = state.node.state.read().await;
    let latest_block = blockchain_state.latest_block.clone();
    let latest_block_hash = blockchain_state.latest_block_hash;
    let known_peers = state.node.known_peers.read().await;
    let pending_txs = state.node.pending_txs.read().await;

    let res = StatusRes {
        block_hash: latest_block_hash,
        block_number: latest_block.header.number,
        known_peers: known_peers.values().cloned().collect(),
        pending_txs: pending_txs.values().cloned().collect(),
    };

    (StatusCode::OK, Json(res)).into_response()
}

#[derive(Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SyncReq {
    #[serde(default)]
    pub from_block: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SyncRes {
    pub blocks: Vec<Block>,
}

#[utoipa::path(
        get,
        path = "/node/sync",
        responses(
            (status = OK, description = "", body = SyncRes),
            (status = BAD_REQUEST, body = ErrorRes),
            (status = INTERNAL_SERVER_ERROR, body = ErrorRes, description = "something went wrong in server"),
        ),
        params(
            SyncReq,
        ),
)]
pub async fn sync(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let params: Query<SyncReq> = match Query::try_from_uri(req.uri()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
    };

    let hash = hex::decode(params.0.from_block);

    let hash_vec = match hash {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: "hash is not valid".to_string(),
                }),
            )
                .into_response();
        }
    };

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hash_vec);
    let blocks = database::get_blocks_after(&state.node.data_dir, hash).await;
    let blocks = match blocks {
        Ok(blocks) => blocks,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorRes {
                    message: format!("something went wrong: {}", e),
                }),
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(SyncRes { blocks })).into_response()
}

#[derive(Serialize, Deserialize, ToSchema, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AddPeerReq {
    #[serde(default)]
    pub ip: String,
    pub port: u16,
    pub miner: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct AddPeerRes {
    pub success: bool,
    pub error: String,
}

#[utoipa::path(
        get,
        path = "/node/peer",
        responses(
            (status = OK, description = "", body = AddPeerRes),
            (status = BAD_REQUEST, body = ErrorRes),
            (status = INTERNAL_SERVER_ERROR, body = ErrorRes, description = "something went wrong in server"),
        ),
        params(
            AddPeerReq,
        ),
)]
pub async fn add_peer(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let params: Query<AddPeerReq> = match Query::try_from_uri(req.uri()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("invalid request body: {}", e),
                }),
            )
                .into_response();
        }
    };
    let miner = match Address::from_str(&params.0.miner) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorRes {
                    message: format!("miner address is not valid: {}", e),
                }),
            )
                .into_response();
        }
    };

    let res = state
        .node
        .add_peer(&PeerNode {
            ip: params.0.ip,
            port: params.0.port,
            is_bootstrap: false,
            account: miner,
            connected: true,
        })
        .await;
    if let Err(e) = res {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorRes {
                message: format!("cannot add peer: {}", e),
            }),
        )
            .into_response();
    }

    let res = AddPeerRes {
        success: true,
        error: "".to_string(),
    };

    (StatusCode::OK, Json(res)).into_response()
}
