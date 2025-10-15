use crate::{
    BoxError,
    block::{Block, Hash, hash_from_hex, hash_to_hex},
    database,
    miner::{self, PendingBlock},
    state::{self, State as BlockchainState},
    tx::{SignedTx, Tx},
    wallet,
};
use alloy::primitives::Address;
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io,
    net::TcpListener,
    select,
    sync::{RwLock, mpsc},
    time::{Duration, interval},
};
use tokio_util::sync::CancellationToken;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct AxumAppState {
    pub node: Node,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub ip: String,
    pub port: u16,
    pub is_bootstrap: bool,
    pub account: Address,
    // Whenever my node already established connection, sync with this Peer
    pub connected: bool,
}

impl PeerNode {
    pub fn new(
        ip: String,
        port: u16,
        is_bootstrap: bool,
        account: Address,
        connected: bool,
    ) -> Self {
        Self {
            ip,
            port,
            is_bootstrap,
            account,
            connected,
        }
    }

    pub fn tcp_addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

pub struct HttpServer {
    router: Router,
    listener: TcpListener,
    axum_app_state: AxumAppState,
}

#[derive(Clone)]
pub struct Node {
    state: Arc<RwLock<BlockchainState>>,
    pending_state: Arc<RwLock<BlockchainState>>,
    info: PeerNode,
    data_dir: String,
    ip: String,
    port: u16,
    known_peers: Arc<RwLock<HashMap<String, PeerNode>>>,
    pending_txs: Arc<RwLock<HashMap<String, SignedTx>>>,
    archived_txs: Arc<RwLock<HashMap<String, SignedTx>>>,
    new_pending_txs: Arc<RwLock<mpsc::Sender<SignedTx>>>,
    new_synced_blocks_sender: Arc<RwLock<mpsc::Sender<Block>>>,
    new_synced_blocks_receiver: Arc<RwLock<mpsc::Receiver<Block>>>,
    is_mining: Arc<RwLock<bool>>,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: BlockchainState,
        data_dir: String,
        ip: String,
        port: u16,
        account: Address,
        bootstrap: PeerNode,
        pending_tx_sender: mpsc::Sender<SignedTx>,
        new_synced_blocks_sender: mpsc::Sender<Block>,
        new_synced_blocks_receiver: mpsc::Receiver<Block>,
    ) -> Self {
        let pending_state = state.clone();
        Self {
            state: Arc::new(RwLock::new(state)),
            pending_state: Arc::new(RwLock::new(pending_state)),
            info: PeerNode::new(ip.clone(), port, false, account, true),
            data_dir,
            ip,
            port,
            known_peers: Arc::new(RwLock::new(HashMap::from([(
                bootstrap.tcp_addr(),
                bootstrap,
            )]))),
            pending_txs: Arc::new(RwLock::new(HashMap::new())),
            archived_txs: Arc::new(RwLock::new(HashMap::new())),
            new_pending_txs: Arc::new(RwLock::new(pending_tx_sender)),
            new_synced_blocks_sender: Arc::new(RwLock::new(new_synced_blocks_sender)),
            new_synced_blocks_receiver: Arc::new(RwLock::new(new_synced_blocks_receiver)),
            is_mining: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn remove_mined_pending_txs(&mut self, b: &Block) {
        let mut pending_txs = self.pending_txs.write().await;
        let mut archived_txs = self.archived_txs.write().await;
        b.txs.iter().for_each(|tx| {
            let key = hex::encode(tx.hash().unwrap()); //if we are here the tx_hash is valid, so unwrap is safe
            let removed_tx = pending_txs.remove(&key);
            if let Some(r_tx) = removed_tx {
                archived_txs.insert(key, r_tx);
            }
        });
    }

    pub async fn validate_tx_before_adding_to_mempool(
        &mut self,
        tx: SignedTx,
    ) -> Result<(), BoxError> {
        let mut pending_state = self.pending_state.write().await;
        state::apply_tx(&mut pending_state, tx)
    }

    pub async fn sync(self) {
        // let mut shared_node = self.0.write().await;
        let known_peers = self.known_peers.read().await;
        let peers: Vec<_> = known_peers.values().cloned().collect();
        drop(known_peers);
        let mut faulty_nodes = vec![];
        for peer in &peers {
            if peer.ip == self.ip && peer.port == self.port {
                continue;
            }
            let peer_status_res = match self.query_peer_status(peer).await {
                Ok(res) => res,
                Err(e) => {
                    println!("cannot fetch from peer {}, err: {}", peer.tcp_addr(), e);
                    faulty_nodes.push(peer);
                    continue;
                }
            };
            if let Err(e) = self.join_known_peers(peer).await {
                println!(
                    "cannot join to known peers {}, err: {:?}",
                    peer.tcp_addr(),
                    e
                );
                continue;
            }

            let _ = self
                .sync_blocks(peer, &peer_status_res)
                .await
                .inspect_err(|e| {
                    println!("cannot sync blocks,err: {}", e);
                });

            let _ = self
                .sync_known_peers(&peer_status_res.known_peers)
                .await
                .inspect_err(|e| {
                    println!("cannot sync blocks,err: {}", e);
                });

            let _ = self
                .sync_pending_txs(peer_status_res.pending_txs)
                .await
                .inspect_err(|e| {
                    println!("cannot sync pending txs,err: {}", e);
                });
        }

        let mut known_peers = self.known_peers.write().await;
        for n in faulty_nodes {
            known_peers.remove(&n.tcp_addr());
        }
    }

    pub async fn sync_pending_txs(&self, pending_txs: Vec<SignedTx>) -> Result<(), BoxError> {
        for tx in pending_txs {
            self.add_pending_tx(tx).await?;
        }
        Ok(())
    }

    pub async fn query_peer_status(&self, peer_node: &PeerNode) -> Result<StatusRes, BoxError> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/status", peer_node.tcp_addr()))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let res: StatusRes = serde_json::from_slice(&bytes)?;
        Ok(res)
    }

    pub async fn join_known_peers(&self, peer_node: &PeerNode) -> Result<(), BoxError> {
        if peer_node.connected {
            return Ok(());
        }

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://{}/node/peer?ip={}&port={}&miner={}",
                peer_node.tcp_addr(),
                self.ip,
                self.port,
                self.info.account,
            ))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let _: AddPeerRes = serde_json::from_slice(&bytes)?;

        //we are sure it exist, because we send it to this fn in caller one
        let mut known_peers = self.known_peers.write().await;
        let k_p = known_peers.get_mut(&peer_node.tcp_addr()).unwrap();
        k_p.connected = true;
        let k_p_cloned = k_p.clone();
        drop(known_peers);
        let _ = self.add_peer(&k_p_cloned).await;
        Ok(())
    }

    pub async fn sync_blocks(
        &self,
        peer_node: &PeerNode,
        status_res: &StatusRes,
    ) -> Result<(), BoxError> {
        if status_res.block_hash == [0; 32] {
            return Ok(());
        }
        let state = self.state.read().await;

        if status_res.block_number < state.latest_block.header.number {
            return Ok(());
        }
        // If it's the genesis block and we already synced it, ignore it
        if status_res.block_number == 0 && state.latest_block_hash() != [0; 32] {
            return Ok(());
        }

        let client = reqwest::Client::new();

        let req = client.get(format!(
            "http://{}/node/sync?from_block={}",
            peer_node.tcp_addr(),
            hex::encode(state.latest_block_hash())
        ));

        drop(state);

        let response = req.send().await?;

        let bytes = response.bytes().await?;
        let res: SyncRes = serde_json::from_slice(&bytes)?;
        let mut state = self.state.write().await;
        let new_synced_blocks_sender = self.new_synced_blocks_sender.write().await;
        let mut pending_state = self.pending_state.write().await;
        for b in res.blocks {
            state.add_block(b.clone())?;
            new_synced_blocks_sender.send(b).await?;
            let new_pending_state = state.clone();
            *pending_state = new_pending_state;
        }

        Ok(())
    }

    pub async fn sync_known_peers(&self, known_peers: &[PeerNode]) -> Result<(), BoxError> {
        for p in known_peers {
            self.add_peer(p).await?;
        }
        Ok(())
    }

    pub async fn add_peer(&self, peer_node: &PeerNode) -> Result<(), BoxError> {
        self.known_peers
            .write()
            .await
            .insert(peer_node.tcp_addr(), peer_node.clone());
        Ok(())
    }

    pub async fn mine(&self, cancellation_token: CancellationToken) -> Result<(), BoxError> {
        let mut mining_interval = interval(Duration::from_secs(10));
        loop {
            let mining_cancellation_token = CancellationToken::new();
            let mut new_synced_blocks_receiver = self.new_synced_blocks_receiver.write().await;
            select! {
                _ = cancellation_token.cancelled() => {
                    break;
                }

                block = new_synced_blocks_receiver.recv() =>{
                match block{
                        Some(b)=>{
                            let mut self_clone = self.clone();
                            if *self.is_mining.read().await{
                                println!("another peer mined faster");
                                self_clone.remove_mined_pending_txs(&b).await;
                                mining_cancellation_token.cancel();
                            }

                        }
                        None =>{
                            continue;
                        }
                    }
                }
                _ = mining_interval.tick() => {
                    let mut self_clone = self.clone();
                    let cancellation_token_cloned = cancellation_token.clone();
                    tokio::spawn(async move {
                        let state= self_clone.state.read().await;
                        let pending_txs = self_clone.pending_txs.read().await;
                        let mut is_mining = self_clone.is_mining.write().await;
                        if !pending_txs.is_empty()  && !*is_mining {
                                *is_mining = true;
                        let block_to_mine = PendingBlock::new(
                                state.latest_block_hash(),
                                state.next_block_number(),
                                self_clone.info.account,
                                pending_txs.values().cloned().collect(),
                        );
                        drop(state);
                        drop(is_mining);
                        drop(pending_txs);
                        let mined_block = miner::mine(cancellation_token_cloned, block_to_mine).await.unwrap();
                        self_clone.remove_mined_pending_txs(&mined_block).await;
                        let mut state = self_clone.state.write().await;
                        state.add_block(mined_block).unwrap();
                        let new_pending_state = state.clone();
                        drop(state);
                        let mut pending_state = self_clone.pending_state.write().await;
                        *pending_state = new_pending_state;
                        *self_clone.is_mining.write().await=false;
                        }
                   });
                }
                    // _ = future::ready(()) => {}
            }
        }
        Ok(())
    }

    pub async fn add_pending_tx(&self, tx: SignedTx) -> Result<(), BoxError> {
        let tx_hash = hex::encode(tx.hash()?);

        let mut self_clone = self.clone();
        self_clone
            .validate_tx_before_adding_to_mempool(tx.clone())
            .await?;

        let mut pending_txs = self.pending_txs.write().await;
        let archived_txs = self.archived_txs.read().await;
        let new_pending_txs = self.new_pending_txs.write().await;
        if !pending_txs.contains_key(&tx_hash) && !archived_txs.contains_key(&tx_hash) {
            pending_txs.insert(tx_hash, tx.clone());
            new_pending_txs.send(tx).await?;
        }
        Ok(())
    }
}

impl HttpServer {
    pub async fn build(node: Node) -> Self {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", node.port))
            .await
            .unwrap();

        let node_for_sync = node.clone();
        let node_for_mine = node.clone();
        tokio::spawn(async move {
            loop {
                node_for_sync.clone().sync().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });

        tokio::spawn(async move {
            let cancellation_token = CancellationToken::new();
            let _ = node_for_mine.mine(cancellation_token).await;
        });

        let axum_app_state = AxumAppState { node };
        let router = get_router(axum_app_state.clone()).await;
        HttpServer {
            router,
            listener,
            axum_app_state,
        }
    }
    pub async fn port(&self) -> u16 {
        self.axum_app_state.node.port
    }

    pub async fn run(self) -> Result<(), io::Error> {
        axum::serve(self.listener, self.router).await
    }

    pub async fn axum_app_state(&self) -> AxumAppState {
        self.axum_app_state.clone()
    }
}

pub async fn get_router(axum_app_state: AxumAppState) -> Router {
    let routes = Router::new()
        .route("/balances/list", get(balances))
        .route("/tx/add", post(add_tx))
        .route("/status", get(status))
        .route("/node/sync", get(sync))
        .route("/node/peer", get(add_peer));

    Router::new()
        .merge(routes)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PATCH,
                    Method::PUT,
                    Method::DELETE,
                ])
                .allow_headers(Any),
        )
        .layer(CatchPanicLayer::custom(handle_panic))
        .with_state(axum_app_state)
}

fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    tracing::error!("cannot begin db tx due to err: {:?}", err);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!( {
            "message": "something went wrong",
        })),
    )
        .into_response()
}

#[derive(Serialize, Deserialize)]
pub struct AddTxReq {
    pub from: String,
    pub from_pwd: String, //password of key_store
    pub to: String,
    pub value: u64,
    pub data: String,
}

pub async fn add_tx(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":"invalid request body"})),
            )
                .into_response();
        }
        Ok(b) => b,
    };
    let params: AddTxReq = match serde_json::from_slice(&body) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":format!("invalid request body: {}",e)})),
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
                Json(json!({"message":format!("invalid request body: {}",e)})),
            )
                .into_response();
        }
    };

    let to_address = match Address::from_str(&params.to.to_lowercase()) {
        Ok(addr) => addr,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":format!("invalid request body: {}",e)})),
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
                Json(json!({"message":format!("invalid request body: {}",e)})),
            )
                .into_response();
        }
    };
    match node.add_pending_tx(signed_tx).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "success":true }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn balances(State(state): State<AxumAppState>, _req: Request) -> impl IntoResponse {
    let blockchain_state = state.node.state.read().await;
    let balances = blockchain_state.balances.clone();
    let latest_block_hash = blockchain_state.latest_block_hash;

    (
        StatusCode::OK,
        Json(json!({ "hash":hex::encode(latest_block_hash),"balances":balances })),
    )
        .into_response()
}

#[derive(Serialize, Deserialize)]
pub struct StatusRes {
    #[serde(serialize_with = "hash_to_hex", deserialize_with = "hash_from_hex")]
    block_hash: Hash,
    block_number: u64,
    known_peers: Vec<PeerNode>,
    pending_txs: Vec<SignedTx>,
}

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

#[derive(Serialize, Deserialize)]
pub struct SyncReq {
    #[serde(default)]
    pub from_block: String,
}

#[derive(Serialize, Deserialize)]
pub struct SyncRes {
    pub blocks: Vec<Block>,
}

pub async fn sync(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let params: Query<SyncReq> = match Query::try_from_uri(req.uri()) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":"invalid request params"})),
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
                Json(json!( {
                    "message": "hash is not valid",
                })),
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
            println!("cannot fetch blocks, err: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!( {
                    "message": "something went wrong",
                })),
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(SyncRes { blocks })).into_response()
}

#[derive(Serialize, Deserialize)]
pub struct AddPeerParams {
    #[serde(default)]
    pub ip: String,
    pub port: u16,
    pub miner: String,
}

#[derive(Serialize, Deserialize)]
pub struct AddPeerRes {
    pub success: bool,
    pub error: String,
}

pub async fn add_peer(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let params: Query<AddPeerParams> = match Query::try_from_uri(req.uri()) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":"invalid request params"})),
            )
                .into_response();
        }
    };
    let miner = match Address::from_str(&params.0.miner) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!( {
                    "message": format!("miner address is not valid: {}",e),
                })),
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
        println!("cannot add peer, err: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!( {
                "message": "cannot add peer",
            })),
        )
            .into_response();
    }

    let res = AddPeerRes {
        success: true,
        error: "".to_string(),
    };

    (StatusCode::OK, Json(res)).into_response()
}
