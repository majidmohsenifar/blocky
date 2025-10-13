use crate::{
    BoxError,
    block::{Block, Hash, hash_from_hex, hash_to_hex},
    database,
    miner::{self, PendingBlock},
    state::State as BlockchainState,
    tx::{Account, Tx},
};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, future, sync::Arc};
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

// pub type SharedState = Arc<RwLock<AppState>>;

#[derive(Clone)]
pub struct AxumAppState {
    pub node: SharedNode,
}

#[derive(Clone)]
pub struct SharedNode(Arc<RwLock<Node>>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub ip: String,
    pub port: u16,
    pub is_bootstrap: bool,
    pub account: Account,
    // Whenever my node already established connection, sync with this Peer
    pub connected: bool,
}

impl PeerNode {
    pub fn new(
        ip: String,
        port: u16,
        is_bootstrap: bool,
        account: Account,
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

pub struct Node {
    state: BlockchainState,
    info: PeerNode,
    data_dir: String,
    ip: String,
    port: u16,
    known_peers: HashMap<String, PeerNode>,
    pending_txs: HashMap<String, Tx>,
    archived_txs: HashMap<String, Tx>,
    new_pending_txs: mpsc::Sender<Tx>,
    new_synced_blocks_sender: mpsc::Sender<Block>,
    new_synced_blocks_receiver: mpsc::Receiver<Block>,
    is_mining: bool,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new_shared_node(
        state: BlockchainState,
        data_dir: String,
        ip: String,
        port: u16,
        account: Account,
        bootstrap: PeerNode,
        pending_tx_sender: mpsc::Sender<Tx>,
        new_synced_blocks_sender: mpsc::Sender<Block>,
        new_synced_blocks_receiver: mpsc::Receiver<Block>,
    ) -> SharedNode {
        SharedNode(Arc::new(RwLock::new(Node {
            state,
            info: PeerNode::new(ip.clone(), port, false, account, true),
            data_dir,
            ip,
            port,
            known_peers: HashMap::from([(bootstrap.tcp_addr(), bootstrap)]),
            pending_txs: HashMap::new(),
            archived_txs: HashMap::new(),
            new_pending_txs: pending_tx_sender,
            new_synced_blocks_sender,
            new_synced_blocks_receiver,
            is_mining: false,
        })))
    }

    pub async fn mine_pending_txs(
        &mut self,
        cancellation_token: CancellationToken,
    ) -> Result<(), BoxError> {
        let block_to_mine = PendingBlock::new(
            self.state.latest_block_hash(),
            self.state.next_block_number(),
            self.info.account.clone(),
            self.pending_txs.values().cloned().collect(),
        );
        let mined_block = miner::mine(cancellation_token, block_to_mine).await?;
        self.remove_mined_pending_txs(&mined_block).await;
        self.state.add_block(mined_block)?;
        Ok(())
    }

    pub async fn remove_mined_pending_txs(&mut self, b: &Block) {
        b.txs.iter().for_each(|tx| {
            let key = hex::encode(tx.hash().unwrap()); //if we are here the tx_hash is valid, so unwrap is safe
            let removed_tx = self.pending_txs.remove(&key);
            if let Some(r_tx) = removed_tx {
                self.archived_txs.insert(key, r_tx);
            }
        });
    }
}

impl SharedNode {
    pub async fn sync(self) {
        let mut shared_node = self.0.write().await;
        let peers: Vec<_> = shared_node.known_peers.values().cloned().collect();
        let mut faulty_nodes = vec![];
        for peer in &peers {
            if peer.ip == shared_node.ip && peer.port == shared_node.port {
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

        for n in faulty_nodes {
            shared_node.known_peers.remove(&n.tcp_addr());
        }
    }

    pub async fn sync_pending_txs(&self, pending_txs: Vec<Tx>) -> Result<(), BoxError> {
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

        let mut shared_node = self.0.write().await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://{}/node/peer?ip={}&port={}",
                peer_node.tcp_addr(),
                shared_node.ip,
                shared_node.port
            ))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let _: AddPeerRes = serde_json::from_slice(&bytes)?;

        //we are sure it exist, because we send it to this fn in caller one
        let k_p = shared_node
            .known_peers
            .get_mut(&peer_node.tcp_addr())
            .unwrap();
        k_p.connected = true;
        let k_p_cloned = k_p.clone();
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

        let mut shared_node = self.0.write().await;
        if status_res.block_number < shared_node.state.latest_block.header.number {
            return Ok(());
        }
        // If it's the genesis block and we already synced it, ignore it
        if status_res.block_number == 0 && shared_node.state.latest_block_hash() != [0; 32] {
            return Ok(());
        }

        let client = reqwest::Client::new();

        let response = client
            .get(format!(
                "http://{}/node/sync?from_block={}",
                peer_node.tcp_addr(),
                hex::encode(shared_node.state.latest_block_hash())
            ))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let res: SyncRes = serde_json::from_slice(&bytes)?;
        for b in res.blocks {
            shared_node.state.add_block(b.clone())?;
            shared_node.new_synced_blocks_sender.send(b).await?;
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
        self.0
            .write()
            .await
            .known_peers
            .insert(peer_node.tcp_addr(), peer_node.clone());
        Ok(())
    }

    pub async fn mine(&self, cancellation_token: CancellationToken) -> Result<(), BoxError> {
        let mut mining_interval = interval(Duration::from_secs(10));
        loop {
            let mining_cancellation_token = CancellationToken::new();
            let mut shared_node = self.0.write().await;
            select! {
            biased;
                _ = cancellation_token.cancelled() => {
                    break;
                }

                block = shared_node.new_synced_blocks_receiver.recv() =>{
                match block{
                        Some(b)=>{
                            if shared_node.is_mining{
                                println!("another peer mined faster");
                                shared_node.remove_mined_pending_txs(&b).await;
                                mining_cancellation_token.cancel();
                            }

                        }
                        None =>{
                            continue;
                        }
                    }
                }
                _ = mining_interval.tick() => {
                    let self_clone = self.clone();
                    let second_self_clone = self.clone();
                    let cancellation_token_cloned = cancellation_token.clone();
                    tokio::spawn(async move {
                        let mut shared_node = self_clone.0.write().await;
                        if !shared_node.pending_txs.is_empty()  && !shared_node.is_mining {
                        shared_node.is_mining = true;
                        let block_to_mine = PendingBlock::new(
                                shared_node.state.latest_block_hash(),
                                shared_node.state.next_block_number(),
                                shared_node.info.account.clone(),
                                shared_node.pending_txs.values().cloned().collect(),
                        );
                        drop(shared_node);
                        let mined_block = miner::mine(cancellation_token_cloned, block_to_mine).await.unwrap();
                        let mut shared_node = second_self_clone.0.write().await;
                        shared_node.remove_mined_pending_txs(&mined_block).await;
                        shared_node.state.add_block(mined_block).unwrap();
                        shared_node.is_mining=false;
                        }
                   });
                }
                    _ = future::ready(()) => {}
            }
        }
        Ok(())
    }

    pub async fn add_pending_tx(&self, tx: Tx) -> Result<(), BoxError> {
        let mut shared_node = self.0.write().await;
        let tx_hash = hex::encode(tx.hash()?);
        if !shared_node.pending_txs.contains_key(&tx_hash)
            && !shared_node.archived_txs.contains_key(&tx_hash)
        {
            shared_node.pending_txs.insert(tx_hash, tx.clone());
            shared_node.new_pending_txs.send(tx).await?;
        }
        Ok(())
    }
}

impl HttpServer {
    pub async fn build(node: SharedNode) -> Self {
        let listener =
            tokio::net::TcpListener::bind(format!("127.0.0.1:{}", node.0.read().await.port))
                .await
                .unwrap();

        let node_for_sync = node.clone();
        let node_for_mine = node.clone();
        tokio::spawn(async move {
            loop {
                node_for_sync.clone().sync().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
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
        self.axum_app_state.node.0.read().await.port
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
    let tx: Tx = match serde_json::from_slice(&body) {
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":format!("invalid request body: {}",e)})),
            )
                .into_response();
        }
        Ok(p) => p,
    };

    match state.node.add_pending_tx(tx).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "success":true }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn balances(State(state): State<AxumAppState>, _req: Request) -> impl IntoResponse {
    let node = state.node.0.read().await;
    let balances = node.state.balances.clone();
    let latest_block_hash = node.state.latest_block_hash;

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
    pending_txs: Vec<Tx>,
}

pub async fn status(State(state): State<AxumAppState>, _req: Request) -> impl IntoResponse {
    let node = state.node.0.read().await;
    let latest_block = node.state.latest_block.clone();
    let latest_block_hash = node.state.latest_block_hash;

    let res = StatusRes {
        block_hash: latest_block_hash,
        block_number: latest_block.header.number,
        known_peers: node.known_peers.values().cloned().collect(),
        pending_txs: node.pending_txs.values().cloned().collect(),
    };

    (StatusCode::OK, Json(res)).into_response()
}

#[derive(Serialize, Deserialize)]
pub struct SyncParams {
    #[serde(default)]
    pub from_block: String,
}

#[derive(Serialize, Deserialize)]
pub struct SyncRes {
    pub blocks: Vec<Block>,
}

pub async fn sync(State(state): State<AxumAppState>, req: Request) -> impl IntoResponse {
    let params: Query<SyncParams> = match Query::try_from_uri(req.uri()) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message":"invalid request params"})),
            )
                .into_response();
        }
    };
    let node = state.node.0.read().await;

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
    let blocks = database::get_blocks_after(&node.data_dir, hash).await;
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

    let res = state
        .node
        .add_peer(&PeerNode {
            ip: params.0.ip,
            port: params.0.port,
            is_bootstrap: false,
            account: params.0.miner,
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
