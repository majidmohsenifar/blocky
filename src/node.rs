use crate::{
    block::{Block, Hash, hash_from_hex, hash_to_hex},
    database,
    state::State as BlockchainState,
    tx::Tx,
};
use axum::{
    BoxError, Json, Router,
    extract::{Query, Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tokio::{io, net::TcpListener, sync::RwLock, time::Duration};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};

pub type SharedState = Arc<RwLock<AppState>>;

pub struct AppState {
    pub node: Arc<RwLock<Node>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerNode {
    pub ip: String,
    pub port: u16,
    pub is_bootstrap: bool,
    // Whenever my node already established connection, sync with this Peer
    pub connected: bool,
}

impl PeerNode {
    pub fn tcp_addr(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

pub struct HttpServer {
    router: Router,
    listener: TcpListener,
    shared_state: SharedState,
}

pub struct Node {
    data_dir: String,
    ip: String,
    port: u16,
    known_peers: HashMap<String, PeerNode>,
    state: BlockchainState,
}

impl Node {
    pub async fn sync(&mut self) {
        let peers: Vec<_> = self.known_peers.values().cloned().collect();
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
        }

        for n in faulty_nodes {
            self.known_peers.remove(&n.tcp_addr());
        }
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

    pub async fn join_known_peers(&mut self, peer_node: &PeerNode) -> Result<(), BoxError> {
        if peer_node.connected {
            return Ok(());
        }

        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "http://{}/node/peer?ip={}&port={}",
                peer_node.tcp_addr(),
                self.ip,
                self.port
            ))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let _: AddPeerRes = serde_json::from_slice(&bytes)?;

        //we are sure it exist, because we send it to this fn in caller one
        let k_p = self.known_peers.get_mut(&peer_node.tcp_addr()).unwrap();
        k_p.connected = true;
        let k_p_cloned = k_p.clone();
        let _ = self.add_peer(&k_p_cloned).await;
        Ok(())
    }

    pub async fn sync_known_peers(&mut self, known_peers: &[PeerNode]) -> Result<(), BoxError> {
        for p in known_peers {
            self.add_peer(p).await;
        }
        Ok(())
    }

    pub async fn sync_blocks(
        &mut self,
        peer_node: &PeerNode,
        status_res: &StatusRes,
    ) -> Result<(), BoxError> {
        if status_res.block_hash == [0; 32] {
            return Ok(());
        }
        if status_res.block_number < self.state.latest_block.header.number {
            return Ok(());
        }
        // If it's the genesis block and we already synced it, ignore it
        if status_res.block_number == 0 && self.state.latest_block_hash() != [0; 32] {
            return Ok(());
        }

        let client = reqwest::Client::new();

        let response = client
            .get(format!(
                "http://{}/node/sync?from_block={}",
                peer_node.tcp_addr(),
                hex::encode(self.state.latest_block_hash())
            ))
            .send()
            .await?;

        let bytes = response.bytes().await?;
        let res: SyncRes = serde_json::from_slice(&bytes)?;
        self.state.add_blocks(res.blocks)?;
        Ok(())
    }

    pub async fn add_peer(&mut self, peer_node: &PeerNode) -> Result<(), BoxError> {
        self.known_peers
            .insert(peer_node.tcp_addr(), peer_node.clone());
        Ok(())
    }
}

impl HttpServer {
    pub async fn build(data_dir: String, port: u16, bootstrap: PeerNode) -> Self {
        let blockchain_state = BlockchainState::new_state_from_disk(&data_dir);
        let blockchain_state = match blockchain_state {
            Err(e) => {
                panic!("cannot create state {e:?}");
            }
            Ok(s) => s,
        };
        println!("running http server on port {}", port);
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let ip = listener.local_addr().unwrap().ip().to_string();

        let node = Node {
            data_dir,
            ip,
            port,
            known_peers: HashMap::from([(
                format!("{}:{}", bootstrap.ip, bootstrap.port),
                bootstrap,
            )]),
            state: blockchain_state,
        };

        let node = Arc::new(RwLock::new(node));
        let node_for_task = node.clone();
        tokio::spawn(async move {
            loop {
                {
                    let mut node_guard = node_for_task.write().await;
                    node_guard.sync().await;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        let app_state = AppState { node };
        let shared_state = Arc::new(RwLock::new(app_state));
        let router = get_router(shared_state.clone()).await;
        HttpServer {
            router,
            listener,
            shared_state,
        }
    }
    pub async fn port(&self) -> u16 {
        self.shared_state.read().await.node.read().await.port
    }

    pub async fn run(self) -> Result<(), io::Error> {
        axum::serve(self.listener, self.router).await
    }

    pub async fn shared_state(&self) -> SharedState {
        self.shared_state.clone()
    }
}

pub async fn get_router(shared_state: SharedState) -> Router {
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
        .with_state(shared_state)
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

pub async fn add_tx(State(state): State<SharedState>, req: Request) -> impl IntoResponse {
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

    let state = state.read().await;
    let mut node = state.node.write().await;

    let b = Block::new(
        node.state.latest_block_hash(),
        node.state.next_block_number(),
        Utc::now().timestamp() as u64,
        &[tx],
    );

    let res = node.state.add_block(b);

    match res {
        Ok(hash) => (StatusCode::OK, Json(json!({ "hash":hex::encode(hash) }))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "message":e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn balances(State(state): State<SharedState>, _req: Request) -> impl IntoResponse {
    let state = state.read().await;
    let node = state.node.read().await;
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
}

pub async fn status(State(state): State<SharedState>, _req: Request) -> impl IntoResponse {
    let state = state.read().await;
    let node = state.node.read().await;
    let latest_block = node.state.latest_block.clone();
    let latest_block_hash = node.state.latest_block_hash;

    let res = StatusRes {
        block_hash: latest_block_hash,
        block_number: latest_block.header.number,
        known_peers: node.known_peers.values().cloned().collect(),
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

pub async fn sync(State(state): State<SharedState>, req: Request) -> impl IntoResponse {
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
    let state = state.read().await;
    let node = state.node.read().await;

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
}

#[derive(Serialize, Deserialize)]
pub struct AddPeerRes {
    pub success: bool,
    pub error: String,
}

pub async fn add_peer(State(state): State<SharedState>, req: Request) -> impl IntoResponse {
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

    let state = state.read().await;
    let mut node = state.node.write().await;

    let res = node
        .add_peer(&PeerNode {
            ip: params.0.ip,
            port: params.0.port,
            is_bootstrap: false,
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
