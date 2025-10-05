use crate::{state::State as BlockchainState, tx::Tx};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::Arc;
use tokio::{io, net::TcpListener, sync::RwLock};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{Any, CorsLayer};

pub type SharedState = Arc<RwLock<AppState>>;

pub struct AppState {
    pub blockchain_state: Arc<RwLock<BlockchainState>>,
}

pub struct HttpServer {
    router: Router,
    listener: TcpListener,
    shared_state: SharedState,
    port: u16,
}

impl HttpServer {
    pub async fn build(blockchain_state: BlockchainState, port: u16) -> Self {
        let app_state = AppState {
            blockchain_state: Arc::new(RwLock::new(blockchain_state)),
        };
        let shared_state = Arc::new(RwLock::new(app_state));
        let router = get_router(shared_state.clone()).await;
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        HttpServer {
            router,
            listener,
            shared_state,
            port,
        }
    }
    pub fn port(&self) -> u16 {
        self.port
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
        .route("/tx/add", post(add_tx));

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
                .allow_headers(Any), //TODO: should we let Any header to be passed?
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
    let mut blockchain_state = state.blockchain_state.write().await;
    let res = blockchain_state.add(tx);
    if let Err(e) = res {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message":format!("error adding tx: {}",e)})),
        )
            .into_response();
    }
    let res = blockchain_state.persist();

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
    let blockchain_state = state.blockchain_state.read().await;
    let balances = blockchain_state.balances.clone();
    let latest_block_hash = blockchain_state.latest_block_hash;

    (
        StatusCode::OK,
        Json(json!({ "hash":hex::encode(latest_block_hash),"balances":balances })),
    )
        .into_response()
}
