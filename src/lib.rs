pub mod block;
pub mod cmd;
pub mod genesis;
pub mod state;
pub mod tx;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
