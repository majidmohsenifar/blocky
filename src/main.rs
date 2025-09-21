use crate::state::State;

pub mod genesis;
pub mod state;
pub mod tx;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
fn main() {
    let state = State::new_state_from_disk().expect("state should be created");
    println!("{state:?}");
}
