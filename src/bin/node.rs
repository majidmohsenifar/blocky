use blocky::state::State;

fn main() {
    let state = State::new_state_from_disk().expect("state should be created");
    println!("{state:?}");
}
