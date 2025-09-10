pub type Account = String;

pub struct Tx {
    from: Account,
    to: Account,
    value: u64,
    data: String,
}

impl Tx {
    pub fn new(from: Account, to: Account, value: u64, data: String) -> Self {
        Self {
            from,
            to,
            value,
            data,
        }
    }
    pub fn is_reward(&self) -> bool {
        self.data.as_str() == "reward"
    }
}
