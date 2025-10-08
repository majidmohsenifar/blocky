use crate::block::{Block, BlockFs, Hash};
use crate::{BoxError, fs};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};

pub async fn get_blocks_after(data_dir: &str, block_hash: Hash) -> Result<Vec<Block>, BoxError> {
    let db_file = OpenOptions::new()
        .read(true)
        .open(fs::get_blocks_db_file_path(data_dir))?;

    let mut start_collecting = block_hash == [0; 32];

    let reader = BufReader::new(db_file);
    let mut blocks = vec![];
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        let block_fs: BlockFs = serde_json::from_str(&line)?;

        if start_collecting {
            blocks.push(block_fs.value);
        }
        if block_fs.key == block_hash {
            start_collecting = true;
        }
    }
    Ok(blocks)
}
