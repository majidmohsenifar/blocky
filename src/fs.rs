use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use crate::{BoxError, genesis::GENESIS_JSON};

pub fn init_data_dir_if_not_exists(data_dir: &str) -> Result<(), BoxError> {
    if Path::new(&get_genesis_json_file_path(data_dir)).exists() {
        return Ok(());
    }
    fs::create_dir_all(get_db_dir_path(data_dir))?;
    write_genesis_to_disk(&get_genesis_json_file_path(data_dir))?;
    write_empty_blocks_db_to_disk(&get_blocks_db_file_path(data_dir))?;
    Ok(())
}

pub fn get_db_dir_path(data_dir: &str) -> String {
    PathBuf::from(data_dir)
        .join("database")
        .to_string_lossy()
        .to_string()
}

pub fn get_genesis_json_file_path(data_dir: &str) -> String {
    PathBuf::from(data_dir)
        .join(get_db_dir_path(data_dir))
        .join("genesis.json")
        .to_string_lossy()
        .to_string()
}

pub fn get_blocks_db_file_path(data_dir: &str) -> String {
    PathBuf::from(data_dir)
        .join(get_db_dir_path(data_dir))
        .join("block.db")
        .to_string_lossy()
        .to_string()
}

fn write_genesis_to_disk(path: &str) -> Result<(), BoxError> {
    let mut genesis_file = File::create(path)?;
    genesis_file.write_all(GENESIS_JSON.as_bytes())?;
    Ok(())
}

fn write_empty_blocks_db_to_disk(path: &str) -> Result<(), BoxError> {
    let mut blocks_db_file = File::create(path)?;
    blocks_db_file.write_all(&[])?;
    Ok(())
}
