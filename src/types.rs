use frostgate_zkip::zkplug::*;

pub type ProgramHash = String;

#[derive(Debug)]
pub enum ProverError {
  ZKError(ZkError),
  ProgramNotFound,
  IOError(std::io::Error),
  Other(String),
}

impl From<ZkError> for ProverError {
  fn from(e: ZkError) -> Self {
    ProverError::ZKError(e)
  }
}

impl From<std::io::Error> for ProverError {
  fn from(e: std::io::Error) -> Self {
    ProverError::IOError(e)
  }
}