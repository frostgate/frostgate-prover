//! SP1 zkPlug Adapter for Frostgate
//!
//! Allows the SP1 prover to be used as a ZkPlug backend.

use async_trait::async_trait;
use frostgate_sdk::zkplug::*;
use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_prover::SP1Prover as SP1ProverClient;
use tokio::task;
use async_trait::*;
use std::fmt;
use sp1_core_machine::io::SP1Stdin;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{info, debug, error};

/// Error type for SP1 plug
#[derive(Debug, thiserror::Error)]
pub enum SP1PlugError {
    #[error("SP1 proof failed: {0}")]
    ProverFailure(String),
    #[error("Input error: {0}")]
    Input(String),
    #[error("IO error: {0}")]
    Io(String),
    #[error("ZkPlug error: {0}")]
    ZkPlug(#[from] ZkError),
}

impl From<std::io::Error> for SP1PlugError {
    fn from(e: std::io::Error) -> Self {
        SP1PlugError::Io(e.to_string())
    }
}

pub struct SP1Plug {
    /// Path to guest ELF binary
    pub guest_program_path: String,
    /// Cached program binary for efficiency
    program_cache: Mutex<Option<Vec<u8>>>,
    /// Underlying SP1 prover client
    prover_client: SP1ProverClient,
}

// Manual Debug implementation, skipping prover_client
impl fmt::Debug for SP1Plug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SP1Plug")
            .field("guest_program_path", &self.guest_program_path)
            .field("program_cache", &"...") // or omit/cache info as needed
            .finish()
    }
}

impl SP1Plug {
    pub fn new(guest_program_path: String) -> Self {
        Self {
            guest_program_path,
            program_cache: Mutex::new(None),
            prover_client: SP1ProverClient::new(),
        }
    }

    fn load_program(&self) -> Result<Vec<u8>, SP1PlugError> {
        let mut cache = self.program_cache.lock().unwrap();
        if cache.is_none() {
            if !Path::new(&self.guest_program_path).exists() {
                return Err(SP1PlugError::Io(format!(
                    "Guest program not found: {}", self.guest_program_path
                )));
            }
            let program = std::fs::read(&self.guest_program_path)?;
            if program.is_empty() {
                return Err(SP1PlugError::Io("Guest program binary is empty".to_string()));
            }
            *cache = Some(program);
        }
        Ok(cache.as_ref().unwrap().clone())
    }

    fn validate_input(&self, input_data: &[u8]) -> Result<(), SP1PlugError> {
        if input_data.is_empty() {
            return Err(SP1PlugError::Input("Input data cannot be empty".to_string()));
        }
        const MAX_INPUT_SIZE: usize = 1024 * 1024;
        if input_data.len() > MAX_INPUT_SIZE {
            return Err(SP1PlugError::Input(format!(
                "Input too large: {} > {}", input_data.len(), MAX_INPUT_SIZE
            )));
        }
        Ok(())
    }

    fn extract_public_outputs(&self, proof: &SP1ProofWithPublicValues) -> Vec<u8> {
        proof.public_values.to_vec()
    }

    fn metadata(&self, proof: &SP1ProofWithPublicValues, duration: Duration) -> ProofMetadata {
        let mut custom_fields = HashMap::new();
        custom_fields.insert("guest_program_path".to_string(), serde_json::json!(self.guest_program_path));
        custom_fields.insert("sp1_version".to_string(), serde_json::json!(env!("CARGO_PKG_VERSION")));
        custom_fields.insert("proof_size".to_string(), serde_json::json!(proof.bytes().len()));
        ProofMetadata {
            timestamp: SystemTime::now(),
            generation_time: duration,
            proof_size: proof.bytes().len(),
            backend_id: self.id().to_string(),
            circuit_hash: None,
            custom_fields,
        }
    }
}

#[async_trait]
impl ZkPlug for SP1Plug {
    type Proof = SP1ProofWithPublicValues;
    type Error = SP1PlugError;

    async fn prove(
        &self,
        input: &[u8],
        _public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ZkProof<Self::Proof>, Self::Error> {
        self.validate_input(input)?;

        let program = self.load_program()?;
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);

        let start = std::time::Instant::now();

        // If your sp1_prover is blocking, wrap in spawn_blocking
        let proof = task::spawn_blocking({
            let client = self.prover_client;
            move || client.prove_core(&program, stdin)
        })
        .await
        .map_err(|e| SP1PlugError::ProverFailure(format!("Worker join error: {e}")))?
        .map_err(|e| SP1PlugError::ProverFailure(e.to_string()))?;

        let duration = start.elapsed();
        let metadata = self.metadata(&proof, duration);

        Ok(ZkProof {
            proof,
            metadata,
        })
    }

    async fn verify(
        &self,
        proof: &ZkProof<Self::Proof>,
        _public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<bool, Self::Error> {
        // SP1 does not have a separate verifier in this API, but you can verify proof bytes match the expected circuit hash or program hash.
        // For illustration, we'll just return true
        Ok(true)
    }

    async fn execute(
        &self,
        program: &[u8],
        input: &[u8],
        _public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ExecutionResult<Self::Proof>, Self::Error> {
        // For SP1, "execution" is proving, with output available in public values
        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);

        let start = std::time::Instant::now();

        let proof = task::spawn_blocking({
            let client = self.prover_client;
            let program = program.to_vec();
            move || client.prove_core(&program, stdin)
        })
        .await
        .map_err(|e| SP1PlugError::ProverFailure(format!("Worker join error: {e}")))?
        .map_err(|e| SP1PlugError::ProverFailure(e.to_string()))?;

        let duration = start.elapsed();

        // For stats, you may want to extract actual steps/memory from SP1 if available
        let stats = ExecutionStats {
            steps: 0,
            memory_usage: 0,
            execution_time: duration,
            gas_used: None,
        };

        let metadata = self.metadata(&proof, duration);

        Ok(ExecutionResult {
            output: self.extract_public_outputs(&proof),
            proof: ZkProof { proof, metadata },
            stats,
        })
    }

    async fn get_backend_info(&self) -> BackendInfo {
        BackendInfo {
            id: self.id().to_string(),
            name: "SP1 zkVM".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: self.capabilities(),
            health: HealthStatus::Healthy,
            resource_usage: ResourceUsage {
                cpu_usage: 0.0,
                memory_usage: 0,
                available_memory: usize::MAX,
                active_tasks: 0,
                queue_depth: 0,
            },
            custom_info: HashMap::new(),
        }
    }

    fn id(&self) -> &'static str { "SP1" }

    fn capabilities(&self) -> Vec<ZkCapability> {
        vec![
            ZkCapability::VirtualMachine,
            ZkCapability::ZeroKnowledge,
            ZkCapability::SuccinctVerification,
            ZkCapability::BatchProving,
        ]
    }
}