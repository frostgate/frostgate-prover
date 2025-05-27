// frostgate-prover/src/sp1_plug.rs

#![allow(unused_imports)]

use async_trait::async_trait;
use frostgate_sdk::zkplug::*;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sp1_core_machine::io::SP1Stdin;
use sp1_sdk::{
    NetworkProver, SP1ProofWithPublicValues, SP1ProvingKey, SP1VerifyingKey, ProverClient, EnvProver,
};
use sp1_sdk::Prover;
use sp1_prover::SP1Prover;
use sp1_prover::{SP1PlonkBn254Proof, SP1Groth16Bn254Proof};
use sp1_prover::components::CpuProverComponents;
use sp1_prover::SP1PublicValues;
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};
use tokio::sync::Semaphore;
use std::fmt;

/// SP1 proof types supported by this plug.
#[derive(Clone, Serialize, Deserialize)]
pub enum Sp1ProofType {
    Core(SP1ProofWithPublicValues),
    PlonkBn254(SP1PlonkBn254Proof),
    Groth16Bn254(SP1Groth16Bn254Proof),
}

/// SP1 plug configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1PlugConfig {
    pub use_network: bool,
    pub network_api_key: Option<String>,
    pub network_endpoint: Option<String>,
    pub max_concurrent: Option<usize>,
}

impl Default for Sp1PlugConfig {
    fn default() -> Self {
        Self {
            use_network: false,
            network_api_key: std::env::var("SP1_PRIVATE_KEY").ok(),
            network_endpoint: None,
            max_concurrent: Some(num_cpus::get()),
        }
    }
}

/// Cached program information including compiled keys
#[derive(Clone)]
struct ProgramInfo {
    elf: Vec<u8>,
    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
    program_hash: String,
    compiled_at: SystemTime,
}

impl fmt::Debug for ProgramInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgramInfo")
            .field("program_hash", &self.program_hash)
            .field("compiled_at", &self.compiled_at)
            .field("proving_key", &"<SP1ProvingKey omitted>")
            .field("verifying_key", &"<SP1VerifyingKey omitted>")
            .finish()
    }
}

/// Backend wrapper for local or network proving
enum Sp1Backend {
    Local(EnvProver),
    Network(NetworkProver),
}

impl fmt::Debug for Sp1Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Sp1Backend::Local(_) => write!(f, "Local(EnvProver)"),
            Sp1Backend::Network(_) => write!(f, "Network(NetworkProver)"),
        }
    }
}

pub struct Sp1Plug {
    backend: Sp1Backend,
    config: Sp1PlugConfig,
    programs: RwLock<HashMap<String, ProgramInfo>>,
    semaphore: Arc<Semaphore>,
}

impl fmt::Debug for Sp1Plug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sp1Plug")
            .field("config", &self.config)
            .field("program_count", &self.programs.read().unwrap().len())
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Sp1PlugError {
    #[error("SP1 key generation error: {0}")]
    KeyGen(String),
    #[error("SP1 proof error: {0}")]
    Proof(String),
    #[error("SP1 verification error: {0}")]
    Verify(String),
    #[error("SP1 execution error: {0}")]
    Execution(String),
    #[error("SP1 program not found: {0}")]
    NotFound(String),
    #[error("SP1 input error: {0}")]
    Input(String),
    #[error("SP1 serialization error: {0}")]
    Serialization(String),
    #[error("SP1 unsupported: {0}")]
    Unsupported(String),
}

impl From<ZkError> for Sp1PlugError {
    fn from(e: ZkError) -> Self {
        Sp1PlugError::Proof(e.to_string())
    }
}

impl From<Sp1PlugError> for ZkError {
    fn from(e: Sp1PlugError) -> Self {
        ZkError::ProofGeneration(e.to_string())
    }
}

impl Sp1Plug {
    pub fn new(config: Option<Sp1PlugConfig>) -> Self {
        let config = config.unwrap_or_default();
        let backend = if config.use_network {
            let api_key = config
                .network_api_key
                .as_deref()
                .unwrap_or_else(|| panic!("SP1 network API key required"));
            let endpoint = config
                .network_endpoint
                .as_deref()
                .unwrap_or("https://api.sp1.giza.io");
            Sp1Backend::Network(NetworkProver::new(api_key, endpoint))
        } else {
            Sp1Backend::Local(EnvProver::new())
        };
        let max_concurrent = config.max_concurrent.unwrap_or_else(num_cpus::get);
        Self {
            backend,
            config,
            programs: RwLock::new(HashMap::new()),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Setup program keys and cache them by hash
    async fn setup_program(&self, elf: &[u8]) -> Result<String, Sp1PlugError> {
        let program_hash = hex::encode(Keccak256::digest(elf));
        if self.programs.read().unwrap().contains_key(&program_hash) {
            return Ok(program_hash);
        }
        
        let (proving_key, verifying_key) = match &self.backend {
            Sp1Backend::Local(prover) => prover.setup(elf),
            Sp1Backend::Network(prover) => prover.setup(elf),
        };
        
        let info = ProgramInfo {
            elf: elf.to_vec(),
            proving_key,
            verifying_key,
            program_hash: program_hash.clone(),
            compiled_at: SystemTime::now(),
        };
        
        self.programs
            .write()
            .unwrap()
            .insert(program_hash.clone(), info);
        Ok(program_hash)
    }

    fn get_program_info(&self, hash: &str) -> Result<ProgramInfo, Sp1PlugError> {
        self.programs
            .read()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| Sp1PlugError::NotFound("Program not found".to_string()))
    }
}

#[async_trait]
impl ZkPlug for Sp1Plug {
    type Proof = Sp1ProofType;
    type Error = Sp1PlugError;

    async fn prove(
        &self,
        input: &[u8],
        public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ZkProof<Self::Proof>, Self::Error> {
        utils::validate_input(input, Some(100 * 1024 * 1024))
            .map_err(|e| Sp1PlugError::Input(e.to_string()))?;
        let program_hash = self.setup_program(input).await?;
        let info = self.get_program_info(&program_hash)?;

        let mut stdin = SP1Stdin::new();
        if let Some(pub_inputs) = public_inputs {
            stdin.write_slice(pub_inputs);
        }

        let _permit = self.semaphore.acquire().await.unwrap();
        let start = Instant::now();

        let proof = match &self.backend {
            Sp1Backend::Local(prover) => {
                prover.prove(&info.proving_key, &stdin)
                    .run()
                    .map_err(|e| Sp1PlugError::Proof(format!("{:?}", e)))?
            }
            Sp1Backend::Network(prover) => {
                prover.prove(&info.proving_key, &stdin)
                    .run()
                    .map_err(|e| Sp1PlugError::Proof(format!("{:?}", e)))?
            }
        };
        let duration = start.elapsed();

        let proof_type = Sp1ProofType::Core(proof);

        let metadata = ProofMetadata {
            timestamp: SystemTime::now(),
            generation_time: duration,
            proof_size: bincode::serialize(&proof_type).map(|v| v.len()).unwrap_or(0),
            backend_id: self.id().to_string(),
            circuit_hash: Some(program_hash),
            custom_fields: HashMap::new(),
        };

        Ok(ZkProof {
            proof: proof_type,
            metadata,
        })
    }

    async fn verify(
        &self,
        proof: &ZkProof<Self::Proof>,
        _public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<bool, Self::Error> {
        let program_hash = proof
            .metadata
            .circuit_hash
            .as_ref()
            .ok_or_else(|| Sp1PlugError::Input("Missing program hash".to_string()))?;
        let info = self.get_program_info(program_hash)?;

        match &proof.proof {
            Sp1ProofType::Core(core) => match &self.backend {
                Sp1Backend::Local(prover) => {
                    prover.verify(core, &info.verifying_key)
                        .map_err(|e| Sp1PlugError::Verify(format!("{:?}", e)))?
                }
                Sp1Backend::Network(prover) => {
                    prover.verify(core, &info.verifying_key)
                        .map_err(|e| Sp1PlugError::Verify(format!("{:?}", e)))?
                }
            },
            Sp1ProofType::PlonkBn254(plonk_with_meta) => {
                let build_dir = Path::new(".");
                let prover = SP1Prover::<CpuProverComponents>::new();
                prover.verify_plonk_bn254(
                    &plonk_with_meta.proof.0,
                    &info.verifying_key,
                    &plonk_with_meta.public_values,
                    build_dir,
                )
                .map_err(|e| Sp1PlugError::Verify(format!("{:?}", e)))?
            },
            Sp1ProofType::Groth16Bn254(groth_with_meta) => {
                let build_dir = Path::new(".");
                let prover = SP1Prover::<CpuProverComponents>::new();
                prover.verify_groth16_bn254(
                    &groth_with_meta.proof.0,
                    &info.verifying_key,
                    &groth_with_meta.public_values,
                    build_dir,
                )
                .map_err(|e| Sp1PlugError::Verify(format!("{:?}", e)))?
            },
        }
        Ok(true)
    }

    async fn execute(
        &self,
        program: &[u8],
        input: &[u8],
        public_inputs: Option<&[u8]>,
        _config: Option<&ZkConfig>,
    ) -> ZkResult<ExecutionResult<Self::Proof>, Self::Error> {
        let program_hash = self.setup_program(program).await?;
        let info = self.get_program_info(&program_hash)?;

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(input);
        if let Some(pub_inputs) = public_inputs {
            stdin.write_slice(pub_inputs);
        }

        let start = Instant::now();

        let (output, report) = match &self.backend {
            Sp1Backend::Local(prover) => {
            prover.execute(&info.elf, &stdin)
                .run()
                .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))?
        }
            Sp1Backend::Network(prover) => {
                prover.execute(&info.elf, &stdin)
                    .run()
                    .map_err(|e| Sp1PlugError::Execution(format!("{:?}", e)))?
            }
        };

        let exec_time = start.elapsed();

        let stats = ExecutionStats {
            steps: report.total_instruction_count() as u64,
            memory_usage: 0,
            execution_time: exec_time,
            gas_used: Some(report.total_instruction_count() as u64),
        };

        let proof = self.prove(program, public_inputs, None).await?;

        let output_bytes = bincode::serialize(&output)
            .map_err(|e| Sp1PlugError::Execution(format!("Serialization error: {:?}", e)))?;

        Ok(ExecutionResult {
            output: output_bytes,
            proof,
            stats,
        })
    }

    async fn get_backend_info(&self) -> BackendInfo {
        BackendInfo {
            id: self.id().to_string(),
            name: "SP1 zkVM".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: self.capabilities(),
            health: self.health_check().await,
            resource_usage: self.get_resource_usage().await,
            custom_info: HashMap::new(),
        }
    }

    fn id(&self) -> &'static str {
        "sp1"
    }

    fn capabilities(&self) -> Vec<ZkCapability> {
        vec![
            ZkCapability::VirtualMachine,
            ZkCapability::BatchProving,
            ZkCapability::SuccinctVerification,
            ZkCapability::ZeroKnowledge,
            ZkCapability::Custom("plonk_bn254".to_string()),
            ZkCapability::Custom("groth16_bn254".to_string()),
        ]
    }

    async fn health_check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }

    async fn get_resource_usage(&self) -> ResourceUsage {
        ResourceUsage {
            cpu_usage: 0.0,
            memory_usage: 0,
            available_memory: 8 * 1024 * 1024 * 1024,
            active_tasks: 0,
            queue_depth: 0,
        }
    }

    async fn initialize(&mut self, _config: Option<&ZkConfig>) -> ZkResult<(), Self::Error> {
        Ok(())
    }

    async fn shutdown(&mut self) -> ZkResult<(), Self::Error> {
        self.programs.write().unwrap().clear();
        Ok(())
    }
}