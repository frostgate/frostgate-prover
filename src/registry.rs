#![allow(async_fn_in_trait)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lazy_static::lazy_static;
use frostgate_zkip::{
    ZkBackend, ZkBackendExt, ZkError, ZkResult,
    types::{HealthStatus, ResourceUsage, ZkConfig},
};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

lazy_static::lazy_static! {
    static ref REGISTRY: Mutex<BackendRegistry> = Mutex::new(BackendRegistry::new());
}

/// Registry for managing ZK backends
#[derive(Default)]
pub struct BackendRegistry {
    backends: HashMap<String, Arc<dyn ZkBackend>>,
}

impl BackendRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Register a new backend
    pub fn register<B>(&mut self, id: String, backend: Arc<B>) -> Result<(), ZkError>
    where
        B: ZkBackend + 'static,
    {
        if self.backends.contains_key(&id) {
            return Err(ZkError::Config(format!("Backend '{}' already registered", id)));
        }
        self.backends.insert(id, backend);
        Ok(())
    }

    /// Get a backend by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn ZkBackend>> {
        self.backends.get(id).cloned()
    }

    /// List all registered backend IDs
    pub fn list_backends(&self) -> Vec<String> {
        self.backends.keys().cloned().collect()
    }

    /// Remove a backend from the registry
    pub fn unregister(&mut self, id: &str) -> Option<Arc<dyn ZkBackend>> {
        self.backends.remove(id)
    }
}

/// Register a backend globally
pub fn register_backend<B: ZkBackend + 'static>(id: String, backend: Arc<B>) -> Result<(), ZkError> {
    REGISTRY.lock().unwrap().register(id, backend)
}

/// Get a backend by ID
pub fn get_backend(id: &str) -> Option<Arc<dyn ZkBackend>> {
    REGISTRY.lock().unwrap().get(id)
}

/// List all registered backend IDs
pub fn list_backends() -> Vec<String> {
    REGISTRY.lock().unwrap().list_backends()
}

/// Remove a backend from the registry
pub fn unregister_backend(id: &str) -> Option<Arc<dyn ZkBackend>> {
    REGISTRY.lock().unwrap().unregister(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    struct MockBackend;

    impl ZkBackend for MockBackend {
        fn prove(&self, program: &[u8], input: &[u8]) -> Result<Vec<u8>, ZkError> {
            Ok(vec![1, 2, 3])
        }

        fn verify(&self, program: &[u8], proof: &[u8]) -> Result<bool, ZkError> {
            Ok(true)
        }
    }

    #[test]
    fn test_backend_registration() {
        let mut registry = BackendRegistry::new();
        let backend = Arc::new(MockBackend);
        
        // Test registration
        registry.register("mock".to_string(), backend.clone()).unwrap();
        assert!(registry.get("mock").is_some());
        
        // Test duplicate registration
        assert!(registry.register("mock".to_string(), backend.clone()).is_err());
        
        // Test unregistration
        let removed = registry.unregister("mock").unwrap();
        assert!(registry.get("mock").is_none());
    }
}