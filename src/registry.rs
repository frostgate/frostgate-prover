#![allow(async_fn_in_trait)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)]

use lazy_static::lazy_static;
use frostgate_zkip::zkplug::*;
use std::sync::Arc;

lazy_static::lazy_static! {
    static ref REGISTRY: std::sync::Mutex<ZkPluginRegistry> = std::sync::Mutex::new(ZkPluginRegistry::new());
}

/// Register a plug globally
pub fn register_plug<P: ZkPlug + 'static>(plug: Arc<P>) -> Result<(), String> where P::Error: Into<ZkError> {
    REGISTRY.lock().unwrap()
        .register(plug)
        .map_err(|e| e.to_string())
}

/// Get a plug by ID
pub fn get_plug(id: &str) -> Option<Arc<dyn ZkPlug<Proof = Box<dyn std::any::Any + Send + Sync>, Error = frostgate_zkip::zkplug::ZkError>>> {
    REGISTRY.lock().unwrap().get(id).cloned()
}