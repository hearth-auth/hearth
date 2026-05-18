use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Shared, Arc-wrapped in-memory key-value store.
/// Clones share the same underlying HashMap, allowing the state machine
/// and the external test harness to read the same committed data.
#[derive(Debug, Clone, Default)]
pub struct EmbeddedStorageEngine {
    data: Arc<Mutex<HashMap<String, String>>>,
}

impl EmbeddedStorageEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.data.lock().unwrap().get(key).cloned()
    }

    pub fn set(&self, key: String, value: String) {
        self.data.lock().unwrap().insert(key, value);
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.data.lock().unwrap().clone()
    }

    pub fn restore(&self, data: HashMap<String, String>) {
        *self.data.lock().unwrap() = data;
    }

    /// Return all key-value pairs whose keys start with `prefix`.
    /// Pass `""` to scan the entire store.
    pub fn scan(&self, prefix: &str) -> Vec<(String, String)> {
        self.data
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().unwrap().is_empty()
    }
}
