use crate::types::{DetectionMode, Progress};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum AppState {
    Idle,
    Scanning,
    Completed,
    Cancelled,
    Error(String),
}

pub type ScanProgress = Arc<Mutex<Progress>>;

#[derive(Debug, Clone)]
pub struct ScanSettings {
    pub path: String,
    pub mode: DetectionMode,
    pub verbose: bool,
    pub extract_strings: bool,
    pub extract_resources: bool,
    pub export_json: bool,
    pub threads: String,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub exclude_pattern_input: String,
    pub find_pattern_input: String,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            path: String::new(),
            mode: DetectionMode::All,
            verbose: false,
            extract_strings: false,
            extract_resources: false,
            export_json: false,
            threads: String::from("0"),
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
            exclude_pattern_input: String::new(),
            find_pattern_input: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResultsUi {
    pub search: String,
    pub severity: &'static str,
}

impl Default for ResultsUi {
    fn default() -> Self {
        Self {
            search: String::new(),
            severity: "All",
        }
    }
}
