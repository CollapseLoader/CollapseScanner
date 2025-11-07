use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub matches: Vec<(FindingType, String)>,
    pub class_details: Option<ClassDetails>,
    pub resource_info: Option<ResourceInfo>,
    pub danger_score: u8,
    pub danger_explanation: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Progress {
    pub current: usize,
    pub total: usize,
    pub message: String,
}

impl Progress {
    pub fn new() -> Self {
        Self {
            current: 0,
            total: 0,
            message: String::from("Ready to scan"),
        }
    }

    pub fn percentage(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            (self.current as f32 / self.total as f32) * 100.0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FindingType {
    IpAddress,
    IpV6Address,
    Url,
    SuspiciousUrl,
    DiscordWebhook,
    SuspiciousKeyword,
    ObfuscationUnicode,
    HighEntropy,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::IpAddress => write!(f, "IPv4 Address"),
            FindingType::IpV6Address => write!(f, "IPv6 Address"),
            FindingType::Url => write!(f, "URL"),
            FindingType::SuspiciousUrl => write!(f, "Suspicious URL"),
            FindingType::DiscordWebhook => write!(f, "Discord Webhook"),
            FindingType::SuspiciousKeyword => write!(f, "Suspicious Keyword"),
            FindingType::ObfuscationUnicode => write!(f, "Obfuscation (Unicode Name)"),
            FindingType::HighEntropy => write!(f, "High Entropy"),
        }
    }
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
impl FindingType {
    pub fn with_emoji(&self) -> (&'static str, &'static str) {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => ("🌐", "red"),
            FindingType::Url => ("🔗", "blue"),
            FindingType::SuspiciousUrl => ("⚠️ ", "yellow"),
            FindingType::DiscordWebhook => ("🤖", "red"),
            FindingType::SuspiciousKeyword => ("❗", "red"),
            FindingType::ObfuscationUnicode => ("㊙️ ", "magenta"),
            FindingType::HighEntropy => ("🔥", "yellow"),
        }
    }
}

impl FindingType {
    pub fn base_score(&self) -> u8 {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => 3,
            FindingType::Url => 2,
            FindingType::SuspiciousUrl => 5,
            FindingType::DiscordWebhook => 10,
            FindingType::SuspiciousKeyword => 3,
            FindingType::ObfuscationUnicode => 1,
            FindingType::HighEntropy => 3,
        }
    }

    pub fn max_contribution(&self) -> u8 {
        match self {
            FindingType::SuspiciousUrl => 9,
            FindingType::IpAddress | FindingType::IpV6Address => 6,
            FindingType::Url => 6,
            FindingType::SuspiciousKeyword => 6,
            FindingType::ObfuscationUnicode => 4,
            FindingType::HighEntropy => 6,
            FindingType::DiscordWebhook => 10,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassDetails {
    pub class_name: String,
    pub superclass_name: String,
    pub interfaces: Vec<String>,
    pub methods: Vec<MethodInfo>,
    pub fields: Vec<FieldInfo>,
    pub strings: Vec<String>,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub path: String,
    pub size: u64,
    pub is_class_file: bool,
    pub entropy: f64,
    pub is_dead_class_candidate: bool,
}

#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DetectionMode {
    Network,
    Malicious,
    Obfuscation,
    All,
}

impl std::fmt::Display for DetectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMode::Network => write!(f, "Network"),
            DetectionMode::Malicious => write!(f, "Malicious"),
            DetectionMode::Obfuscation => write!(f, "Obfuscation"),
            DetectionMode::All => write!(f, "All"),
        }
    }
}

#[derive(Clone)]
pub struct ScannerOptions {
    pub extract_strings: bool,
    pub extract_resources: bool,
    pub output_dir: PathBuf,
    pub export_json: bool,
    pub mode: DetectionMode,
    pub verbose: bool,
    pub ignore_keywords_file: Option<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub max_file_size: Option<usize>,
    pub progress: Option<Arc<Mutex<Progress>>>,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        ScannerOptions {
            extract_strings: false,
            extract_resources: false,
            output_dir: PathBuf::from("./extracted"),
            export_json: false,
            mode: DetectionMode::All,
            verbose: false,
            ignore_keywords_file: None,
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
            max_file_size: None,
            progress: None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConstantPoolEntry {
    Utf8(String),
    Integer,
    Float,
    Long,
    Double,
    Class(u16),
    String(u16),
    Fieldref(u16, u16),
    Methodref(u16, u16),
    InterfaceMethodref(u16, u16),
    NameAndType(u16, u16),
    MethodHandle,
    MethodType,
    Dynamic,
    InvokeDynamic,
    Module,
    Package,
    Placeholder,
}
