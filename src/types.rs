use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod arc_matches_serde {
    use super::FindingType;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(v: &Arc<Vec<(FindingType, String)>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        v.as_ref().serialize(s)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Arc<Vec<(FindingType, String)>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<(FindingType, String)>::deserialize(d).map(Arc::new)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    #[serde(with = "arc_matches_serde")]
    pub matches: Arc<Vec<(FindingType, String)>>,
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
    pub cancelled: bool,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FindingType {
    IpAddress,
    IpV6Address,
    Url,
    SuspiciousUrl,
    DiscordWebhook,
    SuspiciousKeyword,
    SuspiciousApi,
    EncodedPayload,
    TamperedClass,
    NativeLibrary,
    SuspiciousArchiveEntry,
    ObfuscationUnicode,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            FindingType::IpAddress => "IPv4 Address",
            FindingType::IpV6Address => "IPv6 Address",
            FindingType::Url => "URL",
            FindingType::SuspiciousUrl => "Suspicious URL",
            FindingType::DiscordWebhook => "Discord Webhook",
            FindingType::SuspiciousKeyword => "Suspicious Keyword",
            FindingType::SuspiciousApi => "Suspicious Java API",
            FindingType::EncodedPayload => "Encoded Payload",
            FindingType::TamperedClass => "Tampered Class",
            FindingType::NativeLibrary => "Native Library",
            FindingType::SuspiciousArchiveEntry => "Suspicious Archive Entry",
            FindingType::ObfuscationUnicode => "Obfuscation (Unicode Name)",
        };
        f.write_str(label)
    }
}

impl FindingType {
    pub fn with_symbol(&self) -> (&'static str, &'static str) {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => ("◆", "red"),
            FindingType::Url => ("◇", "blue"),
            FindingType::SuspiciousUrl => ("▲ ", "yellow"),
            FindingType::DiscordWebhook => ("■", "red"),
            FindingType::SuspiciousKeyword => ("●", "red"),
            FindingType::SuspiciousApi => ("⬢", "yellow"),
            FindingType::EncodedPayload => ("◈", "magenta"),
            FindingType::TamperedClass => ("✖", "red"),
            FindingType::NativeLibrary => ("▣", "yellow"),
            FindingType::SuspiciousArchiveEntry => ("▦", "yellow"),
            FindingType::ObfuscationUnicode => ("◌ ", "magenta"),
        }
    }

    pub fn base_score(&self) -> u8 {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => 2,
            FindingType::Url => 1,
            FindingType::SuspiciousUrl => 5,
            FindingType::DiscordWebhook => 10,
            FindingType::SuspiciousKeyword => 3,
            FindingType::SuspiciousApi => 3,
            FindingType::EncodedPayload => 2,
            FindingType::TamperedClass => 6,
            FindingType::NativeLibrary => 4,
            FindingType::SuspiciousArchiveEntry => 4,
            FindingType::ObfuscationUnicode => 1,
        }
    }

    pub fn max_contribution(&self) -> u8 {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => 5,
            FindingType::Url => 4,
            FindingType::SuspiciousUrl => 8,
            FindingType::DiscordWebhook => 10,
            FindingType::SuspiciousKeyword => 6,
            FindingType::SuspiciousApi => 7,
            FindingType::EncodedPayload => 5,
            FindingType::TamperedClass => 10,
            FindingType::NativeLibrary => 7,
            FindingType::SuspiciousArchiveEntry => 8,
            FindingType::ObfuscationUnicode => 3,
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
    pub is_dead_class_candidate: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize, clap::ValueEnum)]
pub enum DetectionMode {
    Network,
    Malicious,
    Obfuscation,
    All,
}

impl std::fmt::Display for DetectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            DetectionMode::Network => "Network",
            DetectionMode::Malicious => "Malicious",
            DetectionMode::Obfuscation => "Obfuscation",
            DetectionMode::All => "All",
        };
        f.write_str(label)
    }
}

#[derive(Clone)]
pub struct ScannerOptions {
    pub mode: DetectionMode,
    pub verbose: bool,
    pub ignore_keywords_file: Option<PathBuf>,
    pub exclude_patterns: Vec<String>,
    pub find_patterns: Vec<String>,
    pub progress: Option<Arc<Mutex<Progress>>>,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        ScannerOptions {
            mode: DetectionMode::All,
            verbose: false,
            ignore_keywords_file: None,
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
            progress: None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ConstantPoolEntry {
    Utf8(std::sync::Arc<str>),
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
