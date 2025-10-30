use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub matches: Vec<(FindingType, String)>,
    pub class_details: Option<ClassDetails>,
    pub resource_info: Option<ResourceInfo>,
    pub danger_score: u8,
    pub danger_explanation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FindingType {
    IpAddress,
    IpV6Address,
    Url,
    SuspiciousUrl,
    Crypto,
    SuspiciousKeyword,
    ObfuscationLongName,
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
            FindingType::Crypto => write!(f, "Crypto Keyword"),
            FindingType::SuspiciousKeyword => write!(f, "Suspicious Keyword"),
            FindingType::ObfuscationLongName => write!(f, "Obfuscation (Long Name)"),
            FindingType::ObfuscationUnicode => write!(f, "Obfuscation (Unicode Name)"),
            FindingType::HighEntropy => write!(f, "High Entropy"),
        }
    }
}

impl FindingType {
    pub fn with_emoji(&self) -> (&'static str, &'static str) {
        match self {
            FindingType::IpAddress | FindingType::IpV6Address => ("🌐", "bright_red"),
            FindingType::Url => ("🔗", "bright_red"),
            FindingType::SuspiciousUrl => ("⚠️ ", "yellow"),
            FindingType::Crypto => ("🔒", "bright_yellow"),
            FindingType::SuspiciousKeyword => ("❗", "red"),
            FindingType::ObfuscationLongName => ("📏", "bright_magenta"),
            FindingType::ObfuscationUnicode => ("㊙️ ", "magenta"),
            FindingType::HighEntropy => ("🔥", "yellow"),
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

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum DetectionMode {
    Network,
    Crypto,
    Malicious,
    Obfuscation,
    All,
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
    pub fast_mode: bool,
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
            fast_mode: false,
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
