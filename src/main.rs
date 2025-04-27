#![allow(clippy::collapsible_else_if)]
mod database;

use byteorder::{BigEndian, ReadBytesExt};
use clap::{Parser, ValueEnum};
use colored::*;
use database::GOOD_LINKS;
use encoding_rs::UTF_8;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;
use url::Url;
use walkdir::WalkDir;
use wildmatch::WildMatch;
use zip::ZipArchive;

const NAME_LENGTH_THRESHOLD: usize = 50;
const ENTROPY_THRESHOLD: f64 = 7.2;
const SUSPICIOUS_CHAR_THRESHOLD: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    file_path: String,
    matches: Vec<(FindingType, String)>,
    class_details: Option<ClassDetails>,
    resource_info: Option<ResourceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
enum FindingType {
    IpAddress,
    IpV6Address,
    Url,
    Crypto,
    SuspiciousKeyword,
    ObfuscationLongName,
    ObfuscationChars,
    ObfuscationUnicode,
    HighEntropy,
}

impl std::fmt::Display for FindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingType::IpAddress => write!(f, "IPv4 Address"),
            FindingType::IpV6Address => write!(f, "IPv6 Address"),
            FindingType::Url => write!(f, "URL"),
            FindingType::Crypto => write!(f, "Crypto Keyword"),
            FindingType::SuspiciousKeyword => write!(f, "Suspicious Keyword"),
            FindingType::ObfuscationLongName => write!(f, "Obfuscation (Long Name)"),
            FindingType::ObfuscationChars => write!(f, "Obfuscation (Suspicious Chars/Short)"),
            FindingType::ObfuscationUnicode => write!(f, "Obfuscation (Unicode Name)"),
            FindingType::HighEntropy => write!(f, "High Entropy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClassDetails {
    class_name: String,
    superclass_name: String,
    interfaces: Vec<String>,
    methods: Vec<MethodInfo>,
    fields: Vec<FieldInfo>,
    strings: Vec<String>,
    access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MethodInfo {
    name: String,
    descriptor: String,
    access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldInfo {
    name: String,
    descriptor: String,
    access_flags: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResourceInfo {
    path: String,
    size: u64,
    is_class_file: bool,
    entropy: f64,
    is_dead_class_candidate: bool,
}

#[derive(Debug, Error)]
enum ScanError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Class parse error in '{path}': {msg}")]
    ClassParseError { path: String, msg: String },
    #[error("Unsupported file type: {0:?}")]
    UnsupportedFileType(Option<std::ffi::OsString>),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Template error: {0}")]
    TemplateError(#[from] indicatif::style::TemplateError),
}

#[derive(Parser)]
#[clap(
    author,
    version,
    about = "CollapseScanner - Advanced JAR/class file analysis and reverse engineering tool"
)]
struct Args {
    #[clap(value_parser)]
    path: Option<String>,

    #[clap(
        short,
        long,
        action = clap::ArgAction::SetTrue,
        help = "Enable verbose output (shows size/entropy etc.)"
    )]
    verbose: bool,

    #[clap(
        long,
        help = "Extract strings from class files into the output directory"
    )]
    strings: bool,

    #[clap(
        long,
        help = "Extract all resources from JAR files into the output directory"
    )]
    extract: bool,

    #[clap(
        long,
        value_parser,
        help = "Directory for extracted files and JSON output"
    )]
    output: Option<String>,

    #[clap(
        long,
        help = "Export detailed scan results (including class structures) as JSON"
    )]
    json: bool,

    #[clap(
        value_enum,
        long,
        default_value = "all",
        help = "Filter findings by category"
    )]
    mode: DetectionMode,

    #[clap(
        long,
        value_parser,
        help = "Path to a .txt file with suspicious keywords to ignore (one per line, case-insensitive)"
    )]
    ignore_suspicious: Option<PathBuf>,

    #[clap(
        long,
        value_parser,
        help = "Path to a .txt file with crypto keywords to ignore (one per line, case-insensitive)"
    )]
    ignore_crypto: Option<PathBuf>,

    #[clap(
        long,
        action = clap::ArgAction::Append,
        value_parser,
        help = "Exclude paths matching the wildcard pattern (e.g., 'com/example/*', '*.log', 'assets/**'). Applied before --find."
    )]
    exclude: Vec<String>,

    #[clap(
        long,
        action = clap::ArgAction::Append,
        value_parser,
        help = "Only scan paths matching the wildcard pattern (e.g., 'com/program/*', '**/SpecificClass.class'). Applied after --exclude."
    )]
    find: Vec<String>,

    #[clap(
        long,
        value_parser,
        default_value_t = 0,
        help = "Number of threads to use for parallel processing (0 = automatic based on CPU cores)"
    )]
    threads: usize,

    #[clap(
        long,
        action = clap::ArgAction::SetTrue,
        help = "Fast scan mode - stops processing a JAR file after finding the first suspicious item"
    )]
    fast: bool,

    #[clap(
        long,
        value_parser,
        default_value_t = 50,
        help = "Maximum number of findings to collect before stopping (0 = no limit)"
    )]
    max_findings: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum DetectionMode {
    Network,
    Crypto,
    Malicious,
    Obfuscation,
    All,
}

struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    ipv6_regex: Regex,
    url_regex: Regex,
    crypto_regex: Regex,
    malicious_pattern_regex: Regex,
    suspicious_consecutive_chars_regex: Regex,
    ignored_suspicious_keywords: HashSet<String>,
    ignored_crypto_keywords: HashSet<String>,
    options: ScannerOptions,
    found_custom_jvm_indicator: Arc<Mutex<bool>>,
    exclude_patterns: Vec<WildMatch>,
    find_patterns: Vec<WildMatch>,
}

#[derive(Clone)]
struct ScannerOptions {
    extract_strings: bool,
    extract_resources: bool,
    output_dir: PathBuf,
    export_json: bool,
    mode: DetectionMode,
    verbose: bool,
    ignore_suspicious_file: Option<PathBuf>,
    ignore_crypto_file: Option<PathBuf>,
    exclude_patterns: Vec<String>,
    find_patterns: Vec<String>,
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
            ignore_suspicious_file: None,
            ignore_crypto_file: None,
            exclude_patterns: Vec::new(),
            find_patterns: Vec::new(),
        }
    }
}

impl CollapseScanner {
    fn new(options: ScannerOptions) -> Result<Self, ScanError> {
        let good_links: HashSet<String> = GOOD_LINKS.iter().cloned().collect();

        if options.extract_resources || options.extract_strings || options.export_json {
            fs::create_dir_all(&options.output_dir)?;
        }

        let mut ignored_suspicious_keywords: HashSet<String> = HashSet::new();
        let mut ignored_crypto_keywords: HashSet<String> = HashSet::new();

        if let Some(ref path) = options.ignore_suspicious_file {
            if options.verbose {
                println!(
                    "{} Loading suspicious keyword ignore list from: {}",
                    "📄".yellow(),
                    path.display()
                );
            }
            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    ignored_suspicious_keywords.extend(ignored);
                }
                Err(e) => {
                    eprintln!(
                        "{} Warning: Could not load suspicious ignore list from {}: {}",
                        "⚠️".yellow(),
                        path.display(),
                        e
                    );
                }
            }
        }

        if let Some(ref path) = options.ignore_crypto_file {
            if options.verbose {
                println!(
                    "{} Loading crypto keyword ignore list from: {}",
                    "📄".yellow(),
                    path.display()
                );
            }
            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    ignored_crypto_keywords.extend(ignored);
                }
                Err(e) => {
                    eprintln!(
                        "{} Warning: Could not load crypto ignore list from {}: {}",
                        "⚠️".yellow(),
                        path.display(),
                        e
                    );
                }
            }
        }

        let exclude_patterns = options
            .exclude_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();
        let find_patterns = options
            .find_patterns
            .iter()
            .map(|p| WildMatch::new(p))
            .collect();

        Ok(CollapseScanner {
            good_links,
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            ipv6_regex: Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap(),
            url_regex: Regex::new(r#"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"#).unwrap(),
            crypto_regex: Regex::new(r"(?i)\b(aes|des|rsa|md5|sha[1-9]*-?\d*|blowfish|twofish|pgp|gpg|cipher|keystore|keygenerator|secretkey|password|encrypt|decrypt|hash|salt|ivParameterSpec|SecureRandom)\b").unwrap(),
            malicious_pattern_regex: Regex::new(r"(?i)\b(backdoor|exploit|inject|payload|shellcode|bypass|rootkit|keylog|rat\b|trojan|malware|spyware|meterpreter|cobaltstrike|powershell|cmd\.exe|Runtime\.getRuntime\(\)\.exec|loadLibrary|download|upload|socket\(|bind\(|connect\(|class\.forName|defineClass|unsafe|jndi|ldap|rmi)\b").unwrap(),
            suspicious_consecutive_chars_regex: Regex::new(&format!(r"[^a-zA-Z0-9_$/]{{{},}}", SUSPICIOUS_CHAR_THRESHOLD)).unwrap(),
            ignored_suspicious_keywords,
            ignored_crypto_keywords,
            options,
            found_custom_jvm_indicator: Arc::new(Mutex::new(false)),
            exclude_patterns,
            find_patterns,
        })
    }

    fn should_scan(&self, internal_path: &str) -> bool {
        if self
            .exclude_patterns
            .iter()
            .any(|pattern| pattern.matches(internal_path))
        {
            if self.options.verbose {}
            return false;
        }

        if !self.find_patterns.is_empty() {
            if !self
                .find_patterns
                .iter()
                .any(|pattern| pattern.matches(internal_path))
            {
                if self.options.verbose {}
                return false;
            }
        }

        true
    }

    fn load_ignore_list_from_file(path: &Path) -> Result<HashSet<String>, io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut ignored_set = HashSet::new();

        for line in reader.lines() {
            let line_content = line?;
            let trimmed = line_content.trim();
            if !trimmed.is_empty() {
                ignored_set.insert(trimmed.to_lowercase());
            }
        }
        Ok(ignored_set)
    }

    fn scan_path(&self, path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        if path.is_dir() {
            self.scan_directory(path)
        } else if path.extension().map_or(false, |ext| ext == "jar") {
            self.scan_jar_file(path)
        } else if path.extension().map_or(false, |ext| ext == "class") {
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            if !self.should_scan(&filename) {
                if self.options.verbose {
                    println!(
                        "{} Skipping filtered file: {}",
                        "🚫".dimmed(),
                        path.display()
                    );
                }
                return Ok(Vec::new());
            }

            if self.options.verbose {
                println!(
                    "{} Scanning loose class file: {}",
                    "📄".blue(),
                    path.display()
                );
            }
            let file_data = fs::read(path)?;
            let resource_info = self.analyze_resource(&filename, &file_data)?;
            self.scan_class_file_data(&filename, file_data, Some(resource_info))
                .map(|res| vec![res])
        } else {
            Err(ScanError::UnsupportedFileType(
                path.extension().map(|s| s.to_os_string()),
            ))
        }
    }

    fn scan_directory(&self, dir_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let mut results = Vec::new();
        if self.options.verbose {
            println!("{} Scanning directory: {}", "📁".blue(), dir_path.display());
        }

        let start_time = Instant::now();
        let mut scannable_files = Vec::new();
        let mut skipped_count = 0;

        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if path
                .extension()
                .map_or(false, |ext| ext == "jar" || ext == "class")
            {
                let relative_path = match path.strip_prefix(dir_path) {
                    Ok(p) => p.to_string_lossy().replace('\\', "/"),
                    Err(_) => {
                        if self.options.verbose {
                            eprintln!(
                                "{} Warning: Could not strip prefix for path {}. Using full path for filtering.",
                                "⚠️".yellow(), path.display()
                            );
                        }
                        path.to_string_lossy().replace('\\', "/")
                    }
                };

                if self.should_scan(&relative_path) {
                    scannable_files.push(path.to_path_buf());
                } else {
                    skipped_count += 1;
                }
            }
        }

        if scannable_files.is_empty() {
            if self.options.verbose {
                println!(
                    "{} No scannable files found{} in directory {}",
                    "ℹ️".blue(),
                    if skipped_count > 0 {
                        format!(" ({} skipped by filters)", skipped_count).dimmed()
                    } else {
                        "".into()
                    },
                    dir_path.display()
                );
            }
            return Ok(results);
        }

        if self.options.verbose {
            println!(
                "{} Found {} scannable files{} in {}ms",
                "🔍".green(),
                scannable_files.len(),
                if skipped_count > 0 {
                    format!(" ({} skipped by filters)", skipped_count).dimmed()
                } else {
                    "".into()
                },
                start_time.elapsed().as_millis()
            );
        }

        let multi_progress = MultiProgress::new();
        let progress_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> ");

        let progress = multi_progress.add(ProgressBar::new(scannable_files.len() as u64));
        progress.set_style(progress_style);
        progress.set_message("Processing files...");

        let scan_results: Vec<_> = scannable_files
            .par_iter()
            .map(|path| {
                let result = if self.options.verbose {
                    println!("{} Scanning: {}", "🔍".dimmed(), path.display());
                    self.scan_path(path)
                } else {
                    self.scan_path(path)
                };

                progress.inc(1);
                result
            })
            .collect();

        progress.finish_with_message(format!("Finished scanning {} files", scannable_files.len()));

        for result in scan_results {
            match result {
                Ok(mut scan_results) => results.append(&mut scan_results),
                Err(e) => eprintln!("{} Error scanning: {}", "⚠️".yellow(), e),
            }
        }

        if self.options.verbose {
            println!(
                "{} Directory scan completed in {:.2}s",
                "✅".green(),
                start_time.elapsed().as_secs_f64()
            );
        }

        Ok(results)
    }

    fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let start_time = Instant::now();
        let file = File::open(jar_path)?;
        let mut archive = ZipArchive::new(file)?;
        let total_files = archive.len();
        let multi_progress = MultiProgress::new();
        let mut skipped_count = 0;

        if self.options.verbose {
            println!(
                "{} Filtering and reading entries from {}",
                "🔎".blue(),
                jar_path.display()
            );
        }

        let mut entries_to_scan = Vec::new();
        let mut all_resource_info = Vec::new();

        for i in 0..total_files {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "{} Error accessing entry {} in {}: {}",
                        "⚠️".yellow(),
                        i,
                        jar_path.display(),
                        e
                    );
                    continue;
                }
            };

            let original_entry_name = match file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => String::from_utf8_lossy(file.name_raw()).replace('\\', "/"),
            };

            if !self.should_scan(&original_entry_name) {
                skipped_count += 1;
                continue;
            }

            let file_size = file.size() as usize;
            let mut file_data = Vec::with_capacity(file_size);
            if let Err(e) = file.read_to_end(&mut file_data) {
                eprintln!(
                    "{} Error reading content of {}: {}",
                    "⚠️".yellow(),
                    original_entry_name,
                    e
                );
                continue;
            }

            if self.options.extract_resources {
                if let Err(e) = self.extract_resource(&original_entry_name, &file_data) {
                    eprintln!(
                        "{} Error during extraction of {}: {}",
                        "⚠️".yellow(),
                        original_entry_name,
                        e
                    );
                }
            }

            match self.analyze_resource(&original_entry_name, &file_data) {
                Ok(resource_info) => {
                    if self.options.export_json {
                        all_resource_info.push(resource_info.clone());
                    }

                    if resource_info.is_class_file || resource_info.is_dead_class_candidate {
                        entries_to_scan.push((
                            original_entry_name,
                            file_data.clone(),
                            resource_info,
                        ));
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Error analyzing resource {}: {}",
                        "⚠️".yellow(),
                        original_entry_name,
                        e
                    );
                }
            }
        }

        if self.options.verbose {
            println!(
                "{} Filtered {} entries, {} class candidates found for analysis{}",
                "📊".blue(),
                total_files,
                entries_to_scan.len(),
                if skipped_count > 0 {
                    format!(" ({} skipped by filters)", skipped_count).dimmed()
                } else {
                    "".into()
                }
            );
        }

        if entries_to_scan.is_empty()
            && !self.options.extract_resources
            && !self.options.export_json
        {
            if self.options.verbose {
                println!(
                    "{} No class files found for analysis after filtering.",
                    "ℹ️".blue()
                );
            }
        } else if entries_to_scan.is_empty() {
            if self.options.verbose {
                println!("{} No class files found for analysis, but extraction/export may have occurred.", "ℹ️".blue());
            }
        }

        let pb_template = if self.options.verbose {
            format!(
                "{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Analyzing: {{msg}}",
                "🔬".green()
            )
        } else {
            format!(
                "{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Analyzing {}",
                "🔬".green(),
                jar_path.file_name().unwrap_or_default().to_string_lossy()
            )
        };
        let pb = multi_progress.add(ProgressBar::new(entries_to_scan.len() as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(&pb_template)?
                .progress_chars("=> "),
        );

        let processed_count = AtomicUsize::new(0);
        let results: Vec<ScanResult> = entries_to_scan
            .par_iter()
            // Note: file_data is cloned implicitly when captured by the closure
            .filter_map(|(original_path, file_data, resource_info)| {
                if self.options.verbose {
                    pb.set_message(original_path.clone());
                }
                let result =
                    // Pass data by slice reference here
                    self.scan_class_data(file_data, original_path, Some(resource_info.clone()));

                let _count = processed_count.fetch_add(1, Ordering::SeqCst);
                pb.inc(1);

                match result {
                    Ok(Some(scan_result)) => Some(scan_result),
                    Ok(None) => None, // Class scanned, but no findings / not verbose enough to report
                    Err(e) => {
                        eprintln!(
                            "{} Error processing class {}: {}",
                            "⚠️".yellow(),
                            original_path,
                            e
                        );
                        None // Skip classes that error during detailed parsing
                    }
                }
            })
            .collect();

        pb.finish_with_message(format!(
            "Finished analyzing {} classes",
            entries_to_scan.len()
        ));

        // Export resource info (collected earlier) if requested
        if self.options.export_json && !all_resource_info.is_empty() {
            let resources_json_path = self.options.output_dir.join(format!(
                "{}_resources.json",
                jar_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .replace(".jar", "")
            ));
            let json = serde_json::to_string_pretty(&all_resource_info)?;
            match File::create(&resources_json_path) {
                Ok(mut json_file) => {
                    if let Err(e) = json_file.write_all(json.as_bytes()) {
                        eprintln!(
                            "{} Error writing resources JSON to {}: {}",
                            "⚠️".yellow(),
                            resources_json_path.display(),
                            e
                        );
                    }
                }
                Err(e) => eprintln!(
                    "{} Error creating resources JSON file {}: {}",
                    "⚠️".yellow(),
                    resources_json_path.display(),
                    e
                ),
            };
        }

        if self.options.verbose {
            println!(
                "{} JAR scan completed in {:.2}s",
                "✅".green(),
                start_time.elapsed().as_secs_f64()
            );
        }

        Ok(results) // Return the analysis results (findings in classes)
    }

    fn analyze_resource(
        &self,
        original_path_str: &str,
        data: &[u8],
    ) -> Result<ResourceInfo, ScanError> {
        let is_class_name_candidate =
            original_path_str.ends_with(".class") || original_path_str.ends_with(".class/");

        let is_standard_class_file =
            is_class_name_candidate && data.len() >= 4 && &data[0..4] == b"\xCA\xFE\xBA\xBE";

        let is_dead_class_candidate =
            is_class_name_candidate && data.len() >= 2 && &data[0..2] == b"\xDE\xAD";

        Ok(ResourceInfo {
            path: original_path_str.to_string(),
            size: data.len() as u64,
            is_class_file: is_standard_class_file,
            entropy: Self::calculate_entropy(data),
            is_dead_class_candidate,
        })
    }

    fn scan_class_file_data(
        &self,
        original_path_str: &str,
        data: Vec<u8>,
        resource_info: Option<ResourceInfo>,
    ) -> Result<ScanResult, ScanError> {
        let res_info = match resource_info {
            Some(ri) => ri,
            None => self.analyze_resource(original_path_str, &data)?,
        };

        let result = self
            .scan_class_data(&data, &res_info.path, Some(res_info.clone()))?
            .unwrap_or_else(|| {
                if self.options.verbose || self.options.export_json {
                    ScanResult {
                        file_path: res_info.path.clone(),
                        matches: Vec::new(),
                        class_details: None,
                        resource_info: Some(res_info),
                    }
                } else {
                    ScanResult {
                        file_path: res_info.path.clone(),
                        matches: vec![],
                        class_details: None,
                        resource_info: Some(res_info),
                    }
                }
            });

        Ok(result)
    }

    fn scan_class_data(
        &self,
        data: &[u8],
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let mut findings = Vec::new();

        if data.len() >= 2 && data[0] == 0xDE && data[1] == 0xAD {
            {
                let mut found_flag = self.found_custom_jvm_indicator.lock().unwrap();
                *found_flag = true;
            }

            if let Some(ref ri) = resource_info {
                self.check_high_entropy(ri, &mut findings);
            }

            if !findings.is_empty() || self.options.verbose || self.options.export_json {
                return Ok(Some(ScanResult {
                    file_path: original_path_str.to_string(),
                    matches: findings,
                    class_details: None,
                    resource_info,
                }));
            } else {
                return Ok(None);
            }
        }

        let class_details = match self.parse_class_structure(data, original_path_str) {
            Ok(details) => details,
            Err(e) => return Err(e),
        };

        if let Some(ref ri) = resource_info {
            self.check_high_entropy(ri, &mut findings);
        } else {
            let entropy = Self::calculate_entropy(data);
            let fallback_ri = ResourceInfo {
                path: original_path_str.to_string(),
                size: data.len() as u64,
                is_class_file: true,
                entropy,
                is_dead_class_candidate: false,
            };
            self.check_high_entropy(&fallback_ri, &mut findings);
        }

        self.check_name_obfuscation(&class_details, &mut findings);

        for string in &class_details.strings {
            if string.is_empty() {
                continue;
            }
            self.check_string_patterns(string, &mut findings);
        }

        if self.options.extract_strings && !class_details.strings.is_empty() {
            self.write_strings_to_file(original_path_str, &class_details.strings)?;
        }

        if !findings.is_empty() || self.options.verbose || self.options.export_json {
            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: findings,
                class_details: Some(class_details),
                resource_info,
            }))
        } else {
            Ok(None)
        }
    }

    fn check_high_entropy(
        &self,
        resource_info: &ResourceInfo,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if self.options.mode == DetectionMode::Obfuscation
            || self.options.mode == DetectionMode::All
        {
            if resource_info.entropy > ENTROPY_THRESHOLD {
                let mut context = String::new();
                if resource_info.is_class_file {
                    context.push_str(" (Standard Class)");
                } else if resource_info.is_dead_class_candidate {
                    context.push_str(" (Custom JVM Class Candidate)");
                } else {
                }

                findings.push((
                    FindingType::HighEntropy,
                    format!(
                        "Entropy: {:.2} (Threshold: {:.2}){}",
                        resource_info.entropy, ENTROPY_THRESHOLD, context
                    ),
                ));
            }
        }
    }

    fn get_simple_name(fqn: &str) -> &str {
        let name_part = fqn.strip_suffix('/').unwrap_or(fqn);
        name_part
            .rsplit(|c| c == '/' || c == '.')
            .next()
            .unwrap_or(name_part)
    }

    fn check_name_obfuscation(
        &self,
        details: &ClassDetails,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if self.options.mode != DetectionMode::Obfuscation
            && self.options.mode != DetectionMode::All
        {
            return;
        }

        let mut check = |name: &str, context: &str| {
            if name.is_empty() || name == "java/lang/Object" {
                return;
            }

            let name_char_count = name.chars().count();

            if name.contains('/')
                && context.ends_with(" Name")
                && !context.starts_with("Class")
                && !context.starts_with("Superclass")
                && !context.starts_with("Interface")
            {
                let simple_name = Self::get_simple_name(name);
                if simple_name.contains('/') && simple_name == name {
                    if self.options.verbose {
                        println!("      Suspicious name contains '/': {} - {}", context, name);
                    }
                }
            } else if name_char_count > NAME_LENGTH_THRESHOLD {
                findings.push((
                    FindingType::ObfuscationLongName,
                    format!(
                        "{} '{}' (len {})",
                        context,
                        truncate_string(name, 60),
                        name_char_count
                    ),
                ));
            }

            let simple_name_to_check = Self::get_simple_name(name);
            if self
                .suspicious_consecutive_chars_regex
                .is_match(simple_name_to_check)
            {
                findings.push((
                    FindingType::ObfuscationChars,
                    format!(
                        "Consecutive Symbols: {} '{}'",
                        context,
                        truncate_string(name, 60)
                    ),
                ));
            }

            let non_ascii_count = name.chars().filter(|&c| !c.is_ascii()).count();
            if non_ascii_count > 0 {
                findings.push((
                    FindingType::ObfuscationUnicode,
                    format!(
                        "{} '{}' ({} non-ASCII chars)",
                        context,
                        truncate_string(name, 60),
                        non_ascii_count
                    ),
                ));
            }
        };

        check(&details.class_name, "Class Name");
        if !details.superclass_name.is_empty() {
            check(&details.superclass_name, "Superclass Name");
        }
        details
            .interfaces
            .iter()
            .for_each(|i| check(i, "Interface Name"));
        details
            .fields
            .iter()
            .for_each(|f| check(&f.name, "Field Name"));
        details
            .methods
            .iter()
            .filter(|m| m.name != "<init>" && m.name != "<clinit>")
            .for_each(|m| check(&m.name, "Method Name"));
    }

    fn check_string_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if self.options.mode == DetectionMode::Network || self.options.mode == DetectionMode::All {
            if let Some(cap) = self.ip_regex.captures(string) {
                findings.push((
                    FindingType::IpAddress,
                    cap.get(0).unwrap().as_str().to_string(),
                ));
            }
            if let Some(cap) = self.ipv6_regex.captures(string) {
                findings.push((
                    FindingType::IpV6Address,
                    cap.get(0).unwrap().as_str().to_string(),
                ));
            }
            if let Some(cap) = self.url_regex.captures(string) {
                let url = cap.get(0).unwrap().as_str().to_string();
                let domain = self.extract_domain(&url);
                if !domain.is_empty() && !self.is_good_link(&domain) {
                    findings.push((FindingType::Url, url));
                }
            }
        }
        if self.options.mode == DetectionMode::Crypto || self.options.mode == DetectionMode::All {
            if let Some(cap) = self.crypto_regex.captures(string) {
                let keyword = cap.get(0).unwrap().as_str();
                if !self
                    .ignored_crypto_keywords
                    .contains(&keyword.to_lowercase())
                {
                    findings.push((
                        FindingType::Crypto,
                        format!("'{}' in \"{}\"", keyword, truncate_string(string, 80)),
                    ));
                }
            }
        }
        if self.options.mode == DetectionMode::Malicious || self.options.mode == DetectionMode::All
        {
            if let Some(cap) = self.malicious_pattern_regex.captures(string) {
                let keyword = cap.get(0).unwrap().as_str();
                if !self
                    .ignored_suspicious_keywords
                    .contains(&keyword.to_lowercase())
                {
                    findings.push((
                        FindingType::SuspiciousKeyword,
                        format!("'{}' in \"{}\"", keyword, truncate_string(string, 80)),
                    ));
                }
            }
        }
    }

    fn parse_class_structure(
        &self,
        data: &[u8],
        original_path_str: &str,
    ) -> Result<ClassDetails, ScanError> {
        let mut cursor = Cursor::new(data);

        if data.len() < 10 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "File too small for valid class header".to_string(),
            });
        }
        let magic = cursor.read_u32::<BigEndian>()?;
        if magic != 0xCAFEBABE {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: format!(
                    "Invalid magic number: Expected 0xCAFEBABE, found {:#X}",
                    magic
                ),
            });
        }
        let _minor_version = cursor.read_u16::<BigEndian>()?;
        let _major_version = cursor.read_u16::<BigEndian>()?;

        let cp_count = cursor.read_u16::<BigEndian>()?;
        if cp_count == 0 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "Invalid constant pool count: 0".to_string(),
            });
        }

        let constant_pool = self.parse_constant_pool(&mut cursor, cp_count, original_path_str)?;

        let resolve_utf8 = |index: u16, context: &str| -> Result<String, ScanError> {
            if index == 0 || (index as usize) > constant_pool.len() {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!(
                        "Invalid CP index {} for UTF8 ({}) (pool size {})",
                        index,
                        context,
                        constant_pool.len()
                    ),
                });
            }
            match constant_pool.get(index as usize - 1) {
                Some(ConstantPoolEntry::Utf8(s)) => Ok(s.clone()),
                Some(other) => Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!(
                        "Expected UTF8 at CP index {} ({}), found {:?}",
                        index, context, other
                    ),
                }),
                None => Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!("CP index {} out of bounds ({})", index, context),
                }),
            }
        };

        let resolve_class_name = |index: u16, context: &str| -> Result<String, ScanError> {
            if index == 0 {
                if context == "super_class" {
                    if self.options.verbose {
                        println!(
                            "{} Warning: Superclass index is 0 in '{}', assuming java/lang/Object.",
                            "⚠️".yellow(),
                            original_path_str
                        );
                    }
                    return Ok("java/lang/Object".to_string());
                } else if context == "this_class" {
                    return Err(ScanError::ClassParseError {
                        path: original_path_str.to_string(),
                        msg: "Invalid CP index 0 for this_class".to_string(),
                    });
                } else {
                    if self.options.verbose {
                        println!(
                            "{} Warning: Class index is 0 for {} in '{}'. Using placeholder.",
                            "⚠️".yellow(),
                            context,
                            original_path_str
                        );
                    }
                    return Ok("<INVALID_CLASS_INDEX_0>".to_string());
                }
            }
            if (index as usize) > constant_pool.len() {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!(
                        "Invalid CP index {} for Class ({}) (pool size {})",
                        index,
                        context,
                        constant_pool.len()
                    ),
                });
            }
            match constant_pool.get(index as usize - 1) {
                Some(ConstantPoolEntry::Class(name_index)) => resolve_utf8(
                    *name_index,
                    &format!("name for Class at {} ({})", index, context),
                ),
                Some(other) => Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!(
                        "Expected Class info at CP index {} ({}), found {:?}",
                        index, context, other
                    ),
                }),
                None => Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!("CP index {} out of bounds ({})", index, context),
                }),
            }
        };

        if cursor.position() + 6 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "EOF before class flags/indices".to_string(),
            });
        }
        let access_flags = cursor.read_u16::<BigEndian>()?;
        let this_class_index = cursor.read_u16::<BigEndian>()?;
        let super_class_index = cursor.read_u16::<BigEndian>()?;

        let class_name = resolve_class_name(this_class_index, "this_class")?;
        let superclass_name = resolve_class_name(super_class_index, "super_class")?;

        if cursor.position() + 2 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "EOF before interfaces_count".to_string(),
            });
        }
        let interfaces_count = cursor.read_u16::<BigEndian>()?;
        let mut interfaces = Vec::with_capacity(interfaces_count as usize);
        for i in 0..interfaces_count {
            if cursor.position() + 2 > data.len() as u64 {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!("EOF reading interface index {}", i),
                });
            }
            let interface_index = cursor.read_u16::<BigEndian>()?;
            interfaces.push(resolve_class_name(
                interface_index,
                &format!("interface {}", i),
            )?);
        }

        if cursor.position() + 2 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "EOF before fields_count".to_string(),
            });
        }
        let fields_count = cursor.read_u16::<BigEndian>()?;
        let mut fields = Vec::with_capacity(fields_count as usize);
        for f_idx in 0..fields_count {
            if cursor.position() + 8 > data.len() as u64 {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!("EOF reading field header {}", f_idx),
                });
            }
            let field_access_flags = cursor.read_u16::<BigEndian>()?;
            let name_index = cursor.read_u16::<BigEndian>()?;
            let descriptor_index = cursor.read_u16::<BigEndian>()?;
            let attributes_count = cursor.read_u16::<BigEndian>()?;

            let field_name = match resolve_utf8(name_index, &format!("field {} name", f_idx)) {
                Ok(n) => n,
                Err(e) => {
                    if self.options.verbose {
                        println!("{} Field name resolution error: {}", "⚠️".yellow(), e);
                    }
                    format!("<INVALID_FIELD_NAME_{}>", f_idx)
                }
            };
            let field_descriptor =
                match resolve_utf8(descriptor_index, &format!("field {} descriptor", f_idx)) {
                    Ok(d) => d,
                    Err(e) => {
                        if self.options.verbose {
                            println!("{} Field descriptor resolution error: {}", "⚠️".yellow(), e);
                        }
                        "<INVALID_DESCRIPTOR>".to_string()
                    }
                };

            Self::skip_attributes(
                &mut cursor,
                attributes_count,
                original_path_str,
                "field",
                f_idx,
            )?;
            fields.push(FieldInfo {
                name: field_name,
                descriptor: field_descriptor,
                access_flags: field_access_flags,
            });
        }

        if cursor.position() + 2 > data.len() as u64 {
            return Err(ScanError::ClassParseError {
                path: original_path_str.to_string(),
                msg: "EOF before methods_count".to_string(),
            });
        }
        let methods_count = cursor.read_u16::<BigEndian>()?;
        let mut methods = Vec::with_capacity(methods_count as usize);
        for m_idx in 0..methods_count {
            if cursor.position() + 8 > data.len() as u64 {
                return Err(ScanError::ClassParseError {
                    path: original_path_str.to_string(),
                    msg: format!("EOF reading method header {}", m_idx),
                });
            }
            let method_access_flags = cursor.read_u16::<BigEndian>()?;
            let name_index = cursor.read_u16::<BigEndian>()?;
            let descriptor_index = cursor.read_u16::<BigEndian>()?;
            let attributes_count = cursor.read_u16::<BigEndian>()?;

            let method_name = match resolve_utf8(name_index, &format!("method {} name", m_idx)) {
                Ok(n) => n,
                Err(e) => {
                    if self.options.verbose {
                        println!("{} Method name resolution error: {}", "⚠️".yellow(), e);
                    }
                    format!("<INVALID_METHOD_NAME_{}>", m_idx)
                }
            };
            let method_descriptor =
                match resolve_utf8(descriptor_index, &format!("method {} descriptor", m_idx)) {
                    Ok(d) => d,
                    Err(e) => {
                        if self.options.verbose {
                            println!(
                                "{} Method descriptor resolution error: {}",
                                "⚠️".yellow(),
                                e
                            );
                        }
                        "<INVALID_DESCRIPTOR>".to_string()
                    }
                };

            Self::skip_attributes(
                &mut cursor,
                attributes_count,
                original_path_str,
                "method",
                m_idx,
            )?;
            methods.push(MethodInfo {
                name: method_name,
                descriptor: method_descriptor,
                access_flags: method_access_flags,
            });
        }

        let strings = constant_pool
            .iter()
            .filter_map(|entry| match entry {
                ConstantPoolEntry::String(utf8_index) => {
                    match resolve_utf8(*utf8_index, "String constant") {
                        Ok(s) => Some(s),
                        Err(e) => {
                            if self.options.verbose {
                                println!(
                                    "{} String constant resolution error: {}",
                                    "⚠️".yellow(),
                                    e
                                );
                            }
                            None
                        }
                    }
                }
                ConstantPoolEntry::Utf8(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        Ok(ClassDetails {
            class_name,
            superclass_name,
            interfaces,
            methods,
            fields,
            strings,
            access_flags,
        })
    }

    fn parse_constant_pool(
        &self,
        cursor: &mut Cursor<&[u8]>,
        cp_count: u16,
        file_path_str: &str,
    ) -> Result<Vec<ConstantPoolEntry>, ScanError> {
        if cp_count <= 1 {
            return Ok(Vec::new());
        }
        let capacity = cp_count as usize - 1;

        let mut constant_pool = Vec::with_capacity(capacity);
        let mut i = 1;
        let data_len = cursor.get_ref().len() as u64;

        fn check_needed_bytes(
            cur_pos: u64,
            needed: u64,
            data_len: u64,
            tag: u8,
            index: u16,
            path: &str,
            cp_count: u16,
        ) -> Result<(), ScanError> {
            if index >= cp_count {
                return Err(ScanError::ClassParseError {
                    path: path.to_string(),
                    msg: format!(
                        "Attempted to read CP entry at index {}, but cp_count is only {}",
                        index, cp_count
                    ),
                });
            }
            if cur_pos.saturating_add(needed) > data_len {
                Err(ScanError::ClassParseError {
                    path: path.to_string(),
                    msg: format!(
                        "EOF before reading data for CP tag {} at index {} (pos {}, needed {}, total len {})",
                        tag, index, cur_pos, needed, data_len
                    ),
                })
            } else {
                Ok(())
            }
        }

        while i < cp_count {
            let start_pos = cursor.position();
            check_needed_bytes(start_pos, 1, data_len, 0, i, file_path_str, cp_count)?;
            let tag = cursor.read_u8()?;

            let (needed_data_bytes, entry_slots) = match tag {
                1 => (2u64, 1u16),
                7 | 8 | 16 | 19 | 20 => (2, 1),
                3 | 4 => (4, 1),
                9 | 10 | 11 | 12 | 17 | 18 => (4, 1),
                5 | 6 => (8, 2),
                15 => (3, 1),
                _ => {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!("Unknown CP tag {} at index {}", tag, i),
                    });
                }
            };

            if tag != 1 {
                check_needed_bytes(
                    start_pos + 1,
                    needed_data_bytes,
                    data_len,
                    tag,
                    i,
                    file_path_str,
                    cp_count,
                )?;
            }

            let entry = match tag {
                1 => {
                    check_needed_bytes(
                        cursor.position(),
                        2,
                        data_len,
                        tag,
                        i,
                        file_path_str,
                        cp_count,
                    )?;
                    let length = cursor.read_u16::<BigEndian>()? as usize;
                    check_needed_bytes(
                        cursor.position(),
                        length as u64,
                        data_len,
                        tag,
                        i,
                        file_path_str,
                        cp_count,
                    )?;
                    let mut buf = vec![0; length];
                    cursor.read_exact(&mut buf)?;
                    let (cow, _, had_errors) = UTF_8.decode(&buf);
                    if had_errors && self.options.verbose {
                        eprintln!(
                            "{} Warning: UTF-8 decoding errors in CP index {} ('{}')",
                            "⚠️".yellow(),
                            i,
                            file_path_str
                        );
                    }
                    ConstantPoolEntry::Utf8(cow.into_owned())
                }
                7 => ConstantPoolEntry::Class(cursor.read_u16::<BigEndian>()?),
                8 => ConstantPoolEntry::String(cursor.read_u16::<BigEndian>()?),
                3 => {
                    cursor.seek(SeekFrom::Current(4))?;
                    ConstantPoolEntry::Integer
                }
                4 => {
                    cursor.seek(SeekFrom::Current(4))?;
                    ConstantPoolEntry::Float
                }
                9 => {
                    let c = cursor.read_u16::<BigEndian>()?;
                    let n = cursor.read_u16::<BigEndian>()?;
                    ConstantPoolEntry::Fieldref(c, n)
                }
                10 => {
                    let c = cursor.read_u16::<BigEndian>()?;
                    let n = cursor.read_u16::<BigEndian>()?;
                    ConstantPoolEntry::Methodref(c, n)
                }
                11 => {
                    let c = cursor.read_u16::<BigEndian>()?;
                    let n = cursor.read_u16::<BigEndian>()?;
                    ConstantPoolEntry::InterfaceMethodref(c, n)
                }
                12 => {
                    let n = cursor.read_u16::<BigEndian>()?;
                    let d = cursor.read_u16::<BigEndian>()?;
                    ConstantPoolEntry::NameAndType(n, d)
                }
                5 => {
                    cursor.seek(SeekFrom::Current(8))?;
                    ConstantPoolEntry::Long
                }
                6 => {
                    cursor.seek(SeekFrom::Current(8))?;
                    ConstantPoolEntry::Double
                }
                15 => {
                    cursor.seek(SeekFrom::Current(3))?;
                    ConstantPoolEntry::MethodHandle
                }
                16 => {
                    cursor.seek(SeekFrom::Current(2))?;
                    ConstantPoolEntry::MethodType
                }
                17 => {
                    cursor.seek(SeekFrom::Current(4))?;
                    ConstantPoolEntry::Dynamic
                }
                18 => {
                    cursor.seek(SeekFrom::Current(4))?;
                    ConstantPoolEntry::InvokeDynamic
                }
                19 => {
                    cursor.seek(SeekFrom::Current(2))?;
                    ConstantPoolEntry::Module
                }
                20 => {
                    cursor.seek(SeekFrom::Current(2))?;
                    ConstantPoolEntry::Package
                }
                _ => unreachable!(),
            };

            constant_pool.push(entry);
            if entry_slots == 2 {
                if i + 1 < cp_count {
                    constant_pool.push(ConstantPoolEntry::Placeholder);
                } else {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!(
                            "Corrupt CP: 2-slot entry (tag {}) at last index {} (cp_count {})",
                            tag, i, cp_count
                        ),
                    });
                }
            }
            i += entry_slots;
        }

        if constant_pool.len() != capacity {
            eprintln!(
                 "{} Warning: Constant pool size mismatch for '{}'. Parsed {} entries, expected capacity {}. File might be corrupt.",
                 "⚠️".yellow(),
                 file_path_str,
                 constant_pool.len(),
                 capacity
             );
        }

        Ok(constant_pool)
    }

    fn skip_attributes(
        cursor: &mut Cursor<&[u8]>,
        attributes_count: u16,
        file_path_str: &str,
        member_type: &str,
        member_index: u16,
    ) -> Result<(), ScanError> {
        let data_len = cursor.get_ref().len() as u64;
        for attr_index in 0..attributes_count {
            let attr_header_pos = cursor.position();
            if attr_header_pos.saturating_add(6) > data_len {
                return Err(ScanError::ClassParseError {
                    path: file_path_str.to_string(),
                    msg: format!(
                        "EOF reading attribute header {} for {} {} (at pos {})",
                        attr_index, member_type, member_index, attr_header_pos
                    ),
                });
            }
            let _attribute_name_index = cursor.read_u16::<BigEndian>()?;
            let attribute_length = cursor.read_u32::<BigEndian>()?;
            let current_pos = cursor.position();
            let end_pos = current_pos.saturating_add(attribute_length as u64);

            if end_pos > data_len {
                return Err(ScanError::ClassParseError { path: file_path_str.to_string(), msg: format!("Attribute {} length {} for {} {} exceeds file bounds (at pos {}, needs end pos {}, total len {})", attr_index, attribute_length, member_type, member_index, current_pos, end_pos, data_len) });
            }

            if attribute_length > 0 {
                if let Err(e) = cursor.seek(SeekFrom::Current(attribute_length as i64)) {
                    return Err(ScanError::ClassParseError {
                        path: file_path_str.to_string(),
                        msg: format!(
                            "IO Error seeking attribute {} data for {} {} (len {}, current_pos {}): {}",
                            attr_index, member_type, member_index, attribute_length, current_pos, e
                        ),
                    });
                };
            }
        }
        Ok(())
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut byte_counts = [0u64; 256];
        let len = data.len() as f64;
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }
        byte_counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&count| {
                let probability = count as f64 / len;
                -probability * probability.log2()
            })
            .sum()
    }

    fn write_strings_to_file(
        &self,
        original_path_str: &str,
        strings: &[String],
    ) -> Result<(), io::Error> {
        let safe_base_name = original_path_str.replace(
            |c: char| c == '/' || c == '\\' || !c.is_ascii_alphanumeric() && c != '.',
            "_",
        );
        let strings_path = self
            .options
            .output_dir
            .join(format!("{}_strings.txt", safe_base_name));

        if let Some(parent) = strings_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(&strings_path)?;
        let mut writer = io::BufWriter::new(file);

        for string in strings {
            if !string.is_empty() {
                if let Err(e) = writeln!(writer, "{}", string) {
                    eprintln!(
                        "{} Error writing string to {}: {}",
                        "⚠️".yellow(),
                        strings_path.display(),
                        e
                    );
                }
            }
        }
        Ok(())
    }

    fn extract_domain(&self, url_str: &str) -> String {
        let url_to_parse = if !url_str.contains("://") && url_str.contains('.') {
            format!("http://{}", url_str)
        } else {
            url_str.to_string()
        };

        Url::parse(&url_to_parse)
            .ok()
            .and_then(|url| {
                url.host_str()
                    .map(|host| host.trim_start_matches("www.").to_lowercase())
            })
            .unwrap_or_else(|| {
                url_str
                    .split_once("://")
                    .map_or(url_str, |(_scheme, rest)| rest)
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .split('@')
                    .last()
                    .unwrap_or("")
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .trim_start_matches("www.")
                    .to_lowercase()
            })
    }

    fn is_good_link(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let lower_domain = domain.to_lowercase();
        self.good_links
            .iter()
            .any(|good| lower_domain == *good || lower_domain.ends_with(&format!(".{}", good)))
    }

    fn extract_resource(&self, internal_path: &str, data: &[u8]) -> Result<(), ScanError> {
        let (final_outpath, is_directory) = if internal_path.ends_with(".class/") {
            let file_path_str = internal_path.trim_end_matches('/');
            (self.options.output_dir.join(file_path_str), false)
        } else if internal_path.ends_with('/') {
            (self.options.output_dir.join(internal_path), true)
        } else {
            (self.options.output_dir.join(internal_path), false)
        };

        if let Some(p) = final_outpath.parent() {
            if !p.exists() {
                fs::create_dir_all(p)?;
            }
        } else {
            if !self.options.output_dir.exists() {
                fs::create_dir_all(&self.options.output_dir)?;
            }
        }

        if is_directory {
            fs::create_dir_all(&final_outpath)?;
            Ok(())
        } else {
            match File::create(&final_outpath) {
                Ok(mut outfile) => {
                    if let Err(e) = outfile.write_all(data) {
                        eprintln!(
                            "{} Error writing extracted file {}: {}",
                            "⚠️".yellow(),
                            final_outpath.display(),
                            e
                        );
                        return Err(ScanError::IoError(io::Error::new(
                            io::ErrorKind::WriteZero,
                            e,
                        )));
                    }
                    Ok(())
                }
                Err(e) => {
                    eprintln!(
                        "{} Error creating extracted file {}: {}",
                        "⚠️".yellow(),
                        final_outpath.display(),
                        e
                    );
                    Err(ScanError::IoError(e))
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ConstantPoolEntry {
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

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let options = ScannerOptions {
        extract_strings: args.strings,
        extract_resources: args.extract,
        output_dir: args
            .output
            .map(PathBuf::from)
            .unwrap_or_else(|| ScannerOptions::default().output_dir),
        export_json: args.json,
        mode: args.mode,
        verbose: args.verbose,
        ignore_suspicious_file: args.ignore_suspicious,
        ignore_crypto_file: args.ignore_crypto,
        exclude_patterns: args.exclude,
        find_patterns: args.find,
    };

    if options.extract_resources || options.extract_strings || options.export_json {
        if let Err(e) = fs::create_dir_all(&options.output_dir) {
            eprintln!(
                "{} Failed to create output directory {}: {}",
                "❌".red(),
                options.output_dir.display(),
                e
            );
            return Err(Box::new(e));
        }
    }

    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if args.verbose {
            println!(
                "{} Using {} threads for processing.",
                "🧵".blue(),
                args.threads
            );
        }
    } else if args.verbose {
        println!(
            "{} Using automatic number of threads (Rayon default).",
            "🧵".blue()
        );
    }

    let scanner = CollapseScanner::new(options.clone())?;

    if options.verbose
        && (options.extract_resources || options.extract_strings || options.export_json)
    {
        println!(
            "{} Using output directory: {}",
            "➡️".cyan(),
            options.output_dir.display()
        );
    }
    let path_arg = args.path.unwrap_or_else(|| ".".to_string());
    let path = PathBuf::from(&path_arg);
    if !path.exists() {
        eprintln!("{} Path does not exist: {}", "❌".red(), path.display());
        std::process::exit(1);
    }
    println!(
        "\n{}",
        "==== CollapseScanner - Enhanced Analysis ===="
            .bright_blue()
            .bold()
    );
    println!(
        "{} Target: {}",
        "🎯".green(),
        path.display().to_string().bright_white()
    );
    println!(
        "{} Mode: {}",
        "🔧".yellow(),
        format!("{:?}", args.mode).bright_white()
    );
    if !scanner.options.exclude_patterns.is_empty() {
        println!(
            "{} Exclude Patterns: {}",
            "🚫".yellow(),
            scanner.options.exclude_patterns.join(", ").dimmed()
        );
    }
    if !scanner.options.find_patterns.is_empty() {
        println!(
            "{} Find Patterns: {}",
            "🔍".yellow(),
            scanner.options.find_patterns.join(", ").dimmed()
        );
    }

    if let Some(p) = &scanner.options.ignore_suspicious_file {
        println!(
            "{} Ignoring Suspicious: {}",
            "📄".yellow(),
            p.display().to_string().dimmed()
        );
    }
    if let Some(p) = &scanner.options.ignore_crypto_file {
        println!(
            "{} Ignoring Crypto: {}",
            "📄".yellow(),
            p.display().to_string().dimmed()
        );
    }
    if args.verbose {
        println!("{} Verbose: {}", "🔊".yellow(), "Enabled".bright_white());
    }
    println!("{}", "🚀 Starting scan...".bright_green());

    match scanner.scan_path(&path) {
        Ok(results) => {
            let significant_results: Vec<&ScanResult> = results
                .iter()
                .filter(|r| {
                    !r.matches.is_empty() || scanner.options.export_json || scanner.options.verbose
                })
                .collect();

            if significant_results.is_empty() {
                let potentially_scannable = if path.is_file() {
                    path.extension()
                        .map_or(false, |ext| ext == "jar" || ext == "class")
                } else if path.is_dir() {
                    WalkDir::new(&path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .any(|e| {
                            e.file_type().is_file()
                                && e.path()
                                    .extension()
                                    .map_or(false, |ext| ext == "jar" || ext == "class")
                        })
                } else {
                    false
                };

                if !potentially_scannable {
                    println!(
                        "\n{}",
                        "🤷 No scannable files (.jar, .class) found in the target path.".yellow()
                    );
                } else if !scanner.exclude_patterns.is_empty() || !scanner.find_patterns.is_empty()
                {
                    println!(
                        "\n{}",
                        "✅ No findings in files matching filter criteria.".green()
                    );
                } else {
                    println!("\n{}", "✅ No findings matching current criteria.".green());
                }
            } else {
                println!("\n{}", "⚠️  Findings Report:".bright_yellow().bold());
                let mut findings_by_type: HashMap<FindingType, usize> = HashMap::new();
                let mut total_findings = 0;

                let mut sorted_significant_results = significant_results;
                sorted_significant_results.sort_by_key(|r| &r.file_path);

                for result in sorted_significant_results {
                    println!(
                        "\n{}",
                        format!("📄 File: {}", result.file_path).bright_cyan()
                    );
                    if scanner.options.verbose {
                        if let Some(ri) = &result.resource_info {
                            let class_type = if ri.is_class_file {
                                " (Standard Class)"
                            } else if ri.is_dead_class_candidate {
                                " (Custom JVM Class Candidate)"
                            } else if ri.path.ends_with(".class") || ri.path.ends_with(".class/") {
                                " (Non-standard Class File)"
                            } else {
                                ""
                            };
                            println!(
                                "   {} Size: {} bytes, Entropy: {:.2}{}",
                                "📊".dimmed(),
                                ri.size,
                                ri.entropy,
                                class_type.dimmed()
                            );
                        } else if result.class_details.is_some() {
                            println!(
                                "   {} {}",
                                "ℹ️".dimmed(),
                                "(Standard Class - Info Missing)".dimmed()
                            );
                        }
                        if result.matches.is_empty() {
                            println!("   {}", "No specific findings in this file.".dimmed());
                        }
                    }

                    let mut sorted_matches = result.matches.clone();
                    sorted_matches.sort_by_key(|(t, v)| (format!("{}", t), v.clone()));

                    for (finding_type, value) in &sorted_matches {
                        *findings_by_type.entry(finding_type.clone()).or_insert(0) += 1;
                        total_findings += 1;
                        let (icon, color) = match finding_type {
                            FindingType::IpAddress | FindingType::IpV6Address => {
                                ("🌐", "bright_red")
                            }
                            FindingType::Url => ("🔗", "bright_red"),
                            FindingType::Crypto => ("🔒", "bright_yellow"),
                            FindingType::SuspiciousKeyword => ("❗", "red"),
                            FindingType::ObfuscationLongName => ("📏", "bright_magenta"),
                            FindingType::ObfuscationChars => ("❓", "magenta"),
                            FindingType::ObfuscationUnicode => ("㊙️ ", "magenta"),
                            FindingType::HighEntropy => ("🔥", "yellow"),
                        };
                        println!(
                            "  {} {}: {}",
                            icon.color(color).bold(),
                            finding_type.to_string().color(color).bold(),
                            value.bright_white()
                        );
                    }
                }

                println!("\n{}", "==== Scan Summary ====".bright_blue().bold());
                if total_findings > 0 {
                    println!(
                        "{} Total Findings: {}",
                        "📈".yellow(),
                        total_findings.to_string().bright_white().bold()
                    );
                    let mut sorted_findings: Vec<_> = findings_by_type.iter().collect();
                    sorted_findings.sort_by_key(|(k, _)| format!("{}", k));

                    for (finding_type, count) in sorted_findings {
                        let color = match finding_type {
                            FindingType::IpAddress
                            | FindingType::IpV6Address
                            | FindingType::Url
                            | FindingType::SuspiciousKeyword => "bright_red",
                            FindingType::Crypto | FindingType::HighEntropy => "bright_yellow",
                            FindingType::ObfuscationLongName
                            | FindingType::ObfuscationChars
                            | FindingType::ObfuscationUnicode => "bright_magenta",
                        };
                        println!(
                            "  - {}: {}",
                            finding_type.to_string().color(color),
                            count.to_string().bright_white()
                        );
                    }
                } else {
                    println!(
                        "{}",
                        "✅ No specific findings detected based on current criteria.".green()
                    );
                }
            }

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm {
                println!( "\n{}",
                     format!( "{} {}",
                             "👻".cyan().bold(),
                              "Warning: Files starting with 0xDEAD magic bytes were detected. These likely require a custom JVM or ClassLoader to execute correctly."
                     ).yellow()
                 );
            }

            if scanner.options.export_json {
                let json_output_path = scanner.options.output_dir.join(format!(
                    "{}_scan_results.json",
                    path.file_stem()
                        .unwrap_or_else(|| std::ffi::OsStr::new("scan"))
                        .to_string_lossy()
                ));
                let mut sorted_results = results;
                sorted_results.sort_by_key(|r| r.file_path.clone());
                let json_data = serde_json::to_string_pretty(&sorted_results)?;

                match File::create(&json_output_path) {
                    Ok(mut json_file) => {
                        if let Err(e) = json_file.write_all(json_data.as_bytes()) {
                            eprintln!(
                                "{} Error writing JSON results to {}: {}",
                                "⚠️".yellow(),
                                json_output_path.display(),
                                e
                            );
                        } else {
                            println!(
                                "\n{} Detailed scan results saved to: {}",
                                "💾".green(),
                                json_output_path.display().to_string().bright_white()
                            );
                        }
                    }
                    Err(e) => eprintln!(
                        "{} Error creating JSON results file {}: {}",
                        "⚠️".yellow(),
                        json_output_path.display(),
                        e
                    ),
                }
            }
            if scanner.options.extract_resources {
                println!(
                    "{} Resources extracted to: {}",
                    "📦".green(),
                    scanner
                        .options
                        .output_dir
                        .display()
                        .to_string()
                        .bright_white()
                );
            }
            if scanner.options.extract_strings {
                println!(
                    "{} Strings extracted to: {}",
                    "🔤".green(),
                    scanner
                        .options
                        .output_dir
                        .display()
                        .to_string()
                        .bright_white()
                );
            }
        }
        Err(e) => {
            eprintln!("\n{} {}", "❌ Error during scan:".bright_red().bold(), e);
            std::process::exit(1);
        }
    }

    Ok(())
}
