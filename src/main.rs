mod database;

use byteorder::{BigEndian, ReadBytesExt};
use clap::{Parser, ValueEnum};
use colored::*;
use database::GOOD_LINKS;
use encoding_rs::UTF_8;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;
use walkdir::WalkDir;
use zip::ZipArchive;

#[derive(Debug, Clone)]
struct ScanResult {
    file_path: String,
    matches: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClassStructure {
    class_name: String,
    superclass: String,
    interfaces: Vec<String>,
    methods: Vec<MethodInfo>,
    fields: Vec<FieldInfo>,
    strings: Vec<String>,
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
}

#[derive(Debug, Error)]
enum ScanError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),
    #[error("Parse error: {0}")]
    ParseError(String),
}

#[derive(Parser)]
#[clap(
    author,
    version,
    about = "Advanced JAR/class file reverse engineering tool"
)]
struct Args {
    #[clap(value_parser)]
    path: Option<String>,

    #[clap(long)]
    strings: bool,

    #[clap(long)]
    extract: bool,

    #[clap(long, value_parser)]
    output: Option<String>,

    #[clap(long)]
    json: bool,

    #[clap(value_enum, long, default_value = "all")]
    mode: DetectionMode,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum DetectionMode {
    Network,
    Crypto,
    Malicious,
    All,
}

struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    url_regex: Regex,
    crypto_regex: Regex,
    malicious_pattern_regex: Regex,
    options: ScannerOptions,
}

struct ScannerOptions {
    extract_strings: bool,
    extract_resources: bool,
    output_dir: PathBuf,
    export_json: bool,
    mode: DetectionMode,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        ScannerOptions {
            extract_strings: false,
            extract_resources: false,
            output_dir: PathBuf::from("./extracted"),
            export_json: false,
            mode: DetectionMode::All,
        }
    }
}

impl CollapseScanner {
    fn new(options: ScannerOptions) -> Result<Self, io::Error> {
        let good_links: HashSet<String> = GOOD_LINKS.iter().cloned().collect();

        if options.extract_resources {
            fs::create_dir_all(&options.output_dir)?;
        }

        Ok(CollapseScanner {
            good_links,
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            url_regex: Regex::new(r"(?i)\b(https?://|www\.)[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)").unwrap(),
            crypto_regex: Regex::new(r"(?i)(aes|des|rsa|md5|sha[0-9]|encrypt|decrypt|cipher|key(?:store|gen)|secret|password|hash|salt)").unwrap(),
            malicious_pattern_regex: Regex::new(r"(?i)(backdoor|exploit|inject|payload|shellcode|bypass|rootkit|keylog|steal)").unwrap(),
            options,
        })
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        let mut byte_counts = [0u32; 256];
        let len = data.len() as f64;

        for &byte in data {
            byte_counts[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        for &count in &byte_counts {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    fn scan_path(&self, path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        if path.is_dir() {
            self.scan_directory(path)
        } else if path.extension().map_or(false, |ext| ext == "jar") {
            self.scan_jar_file(path)
        } else if path.extension().map_or(false, |ext| ext == "class") {
            self.scan_class_file(path).map(|result| vec![result])
        } else {
            Err(ScanError::ParseError(format!(
                "Unsupported file type: {:?}",
                path.extension().unwrap_or_default()
            )))
        }
    }

    fn scan_directory(&self, dir_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let mut results = Vec::new();

        for entry in WalkDir::new(dir_path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let path = entry.path();
                if path
                    .extension()
                    .map_or(false, |ext| ext == "jar" || ext == "class")
                {
                    match self.scan_path(path) {
                        Ok(mut scan_results) => results.append(&mut scan_results),
                        Err(e) => eprintln!("Error scanning {}: {}", path.display(), e),
                    }
                }
            }
        }

        Ok(results)
    }

    fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let file = File::open(jar_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut results = Vec::new();

        let pb = ProgressBar::new(archive.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                .unwrap()
                .progress_chars("##-"),
        );
        pb.set_message(format!("Scanning {}", jar_path.display()));

        let mut resources = Vec::new();

        for i in 0..archive.len() {
            pb.inc(1);

            let mut file = archive.by_index(i)?;
            let file_path = file.name().to_string();

            let is_class = file_path.ends_with(".class");

            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;
            let entropy = Self::calculate_entropy(&file_data);

            resources.push(ResourceInfo {
                path: file_path.clone(),
                size: file_data.len() as u64,
                is_class_file: is_class,
                entropy,
            });

            if self.options.extract_resources {
                let outpath = self.options.output_dir.join(file_path.clone());
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                outfile.write_all(&file_data)?;
            }

            if is_class {
                let file_name = PathBuf::from(&file_path)
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();

                if let Some(mut scan_result) = self.scan_class_data(&file_data, &file_name)? {
                    scan_result.file_path = format!("{}", file_path);
                    results.push(scan_result);
                }
            }
        }

        pb.finish_with_message(format!("Completed scanning {}", jar_path.display()));

        if self.options.export_json {
            let resources_json_path = self.options.output_dir.join(format!(
                "{}_resources.json",
                jar_path.file_name().unwrap_or_default().to_string_lossy()
            ));
            if let Ok(json) = serde_json::to_string_pretty(&resources) {
                let mut json_file = File::create(resources_json_path)?;
                json_file.write_all(json.as_bytes())?;
            }
        }

        Ok(results)
    }

    fn scan_class_file(&self, file_path: &Path) -> Result<ScanResult, ScanError> {
        let mut file = File::open(file_path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let file_name = file_path.to_string_lossy().to_string();

        let result = self
            .scan_class_data(&data, &file_name)?
            .unwrap_or(ScanResult {
                file_path: file_name,
                matches: Vec::new(),
            });

        Ok(result)
    }

    fn scan_class_data(
        &self,
        data: &[u8],
        file_name: &str,
    ) -> Result<Option<ScanResult>, ScanError> {
        let mut matches = Vec::new();

        let strings = self.extract_strings_from_class(data)?;

        for string in &strings {
            if !string.is_empty() {
                if self.options.mode == DetectionMode::Network
                    || self.options.mode == DetectionMode::All
                {
                    if let Some(cap) = self.ip_regex.captures(string) {
                        let ip = cap.get(0).unwrap().as_str().to_string();
                        matches.push(("IP".to_string(), ip));
                    }

                    if let Some(cap) = self.url_regex.captures(string) {
                        let url = cap.get(0).unwrap().as_str().to_string();
                        let domain = self.extract_domain(&url);

                        if !domain.is_empty() && !self.is_good_link(&domain) {
                            matches.push(("URL".to_string(), url));
                        }
                    }
                }

                if self.options.mode == DetectionMode::Crypto
                    || self.options.mode == DetectionMode::All
                {
                    if let Some(cap) = self.crypto_regex.captures(string) {
                        let pattern = cap.get(0).unwrap().as_str().to_string();
                        matches.push(("CRYPTO".to_string(), format!("{}: {}", pattern, string)));
                    }
                }

                if self.options.mode == DetectionMode::Malicious
                    || self.options.mode == DetectionMode::All
                {
                    if let Some(cap) = self.malicious_pattern_regex.captures(string) {
                        let pattern = cap.get(0).unwrap().as_str().to_string();
                        matches
                            .push(("SUSPICIOUS".to_string(), format!("{}: {}", pattern, string)));
                    }
                }
            }
        }

        if self.options.extract_strings {
            let base_name = PathBuf::from(file_name)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let strings_path = self
                .options
                .output_dir
                .join(format!("{}_strings.txt", base_name));
            let mut strings_file = File::create(strings_path)?;

            for string in &strings {
                if !string.is_empty() {
                    writeln!(strings_file, "{}", string)?;
                }
            }
        }

        if !matches.is_empty() {
            Ok(Some(ScanResult {
                file_path: file_name.to_string(),
                matches,
            }))
        } else {
            Ok(None)
        }
    }

    fn extract_strings_from_class(&self, data: &[u8]) -> Result<Vec<String>, ScanError> {
        let mut strings = Vec::new();
        let mut cp_indexes = Vec::new();

        if data.len() < 10 {
            return Err(ScanError::ParseError("Class file too small".to_string()));
        }

        if &data[0..4] != &[0xCA, 0xFE, 0xBA, 0xBE] {
            return Err(ScanError::ParseError(
                "Invalid class file format".to_string(),
            ));
        }

        let mut cursor = io::Cursor::new(data);
        cursor.set_position(8);

        let cp_count = cursor
            .read_u16::<BigEndian>()
            .map_err(|_| ScanError::ParseError("Failed to read constant pool count".to_string()))?;

        let mut i = 1;
        while i < cp_count {
            let tag = cursor.read_u8().map_err(|_| {
                ScanError::ParseError("Failed to read constant pool tag".to_string())
            })?;

            match tag {
                1 => {
                    let length = cursor.read_u16::<BigEndian>().map_err(|_| {
                        ScanError::ParseError("Failed to read string length".to_string())
                    })?;
                    let mut string_data = vec![0u8; length as usize];
                    cursor.read_exact(&mut string_data).map_err(|_| {
                        ScanError::ParseError("Failed to read string data".to_string())
                    })?;

                    if let Ok(string) = String::from_utf8(string_data.clone()) {
                        strings.push(string);
                    } else {
                        let (cow, _, _) = UTF_8.decode(&string_data);
                        strings.push(cow.to_string());
                    }

                    i += 1;
                }
                3 | 4 => {
                    cursor.set_position(cursor.position() + 4);
                    i += 1;
                }
                5 | 6 => {
                    cursor.set_position(cursor.position() + 8);
                    i += 2;
                }
                7 | 8 => {
                    cp_indexes.push(cursor.read_u16::<BigEndian>().map_err(|_| {
                        ScanError::ParseError("Failed to read constant pool index".to_string())
                    })?);
                    i += 1;
                }
                9 | 10 | 11 | 12 => {
                    cursor.set_position(cursor.position() + 4);
                    i += 1;
                }
                15 => {
                    cursor.set_position(cursor.position() + 3);
                    i += 1;
                }
                16 => {
                    cursor.set_position(cursor.position() + 2);
                    i += 1;
                }
                17 | 18 => {
                    cursor.set_position(cursor.position() + 4);
                    i += 1;
                }
                19 | 20 => {
                    cursor.set_position(cursor.position() + 2);
                    i += 1;
                }
                _ => {
                    return Err(ScanError::ParseError(format!(
                        "Unknown constant pool tag: {}",
                        tag
                    )));
                }
            }
        }

        Ok(strings)
    }

    fn extract_domain(&self, url: &str) -> String {
        if let Ok(parsed_url) = Url::parse(url) {
            if let Some(host) = parsed_url.host_str() {
                return host.to_string();
            }
        }

        let url_lower = url.to_lowercase();
        if url_lower.starts_with("http://") || url_lower.starts_with("https://") {
            let without_protocol = url_lower.split("://").nth(1).unwrap_or("");
            let domain = without_protocol.split('/').next().unwrap_or("");
            return domain.to_string();
        } else if url_lower.starts_with("www.") {
            let domain = url_lower.split('/').next().unwrap_or("");
            return domain.to_string();
        }

        String::new()
    }

    fn is_good_link(&self, domain: &str) -> bool {
        for good_link in &self.good_links {
            if domain.contains(good_link) {
                return true;
            }
        }
        false
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
            .unwrap_or_else(|| PathBuf::from("./extracted")),
        export_json: args.json,
        mode: args.mode,
    };

    if options.extract_resources || options.extract_strings || options.export_json {
        fs::create_dir_all(&options.output_dir)?;
    }

    let scanner = CollapseScanner::new(options)?;
    let path = args.path.map(PathBuf::from).unwrap_or_else(|| {
        println!(
            "{}",
            "No path specified, scanning current directory.".yellow()
        );
        PathBuf::from(".")
    });

    println!(
        "{}",
        "==== CollapseScanner - Advanced JAR Reverse Engineering Tool ====".bright_cyan()
    );
    println!(
        "{}",
        "Scanning for suspicious and malicious patterns...".bright_green()
    );

    match scanner.scan_path(&path) {
        Ok(results) => {
            if results.is_empty() {
                println!("{}", "✅ No suspicious patterns found.".green());
            } else {
                println!("\n{}", "🔍 Found suspicious patterns:".bright_red());

                let mut total_matches = 0;
                for result in &results {
                    if !result.matches.is_empty() {
                        println!(
                            "\n{} {}",
                            "📄".bright_yellow(),
                            result.file_path.bright_cyan()
                        );

                        for (pattern_type, value) in &result.matches {
                            match pattern_type.as_str() {
                                "IP" => println!(
                                    "  {} {}: {}",
                                    "🌐".bright_red(),
                                    "IP Address".bright_red(),
                                    value.bright_white()
                                ),
                                "URL" => println!(
                                    "  {} {}: {}",
                                    "🔗".bright_red(),
                                    "URL".bright_red(),
                                    value.bright_white()
                                ),
                                "CRYPTO" => println!(
                                    "  {} {}: {}",
                                    "🔒".bright_yellow(),
                                    "Crypto".bright_yellow(),
                                    value.bright_white()
                                ),
                                "SUSPICIOUS" => println!(
                                    "  {} {}: {}",
                                    "⚠️".bright_red(),
                                    " Suspicious".bright_red(),
                                    value.bright_white()
                                ),
                                "OBFUSCATED" => println!(
                                    "  {} {}: {}",
                                    "🔍".bright_magenta(),
                                    "Obfuscated Code".bright_magenta(),
                                    value.bright_white()
                                ),
                                _ => println!(
                                    "  {}: {}",
                                    pattern_type.bright_yellow(),
                                    value.bright_white()
                                ),
                            }

                            total_matches += 1;
                        }
                    }
                }

                println!(
                    "\n{} {} {}",
                    "Total:".bright_cyan(),
                    total_matches.to_string().bright_white(),
                    "suspicious patterns".bright_cyan()
                );
            }

            if scanner.options.extract_resources {
                println!(
                    "\n{} {}",
                    "📦".bright_green(),
                    format!(
                        "Resources extracted to {}",
                        scanner.options.output_dir.display()
                    )
                    .bright_green()
                );
            }

            if scanner.options.extract_strings {
                println!(
                    "{} {}",
                    "🔤".bright_green(),
                    format!(
                        "Strings extracted to {}",
                        scanner.options.output_dir.display()
                    )
                    .bright_green()
                );
            }
        }
        Err(e) => {
            eprintln!("{} {}", "Error scanning:".bright_red(), e);
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )));
        }
    }

    Ok(())
}
