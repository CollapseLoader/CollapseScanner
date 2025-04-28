use crate::database::GOOD_LINKS;
use crate::detection::{
    cache_safe_string, calculate_detection_hash, contains_crypto_indicators,
    contains_malicious_indicators, contains_network_indicators, is_cached_safe_string,
    is_obfuscated_name, should_analyze_string, ENTROPY_THRESHOLD, MAX_PATTERN_CHECK_LENGTH,
    MIN_STRING_LENGTH, NAME_LENGTH_THRESHOLD, RESULT_CACHE_SIZE, SUSPICIOUS_CHAR_THRESHOLD,
};
use crate::errors::ScanError;
use crate::parser::parse_class_structure;
use crate::types::{
    ClassDetails, DetectionMode, FindingType, ResourceInfo, ScanResult, ScannerOptions,
};
use crate::utils::{calculate_entropy, extract_domain, get_simple_name, truncate_string};

use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::num::NonZero;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
const BUFFER_SIZE: usize = 512 * 1024;
use lru::LruCache;
use walkdir::WalkDir;
use wildmatch::WildMatch;
use zip::ZipArchive;

pub struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    ipv6_regex: Regex,
    url_regex: Regex,
    crypto_regex: Regex,
    malicious_pattern_regex: Regex,
    suspicious_consecutive_chars_regex: Regex,
    ignored_suspicious_keywords: HashSet<String>,
    ignored_crypto_keywords: HashSet<String>,
    pub options: ScannerOptions,
    pub found_custom_jvm_indicator: Arc<Mutex<bool>>,
    exclude_patterns: Vec<WildMatch>,
    find_patterns: Vec<WildMatch>,
    result_cache: Arc<Mutex<LruCache<u64, Vec<(FindingType, String)>>>>,
}

impl CollapseScanner {
    pub fn new(options: ScannerOptions) -> Result<Self, ScanError> {
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
            result_cache: Arc::new(Mutex::new(LruCache::new(NonZero::new(RESULT_CACHE_SIZE).unwrap()))),
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

    pub fn scan_path(&self, path: &Path) -> Result<Vec<ScanResult>, ScanError> {
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

        let progress_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("=> ");

        let progress = ProgressBar::new(scannable_files.len() as u64);
        progress.set_style(progress_style);
        progress.set_message("Processing files...");

        let scan_results: Vec<_> = scannable_files
            .iter()
            .map(|path| {
                let result = if self.options.verbose {
                    progress.set_message(format!("Scanning: {}", path.display()));
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
        let mut skipped_count = 0;

        if self.options.verbose {
            println!(
                "{} Filtering and reading entries from {}",
                "🔎".blue(),
                jar_path.display()
            );
        }

        let mut entries_to_scan = Vec::with_capacity(total_files / 2);
        let mut all_resource_info = if self.options.export_json {
            Vec::with_capacity(total_files)
        } else {
            Vec::new()
        };

        let mut reusable_buffer = Vec::with_capacity(BUFFER_SIZE);

        let pb_template = if self.options.verbose {
            format!("{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Reading: {{msg}}", "🔍".green())
        } else {
            format!(
                "{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Reading {}",
                "🔍".green(),
                jar_path.file_name().unwrap_or_default().to_string_lossy()
            )
        };

        let pb_read = ProgressBar::new(total_files as u64);
        pb_read.set_style(
            ProgressStyle::default_bar()
                .template(&pb_template)?
                .progress_chars("=> "),
        );

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

            pb_read.inc(1);

            let original_entry_name = match file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => String::from_utf8_lossy(file.name_raw()).replace('\\', "/"),
            };

            if self.options.verbose {
                pb_read.set_message(original_entry_name.clone());
            }

            if !self.should_scan(&original_entry_name) {
                skipped_count += 1;
                continue;
            }

            let file_size = file.size() as usize;

            reusable_buffer.clear();

            if reusable_buffer.capacity() < file_size {
                reusable_buffer.reserve(file_size - reusable_buffer.capacity());
            }

            if let Err(e) = file.read_to_end(&mut reusable_buffer) {
                eprintln!(
                    "{} Error reading content of {}: {}",
                    "⚠️".yellow(),
                    original_entry_name,
                    e
                );
                continue;
            }

            if self.options.extract_resources {
                if let Err(e) = self.extract_resource(&original_entry_name, &reusable_buffer) {
                    eprintln!(
                        "{} Error during extraction of {}: {}",
                        "⚠️".yellow(),
                        original_entry_name,
                        e
                    );
                }
            }

            match self.analyze_resource(&original_entry_name, &reusable_buffer) {
                Ok(resource_info) => {
                    if self.options.export_json {
                        all_resource_info.push(resource_info.clone());
                    }

                    if resource_info.is_class_file || resource_info.is_dead_class_candidate {
                        let data_to_scan = reusable_buffer.clone();
                        entries_to_scan.push((original_entry_name, data_to_scan, resource_info));
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
        pb_read.finish_with_message(format!("Finished reading {} entries", total_files));

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

        let pb_template_analyze = if self.options.verbose {
            format!("{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Analyzing: {{msg}}", "🔬".green())
        } else {
            format!(
                "{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} Analyzing {}",
                "🔬".green(),
                jar_path.file_name().unwrap_or_default().to_string_lossy()
            )
        };

        let entries_count = entries_to_scan.len();
        let pb_analyze = ProgressBar::new(entries_count as u64);
        pb_analyze.set_style(
            ProgressStyle::default_bar()
                .template(&pb_template_analyze)?
                .progress_chars("=> "),
        );

        let results: Vec<ScanResult> = entries_to_scan
            .into_iter()
            .filter_map(|(original_path, file_data, resource_info)| {
                if self.options.verbose {
                    pb_analyze.set_message(original_path.clone());
                }
                let result = self.scan_class_data(&file_data, &original_path, Some(resource_info));

                pb_analyze.inc(1);

                match result {
                    Ok(Some(scan_result)) => Some(scan_result),
                    Ok(None) => None,
                    Err(e) => {
                        eprintln!(
                            "{} Error processing class {}: {}",
                            "⚠️".yellow(),
                            original_path,
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        pb_analyze.finish_with_message(format!("Finished analyzing {} classes", entries_count));

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

        Ok(results)
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
            entropy: calculate_entropy(data),
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
        let data_hash = calculate_detection_hash(data);

        if let Some(cached_findings) = self.get_cached_findings(data_hash) {
            if !cached_findings.is_empty() || self.options.verbose || self.options.export_json {
                return Ok(Some(ScanResult {
                    file_path: original_path_str.to_string(),
                    matches: cached_findings,
                    class_details: None,
                    resource_info,
                }));
            } else {
                return Ok(None);
            }
        }

        let mut findings = Vec::new();

        if data.len() >= 2 && data[0] != 0xCA && data[1] != 0xFE {
            {
                let mut found_flag = self.found_custom_jvm_indicator.lock().unwrap();
                *found_flag = true;
            }

            if let Some(ref ri) = resource_info {
                self.check_high_entropy(ri, &mut findings);
            }

            self.cache_findings(data_hash, &findings);

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

        let class_details =
            match parse_class_structure(data, original_path_str, self.options.verbose) {
                Ok(details) => details,
                Err(e) => return Err(e),
            };

        if let Some(ref ri) = resource_info {
            self.check_high_entropy(ri, &mut findings);
        } else {
            let entropy = calculate_entropy(data);
            let fallback_ri = ResourceInfo {
                path: original_path_str.to_string(),
                size: data.len() as u64,
                is_class_file: true,
                entropy,
                is_dead_class_candidate: false,
            };
            self.check_high_entropy(&fallback_ri, &mut findings);
        }

        if self.options.mode == DetectionMode::Obfuscation
            || self.options.mode == DetectionMode::All
        {
            self.check_name_obfuscation(&class_details, &mut findings);
        }

        for string in &class_details.strings {
            if string.is_empty() || is_cached_safe_string(string) {
                continue;
            }

            if should_analyze_string(string) {
                let findings_before = findings.len();

                match self.options.mode {
                    DetectionMode::All => {
                        if contains_network_indicators(string) {
                            self.check_network_patterns(string, &mut findings);
                        }
                        if contains_crypto_indicators(string) {
                            self.check_crypto_patterns(string, &mut findings);
                        }
                        if contains_malicious_indicators(string) {
                            self.check_malicious_patterns(string, &mut findings);
                        }
                    }
                    DetectionMode::Network => {
                        if contains_network_indicators(string) {
                            self.check_network_patterns(string, &mut findings);
                        }
                    }
                    DetectionMode::Crypto => {
                        if contains_crypto_indicators(string) {
                            self.check_crypto_patterns(string, &mut findings);
                        }
                    }
                    DetectionMode::Malicious => {
                        if contains_malicious_indicators(string) {
                            self.check_malicious_patterns(string, &mut findings);
                        }
                    }
                    _ => {}
                }

                if findings_before == findings.len() {
                    cache_safe_string(string);
                }
            }
        }

        self.cache_findings(data_hash, &findings);

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

    fn check_network_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if string.len() < MIN_STRING_LENGTH {
            return;
        }

        let check_string = if string.len() > MAX_PATTERN_CHECK_LENGTH {
            &string[0..MAX_PATTERN_CHECK_LENGTH]
        } else {
            string
        };

        if let Some(cap) = self.ip_regex.captures(check_string) {
            findings.push((
                FindingType::IpAddress,
                cap.get(0).unwrap().as_str().to_string(),
            ));
        }

        if let Some(cap) = self.ipv6_regex.captures(check_string) {
            findings.push((
                FindingType::IpV6Address,
                cap.get(0).unwrap().as_str().to_string(),
            ));
        }

        if let Some(cap) = self.url_regex.captures(check_string) {
            let url = cap.get(0).unwrap().as_str().to_string();
            let domain = extract_domain(&url);
            if !domain.is_empty() && !self.is_good_link(&domain) {
                findings.push((FindingType::Url, url));
            }
        }
    }

    fn check_crypto_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if string.len() < MIN_STRING_LENGTH {
            return;
        }

        let check_string = if string.len() > MAX_PATTERN_CHECK_LENGTH {
            &string[0..MAX_PATTERN_CHECK_LENGTH]
        } else {
            string
        };

        if let Some(cap) = self.crypto_regex.captures(check_string) {
            let keyword = cap.get(0).unwrap().as_str();
            let keyword_lower = keyword.to_lowercase();
            if !self.ignored_crypto_keywords.contains(&keyword_lower) {
                findings.push((
                    FindingType::Crypto,
                    format!("'{}' in \"{}\"", keyword, truncate_string(string, 80)),
                ));
            }
        }
    }

    fn check_malicious_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if string.len() < MIN_STRING_LENGTH {
            return;
        }

        let check_string = if string.len() > MAX_PATTERN_CHECK_LENGTH {
            &string[0..MAX_PATTERN_CHECK_LENGTH]
        } else {
            string
        };

        if let Some(cap) = self.malicious_pattern_regex.captures(check_string) {
            let keyword = cap.get(0).unwrap().as_str();
            let keyword_lower = keyword.to_lowercase();
            if !self.ignored_suspicious_keywords.contains(&keyword_lower) {
                findings.push((
                    FindingType::SuspiciousKeyword,
                    format!("'{}' in \"{}\"", keyword, truncate_string(string, 80)),
                ));
            }
        }
    }

    fn check_name_obfuscation(
        &self,
        details: &ClassDetails,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let mut check = |name: &str, context: &str| {
            if name.is_empty() || name == "java/lang/Object" {
                return;
            }

            if is_obfuscated_name(name) {
                findings.push((
                    FindingType::ObfuscationChars,
                    format!("{} '{}'", context, name),
                ));
                return;
            }

            let name_char_count = name.chars().count();

            if name.contains('/')
                && context.ends_with(" Name")
                && !context.starts_with("Class")
                && !context.starts_with("Superclass")
                && !context.starts_with("Interface")
            {
                let simple_name = get_simple_name(name);
                if simple_name.contains('/') && simple_name == name {
                    if self.options.verbose {
                        println!("      Suspicious name contains '/': {} - {}", context, name);
                    }
                }
            } else if name_char_count > NAME_LENGTH_THRESHOLD {
                findings.push((
                    FindingType::ObfuscationLongName,
                    format!("{} '{}' (len {})", context, name, name_char_count),
                ));
            }

            let simple_name_to_check = get_simple_name(name);
            if self
                .suspicious_consecutive_chars_regex
                .is_match(simple_name_to_check)
            {
                findings.push((
                    FindingType::ObfuscationChars,
                    format!(
                        "Consecutive Symbols: {} '{}'",
                        context,
                        truncate_string(name, 20)
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
                        truncate_string(name, 20),
                        non_ascii_count
                    ),
                ));
            }
        };

        check(&details.class_name, "Class Name");
        if !details.superclass_name.is_empty() {
            check(&details.superclass_name, "Superclass Name");
        }

        for i in details.interfaces.iter().take(5) {
            check(i, "Interface Name");
        }

        let fields_sample_size = (details.fields.len() / 10).max(5).min(details.fields.len());
        for f in details.fields.iter().take(fields_sample_size) {
            check(&f.name, "Field Name");
        }

        let methods_sample_size = (details.methods.len() / 10)
            .max(5)
            .min(details.methods.len());
        for m in details
            .methods
            .iter()
            .filter(|m| m.name != "<init>" && m.name != "<clinit>")
            .take(methods_sample_size)
        {
            check(&m.name, "Method Name");
        }
    }

    fn is_good_link(&self, domain: &str) -> bool {
        let lower_domain = domain.to_lowercase();

        if self.good_links.contains(&lower_domain) {
            return true;
        }

        self.good_links
            .iter()
            .any(|good| lower_domain.ends_with(&format!(".{}", good)))
    }

    fn get_cached_findings(&self, hash: u64) -> Option<Vec<(FindingType, String)>> {
        if let Ok(mut cache) = self.result_cache.lock() {
            return cache.get(&hash).cloned();
        }
        None
    }

    fn cache_findings(&self, hash: u64, findings: &[(FindingType, String)]) {
        if let Ok(mut cache) = self.result_cache.lock() {
            cache.put(hash, findings.to_vec());
        }
    }

    fn check_high_entropy(
        &self,
        resource_info: &ResourceInfo,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if resource_info.entropy > ENTROPY_THRESHOLD {
            findings.push((
                FindingType::HighEntropy,
                format!(
                    "High entropy value: {:.2} (threshold: {:.2})",
                    resource_info.entropy, ENTROPY_THRESHOLD
                ),
            ));
        }
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
        } else if !self.options.output_dir.exists() {
            fs::create_dir_all(&self.options.output_dir)?;
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
}
