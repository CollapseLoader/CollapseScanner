use crate::config::SYSTEM_CONFIG;
use crate::database::GOOD_LINKS;
use crate::detection::{
    cache_safe_string, calculate_detection_hash, is_cached_safe_string, ENTROPY_THRESHOLD,
    NAME_LENGTH_THRESHOLD, SUSPICIOUS_DOMAINS,
};
use crate::errors::ScanError;
use crate::parser::parse_class_structure;
use crate::types::{
    ClassDetails, DetectionMode, FindingType, ResourceInfo, ScanResult, ScannerOptions,
};
use crate::utils::{calculate_entropy, extract_domain, get_simple_name, truncate_string};

use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use lru::LruCache;
use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use walkdir::WalkDir;
use wildmatch::WildMatch;
use zip::ZipArchive;

pub struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    ipv6_regex: Regex,
    url_regex: Regex,
    suspicious_domains: HashSet<String>,
    crypto_regex: Regex,
    malicious_pattern_regex: Regex,
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

        if let Some(ref path) = options.ignore_keywords_file {
            if options.verbose {
                println!(
                    "{} Loading keywords ignore list from: {}",
                    "📄".yellow(),
                    path.display()
                );
            }
            match Self::load_ignore_list_from_file(path) {
                Ok(ignored) => {
                    ignored_suspicious_keywords.extend(ignored.clone());
                    ignored_crypto_keywords.extend(ignored);
                }
                Err(e) => {
                    eprintln!(
                        "{} Warning: Could not load keywords ignore list from {}: {}",
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

        let cache_size = NonZeroUsize::new(SYSTEM_CONFIG.result_cache_size)
            .unwrap_or_else(|| NonZeroUsize::new(1).unwrap());

        if options.verbose {
            SYSTEM_CONFIG.log_config();
        }

        Ok(CollapseScanner {
            good_links,
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            ipv6_regex: Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap(),
            url_regex: Regex::new(r#"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»""'']))"#).unwrap(),
            suspicious_domains: SUSPICIOUS_DOMAINS.clone(),
            crypto_regex: Regex::new(r"(?i)\b(aes|des|rsa|md5|sha[1-9]*-?\d*|blowfish|twofish|pgp|gpg|cipher|keystore|keygenerator|secretkey|password|encrypt|decrypt|hash|salt|ivParameterSpec|SecureRandom)\b").unwrap(),
            malicious_pattern_regex: Regex::new(r"(?i)\b(backdoor|exploit|payload|shellcode|bypass|rootkit|keylog|rat\b|trojan|malware|spyware|meterpreter|cobaltstrike|powershell|cmd\.exe|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|loadLibrary|download|upload|socket\(|bind\(|connect\(|URL\(|URLConnection|Class\.forName|defineClass|getMethod|unsafe|jndi|ldap|rmi|base64|decode)\b").unwrap(),
            ignored_suspicious_keywords,
            ignored_crypto_keywords,
            options,
            found_custom_jvm_indicator: Arc::new(Mutex::new(false)),
            exclude_patterns,
            find_patterns,
            result_cache: Arc::new(Mutex::new(LruCache::new(cache_size))),
        })
    }

    fn should_scan(&self, internal_path: &str) -> bool {
        if self
            .exclude_patterns
            .iter()
            .any(|pattern| pattern.matches(internal_path))
        {
            if self.options.verbose {
                println!(
                    "{} Skipping excluded file: {}",
                    "🚫".dimmed(),
                    internal_path
                );
            }
            return false;
        }

        if !self.find_patterns.is_empty() {
            let matches = self
                .find_patterns
                .iter()
                .any(|pattern| pattern.matches(internal_path));

            if !matches {
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
        let mut total_files_walked = 0;

        for entry in WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            total_files_walked += 1;
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
                println!(
                    "{} Total files walked: {} | Scannable files: 0",
                    "📊".dimmed(),
                    total_files_walked
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
            println!(
                "{} Total files walked: {} | Filtered to: {}",
                "📊".dimmed(),
                total_files_walked,
                scannable_files.len()
            );
        }

        let progress_style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({percent:>3}%) {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  ");

        let progress = ProgressBar::new(scannable_files.len() as u64);
        progress.set_style(progress_style);
        progress.set_message("Analyzing files...");

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

        let mut error_count = 0;
        let mut success_count = 0;
        for result in scan_results {
            match result {
                Ok(mut scan_results) => {
                    success_count += 1;
                    results.append(&mut scan_results);
                }
                Err(e) => {
                    error_count += 1;
                    eprintln!("{} Error scanning file: {}", "⚠️".yellow(), e);
                }
            }
        }

        if self.options.verbose && error_count > 0 {
            println!(
                "{} Scan summary: {} successful, {} errors",
                "📊".dimmed(),
                success_count,
                error_count
            );
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
        let mut results = Vec::new();
        let mut all_resource_info = if self.options.export_json {
            Vec::with_capacity(total_files)
        } else {
            Vec::new()
        };

        if self.options.verbose {
            println!("{} Scanning JAR file: {}", "🔎".blue(), jar_path.display());
        }

        let buffer_size = SYSTEM_CONFIG.buffer_size;
        let mut reusable_buffer = Vec::with_capacity(buffer_size);

        let pb_template = format!("{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} ({{percent:>3}}%) Processing: {{msg}}", "🔍".green());

        let progress_bar = ProgressBar::new(total_files as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template(&pb_template)?
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        for i in 0..total_files {
            let mut file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "{} Error accessing entry {} in {}: {}",
                        "⚠️ ".yellow(),
                        i,
                        jar_path.display(),
                        e
                    );
                    progress_bar.inc(1);
                    continue;
                }
            };

            let original_entry_name = match file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => String::from_utf8_lossy(file.name_raw()).replace('\\', "/"),
            };

            progress_bar.set_message(original_entry_name.clone());

            if !self.should_scan(&original_entry_name) {
                skipped_count += 1;
                progress_bar.inc(1);
                continue;
            }

            reusable_buffer.clear();
            let file_size = file.size() as usize;

            if reusable_buffer.capacity() < file_size {
                reusable_buffer.reserve(file_size - reusable_buffer.capacity());
            }

            if let Err(e) = file.read_to_end(&mut reusable_buffer) {
                eprintln!(
                    "{} Error reading content of {}: {}",
                    "⚠️ ".yellow(),
                    original_entry_name,
                    e
                );
                progress_bar.inc(1);
                continue;
            }

            if self.options.extract_resources {
                if let Err(e) = self.extract_resource(&original_entry_name, &reusable_buffer) {
                    eprintln!(
                        "{} Error during extraction of {}: {}",
                        "⚠️ ".yellow(),
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
                        match self.scan_class_data(
                            &reusable_buffer,
                            &original_entry_name,
                            Some(resource_info.clone()),
                        ) {
                            Ok(Some(scan_result)) => {
                                results.push(scan_result);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                eprintln!("{} Error processing class: {}", "⚠️ ".yellow(), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Error analyzing resource {}: {}",
                        "⚠️ ".yellow(),
                        original_entry_name,
                        e
                    );
                }
            }

            progress_bar.inc(1);
        }

        progress_bar.finish_with_message(format!(
            "Finished processing {} files ({} skipped, {} analyzed)",
            total_files,
            skipped_count,
            total_files - skipped_count
        ));

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
            is_class_name_candidate && data.len() >= 2 && &data[0..2] != b"\xCA\xFE";

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

        // scan_class_data now returns results with danger_score already calculated
        let result = self
            .scan_class_data(&data, &res_info.path, Some(res_info.clone()))?
            .unwrap_or_else(|| ScanResult {
                file_path: res_info.path.clone(),
                matches: Vec::new(),
                class_details: None,
                resource_info: Some(res_info.clone()),
                danger_score: 1,
                danger_explanation: vec!["No suspicious elements detected.".to_string()],
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
                let danger_score =
                    self.calculate_danger_score(&cached_findings, resource_info.as_ref());
                let danger_explanation = self.generate_danger_explanation(
                    danger_score,
                    &cached_findings,
                    resource_info.as_ref(),
                );

                return Ok(Some(ScanResult {
                    file_path: original_path_str.to_string(),
                    matches: cached_findings,
                    class_details: None,
                    resource_info,
                    danger_score,
                    danger_explanation,
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
                let danger_score = self.calculate_danger_score(&findings, resource_info.as_ref());
                let danger_explanation = self.generate_danger_explanation(
                    danger_score,
                    &findings,
                    resource_info.as_ref(),
                );

                return Ok(Some(ScanResult {
                    file_path: original_path_str.to_string(),
                    matches: findings,
                    class_details: None,
                    resource_info,
                    danger_score,
                    danger_explanation,
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

        let strings_to_scan: Vec<&String> = class_details
            .strings
            .iter()
            .filter(|s| !s.is_empty() && s.len() >= 3 && !is_cached_safe_string(s))
            .collect();

        if self.options.verbose && !strings_to_scan.is_empty() {
            println!(
                "      {} Analyzing {} strings in class",
                "🔤".dimmed(),
                strings_to_scan.len()
            );
        }

        match self.options.mode {
            DetectionMode::All => {
                for string in &strings_to_scan {
                    let findings_before = findings.len();

                    self.check_network_patterns(string, &mut findings);

                    if findings_before == findings.len() {
                        self.check_crypto_patterns(string, &mut findings);
                    }
                    if findings_before == findings.len() {
                        self.check_malicious_patterns(string, &mut findings);
                    }
                    if findings_before == findings.len() {
                        self.check_suspicious_url_patterns(string, &mut findings);
                    }

                    if findings_before == findings.len() {
                        cache_safe_string(string);
                    }
                }
            }
            DetectionMode::Network => {
                for string in &strings_to_scan {
                    let findings_before = findings.len();
                    self.check_network_patterns(string, &mut findings);
                    if findings_before == findings.len() {
                        self.check_suspicious_url_patterns(string, &mut findings);
                    }
                    if findings_before == findings.len() {
                        cache_safe_string(string);
                    }
                }
            }
            DetectionMode::Crypto => {
                for string in &strings_to_scan {
                    let findings_before = findings.len();
                    self.check_crypto_patterns(string, &mut findings);
                    if findings_before == findings.len() {
                        cache_safe_string(string);
                    }
                }
            }
            DetectionMode::Malicious => {
                for string in &strings_to_scan {
                    let findings_before = findings.len();
                    self.check_malicious_patterns(string, &mut findings);
                    if findings_before == findings.len() {
                        cache_safe_string(string);
                    }
                }
            }
            _ => {}
        }

        self.cache_findings(data_hash, &findings);

        if self.options.extract_strings && !class_details.strings.is_empty() {
            if self.options.verbose {
                println!(
                    "      {} Extracting {} strings to file",
                    "💾".dimmed(),
                    class_details.strings.len()
                );
            }
            self.write_strings_to_file(original_path_str, &class_details.strings)?;
        }

        if !findings.is_empty() || self.options.verbose || self.options.export_json {
            let danger_score = self.calculate_danger_score(&findings, resource_info.as_ref());
            let danger_explanation =
                self.generate_danger_explanation(danger_score, &findings, resource_info.as_ref());

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: findings,
                class_details: Some(class_details),
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }

    fn check_network_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if let Some(cap) = self.ip_regex.captures(string) {
            findings.push((
                FindingType::IpAddress,
                cap.get(0).unwrap().as_str().to_string(),
            ));
            return;
        }

        if let Some(cap) = self.ipv6_regex.captures(string) {
            findings.push((
                FindingType::IpV6Address,
                cap.get(0).unwrap().as_str().to_string(),
            ));
            return;
        }

        if let Some(cap) = self.url_regex.captures(string) {
            let url_match = cap.get(0).unwrap().as_str();
            let domain = extract_domain(url_match);

            if !domain.is_empty()
                && !self.is_good_link(&domain)
                && !self.is_suspicious_domain(&domain)
            {
                findings.push((FindingType::Url, url_match.to_string()));
            }
        }
    }

    fn check_suspicious_url_patterns(
        &self,
        string: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        for cap in self.url_regex.captures_iter(string) {
            if let Some(url_match) = cap.get(0) {
                let url_str = url_match.as_str();
                let domain = extract_domain(url_str);

                if !domain.is_empty() && self.is_suspicious_domain(&domain) {
                    findings.push((
                        FindingType::SuspiciousUrl,
                        format!("Suspicious URL: {}", url_str),
                    ));
                }
            }
        }
    }

    fn is_suspicious_domain(&self, domain: &str) -> bool {
        let lower_domain = domain.to_lowercase();

        if self.suspicious_domains.contains(&lower_domain) {
            return true;
        }

        for suspicious in &self.suspicious_domains {
            if lower_domain == *suspicious || lower_domain.ends_with(&format!(".{}", suspicious)) {
                return true;
            }
        }

        false
    }

    fn check_crypto_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if let Some(cap) = self.crypto_regex.captures(string) {
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
        if let Some(cap) = self.malicious_pattern_regex.captures(string) {
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

        let parts: Vec<&str> = lower_domain.split('.').collect();
        for i in 1..parts.len() {
            let parent_domain = parts[i..].join(".");
            if self.good_links.contains(&parent_domain) {
                return true;
            }
        }

        false
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
            let entropy_level = if resource_info.entropy > ENTROPY_THRESHOLD + 1.0 {
                "Very High"
            } else if resource_info.entropy > ENTROPY_THRESHOLD + 0.5 {
                "High"
            } else {
                "Moderate"
            };

            findings.push((
                FindingType::HighEntropy,
                format!(
                    "{} entropy value: {:.2} (threshold: {:.2}) - suggests possible encryption or compression",
                    entropy_level,
                    resource_info.entropy,
                    ENTROPY_THRESHOLD
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

    fn calculate_danger_score(
        &self,
        findings: &[(FindingType, String)],
        resource_info: Option<&ResourceInfo>,
    ) -> u8 {
        if findings.is_empty() {
            return 1;
        }

        let mut score = 0;

        let mut type_counts: HashMap<FindingType, usize> = HashMap::new();
        for (finding_type, _) in findings {
            *type_counts.entry(finding_type.clone()).or_insert(0) += 1;
        }

        let suspicious_url_count = type_counts.get(&FindingType::SuspiciousUrl).unwrap_or(&0);
        let ip_address_count = type_counts.get(&FindingType::IpAddress).unwrap_or(&0)
            + type_counts.get(&FindingType::IpV6Address).unwrap_or(&0);
        let url_count = type_counts.get(&FindingType::Url).unwrap_or(&0);
        let crypto_count = type_counts.get(&FindingType::Crypto).unwrap_or(&0);
        let suspicious_keyword_count = type_counts
            .get(&FindingType::SuspiciousKeyword)
            .unwrap_or(&0);
        let obfuscation_count = type_counts
            .get(&FindingType::ObfuscationLongName)
            .unwrap_or(&0)
            + type_counts
                .get(&FindingType::ObfuscationUnicode)
                .unwrap_or(&0);
        let high_entropy_count = type_counts.get(&FindingType::HighEntropy).unwrap_or(&0);

        score += (suspicious_url_count * 5).min(8);
        score += (ip_address_count * 2).min(4);
        score += (*url_count).min(3);
        score += (suspicious_keyword_count * 2).min(6);
        score += (*crypto_count).min(2);
        score += obfuscation_count.min(4);
        score += (high_entropy_count * 2).min(3);

        if let Some(ri) = resource_info {
            if ri.is_dead_class_candidate {
                score += 3;
            }

            if ri.entropy > ENTROPY_THRESHOLD + 0.5 {
                score += 2;
            } else if ri.entropy > ENTROPY_THRESHOLD + 0.3 {
                score += 1;
            }
        }

        if *suspicious_url_count > 0 && (*suspicious_keyword_count > 0 || ip_address_count > 0) {
            score += 2;
        }

        if type_counts.len() >= 3 {
            score += 1;
        }

        score.min(10).max(1) as u8
    }

    fn generate_danger_explanation(
        &self,
        score: u8,
        findings: &[(FindingType, String)],
        resource_info: Option<&ResourceInfo>,
    ) -> Vec<String> {
        if findings.is_empty() {
            return vec!["No suspicious elements detected.".to_string()];
        }

        let mut explanations = Vec::new();

        if score >= 8 {
            explanations.push(
                "⚠️ HIGH RISK: This file contains multiple high-risk indicators!".to_string(),
            );
        } else if score >= 5 {
            explanations.push(
                "⚠️ MODERATE RISK: This file contains several suspicious elements.".to_string(),
            );
        } else if score >= 3 {
            explanations.push(
                "⚠️ LOW RISK: This file contains some potentially concerning elements.".to_string(),
            );
        } else {
            explanations
                .push("✅ MINIMAL RISK: Few or no concerning elements detected.".to_string());
        }

        let mut by_type: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (finding_type, value) in findings {
            by_type
                .entry(finding_type.clone())
                .or_default()
                .push(value.clone());
        }

        if let Some(urls) = by_type.get(&FindingType::SuspiciousUrl) {
            if !urls.is_empty() {
                explanations.push(format!(
                    "Found {} suspicious URL(s) including Discord webhooks that may be used for data exfiltration.",
                    urls.len()
                ));
            }
        }

        if let Some(ips) = by_type.get(&FindingType::IpAddress) {
            if !ips.is_empty() {
                let sample = ips[0].clone();
                explanations.push(format!(
                    "Contains {} hardcoded IP address(es) such as {} that may indicate communication with malicious servers.",
                    ips.len(), sample
                ));
            }
        }

        if let Some(urls) = by_type.get(&FindingType::Url) {
            if !urls.is_empty() {
                let domains: Vec<String> = urls
                    .iter()
                    .map(|url| extract_domain(url))
                    .filter(|domain| !domain.is_empty() && !self.is_good_link(domain))
                    .collect();

                if !domains.is_empty() {
                    let unique_domains: HashSet<String> = domains.into_iter().collect();
                    let domain_list = unique_domains
                        .into_iter()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(", ");

                    explanations.push(format!(
                        "Contains connections to {} potentially suspicious domain(s) including: {}{}",
                        urls.len(),
                        domain_list,
                        if urls.len() > 3 { " and others..." } else { "" }
                    ));
                }
            }
        }

        if let Some(keywords) = by_type.get(&FindingType::SuspiciousKeyword) {
            if !keywords.is_empty() {
                explanations.push(format!(
                    "Contains {} suspicious code pattern(s) that may indicate malicious behavior.",
                    keywords.len()
                ));
            }
        }

        if let Some(high_entropy) = by_type.get(&FindingType::HighEntropy) {
            if !high_entropy.is_empty() && resource_info.is_some() {
                let ri = resource_info.unwrap();
                let entropy_desc = if ri.entropy > ENTROPY_THRESHOLD + 1.0 {
                    "Very high entropy"
                } else if ri.entropy > ENTROPY_THRESHOLD + 0.5 {
                    "High entropy"
                } else {
                    "Moderately high entropy"
                };
                explanations.push(format!(
                    "{} value ({:.2}) suggesting possible encryption, compression, or obfuscated code.",
                    entropy_desc,
                    ri.entropy
                ));
            }
        }

        if resource_info.map_or(false, |ri| ri.is_dead_class_candidate) {
            explanations.push(
                "Contains custom JVM bytecode (0xDEAD) which may indicate use of a custom classloader to evade detection.".to_string()
            );
        }

        explanations
    }
}
