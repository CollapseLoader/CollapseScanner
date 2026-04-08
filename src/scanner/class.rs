use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::detection::{cache_safe_string, calculate_detection_hash, is_cached_safe_string};
use crate::errors::ScanError;
use crate::filters::{
    is_known_good_ip, is_public_routable_ip, IPV6_REGEX, IP_REGEX, MALICIOUS_PATTERN_REGEX,
    URL_REGEX,
};
use crate::parser::parse_class_structure;
use crate::scanner::scan::CollapseScanner;
use crate::types::{ClassDetails, DetectionMode, FindingType, ResourceInfo, ScanResult};
use crate::utils::{extract_domain, get_simple_name, truncate_string};

const MIN_BASE64_BLOB_LEN: usize = 96;
const MIN_HEX_BLOB_LEN: usize = 128;
const BASE64_ENTROPY_THRESHOLD: f64 = 4.6;
const HEX_ENTROPY_THRESHOLD: f64 = 3.2;

const PROCESS_EXECUTION_MARKERS: &[&str] = &[
    "java/lang/Runtime",
    "Runtime",
    "getRuntime",
    "exec",
    "ProcessBuilder",
    "java/lang/ProcessBuilder",
];

const REFLECTION_MARKERS: &[&str] = &[
    "java/lang/reflect/Method",
    "java/lang/reflect/Field",
    "java/lang/reflect/Constructor",
    "setAccessible",
    "invoke",
];

const DYNAMIC_LOADING_MARKERS: &[&str] = &[
    "defineClass",
    "URLClassLoader",
    "MethodHandles$Lookup",
    "Lookup.defineClass",
];

const SCRIPT_ENGINE_MARKERS: &[&str] =
    &["javax/script/ScriptEngineManager", "javax/script/ScriptEngine"];

const JAVA_AGENT_MARKERS: &[&str] = &[
    "java/lang/instrument/Instrumentation",
    "Premain-Class",
    "Agent-Class",
    "Launcher-Agent-Class",
];

const ATTACH_API_MARKERS: &[&str] = &[
    "com/sun/tools/attach/VirtualMachine",
    "sun/tools/attach/HotSpotVirtualMachine",
];

const NATIVE_BRIDGE_MARKERS: &[&str] = &["com/sun/jna/Native", "com/sun/jna/Library", "sun/misc/Unsafe"];

impl CollapseScanner {
    const MAX_SCAN_STRING_LEN: usize = 2048;
    pub(crate) fn scan_class_file_data(
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
            .unwrap_or_else(|| ScanResult {
                file_path: res_info.path.clone(),
                matches: Arc::new(Vec::new()),
                class_details: None,
                resource_info: Some(res_info.clone()),
                danger_score: 1,
                danger_explanation: vec!["No suspicious elements detected.".to_string()],
            });

        Ok(result)
    }

    pub fn scan_class_data(
        &self,
        data: &[u8],
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let data_hash = calculate_detection_hash(data);

        if let Some(cached_findings) = self.get_cached_findings(data_hash) {
            return self.handle_cached_findings(
                cached_findings.clone(),
                original_path_str,
                resource_info,
            );
        }

        let mut findings = Vec::new();

        let looks_like_class_path = original_path_str.ends_with(".class")
            || original_path_str.ends_with(".class/");
        let has_valid_class_magic = data.starts_with(b"\xCA\xFE\xBA\xBE");

        if looks_like_class_path && !has_valid_class_magic {
            return self.handle_non_standard_class(
                data,
                data_hash,
                original_path_str,
                resource_info,
                &mut findings,
            );
        }

        let class_details = parse_class_structure(data, original_path_str, self.options.verbose)?;

        self.analyze_class_details(&class_details, &mut findings);

        let strings_to_scan = self.prepare_strings_for_scanning(&class_details);

        self.scan_strings_by_mode(&strings_to_scan, &mut findings);
        self.normalize_findings(&mut findings);

        let _cached_arc = self
            .result_cache
            .get_with(data_hash, || Arc::new(findings.clone()));

        self.create_scan_result(findings, class_details, original_path_str, resource_info)
    }

    fn check_network_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if let Some(ip_match) = IP_REGEX.find(string) {
            let ip_str = ip_match.as_str().to_owned();
            if !is_public_routable_ip(&ip_str) {
                return;
            }
            findings.push((FindingType::IpAddress, ip_str));
            return;
        }

        if let Some(ip_match) = IPV6_REGEX.find(string) {
            let ip_str = ip_match.as_str().to_owned();
            if !is_public_routable_ip(&ip_str) {
                return;
            }
            findings.push((FindingType::IpV6Address, ip_str));
            return;
        }

        if let Some(url_match) = URL_REGEX.find(string) {
            let url_match = url_match.as_str();
            let domain = extract_domain(url_match);

            if !domain.is_empty()
                && !self.is_good_link(&domain)
                && !self.is_suspicious_domain(&domain)
                && !self.is_local_host(&domain)
            {
                if is_known_good_ip(&domain) {
                    return;
                }
                findings.push((FindingType::Url, url_match.to_string()));
            }
        }
    }

    fn is_local_host(&self, host: &str) -> bool {
        let lower = host.to_lowercase();
        lower == "localhost"
            || lower.ends_with(".local")
            || lower.ends_with(".lan")
            || lower.ends_with(".internal")
            || lower.ends_with(".home")
            || lower.ends_with(".localdomain")
    }

    fn check_suspicious_url_patterns(
        &self,
        string: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        for cap in URL_REGEX.captures_iter(string) {
            if let Some(url_match) = cap.get(0) {
                let url_str = url_match.as_str();
                let domain = extract_domain(url_str).to_lowercase();

                if domain.is_empty() {
                    continue;
                }

                let is_discord_domain = domain.ends_with("discord.com")
                    || domain.ends_with("discordapp.com")
                    || domain.contains(".discord.com")
                    || domain.contains(".discordapp.com");

                if is_discord_domain && url_str.to_lowercase().contains("/api/webhooks/") {
                    findings.push((
                        FindingType::DiscordWebhook,
                        format!("Discord Webhook: {}", url_str),
                    ));
                } else if self.is_suspicious_domain(&domain) {
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

    fn check_malicious_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        if let Some(keyword) = MALICIOUS_PATTERN_REGEX.find(string) {
            let keyword = keyword.as_str();
            let keyword_lower = keyword.to_lowercase();
            if !self.ignored_suspicious_keywords.contains(&keyword_lower) {
                findings.push((
                    FindingType::SuspiciousKeyword,
                    format!("'{}' in \"{}\"", keyword, truncate_string(string, 80)),
                ));
            }
        }
    }

    fn check_encoded_payloads(&self, string: &str, findings: &mut Vec<(FindingType, String)>) {
        let candidate = string.trim();
        if candidate.len() < MIN_BASE64_BLOB_LEN {
            return;
        }

        if self.looks_like_base64_blob(candidate) {
            findings.push((
                FindingType::EncodedPayload,
                format!("High-entropy Base64-like blob ({} chars)", candidate.len()),
            ));
            return;
        }

        if self.looks_like_hex_blob(candidate) {
            findings.push((
                FindingType::EncodedPayload,
                format!("High-entropy hex blob ({} chars)", candidate.len()),
            ));
        }
    }

    fn looks_like_base64_blob(&self, input: &str) -> bool {
        if input.len() < MIN_BASE64_BLOB_LEN || !input.len().is_multiple_of(4) {
            return false;
        }

        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;

        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' => has_upper = true,
                b'a'..=b'z' => has_lower = true,
                b'0'..=b'9' => has_digit = true,
                b'+' | b'/' | b'=' => {}
                _ => return false,
            }
        }

        let padding_len = input.bytes().rev().take_while(|byte| *byte == b'=').count();
        if padding_len > 2 || !has_upper || !has_lower || !has_digit {
            return false;
        }

        self.estimate_entropy(input) >= BASE64_ENTROPY_THRESHOLD
    }

    fn looks_like_hex_blob(&self, input: &str) -> bool {
        if input.len() < MIN_HEX_BLOB_LEN || !input.len().is_multiple_of(2) {
            return false;
        }

        let mut has_alpha = false;
        let mut has_digit = false;

        for byte in input.bytes() {
            match byte {
                b'0'..=b'9' => has_digit = true,
                b'a'..=b'f' | b'A'..=b'F' => has_alpha = true,
                _ => return false,
            }
        }

        has_alpha && has_digit && self.estimate_entropy(input) >= HEX_ENTROPY_THRESHOLD
    }

    fn estimate_entropy(&self, input: &str) -> f64 {
        let mut counts = [0usize; 256];
        for byte in input.bytes() {
            counts[byte as usize] += 1;
        }

        let len = input.len() as f64;
        counts
            .iter()
            .filter(|count| **count > 0)
            .fold(0.0, |entropy, count| {
                let probability = *count as f64 / len;
                entropy - probability * probability.log2()
            })
    }

    fn check_all_patterns(&self, string: &str, findings: &mut Vec<(FindingType, String)>) -> bool {
        let initial_len = findings.len();
        let has_url = URL_REGEX.is_match(string);
        let has_network = has_url || IP_REGEX.is_match(string) || IPV6_REGEX.is_match(string);

        if has_network {
            self.check_network_patterns(string, findings);
            if has_url {
                self.check_suspicious_url_patterns(string, findings);
            }
        }

        if MALICIOUS_PATTERN_REGEX.is_match(string) {
            self.check_malicious_patterns(string, findings);
        }

        self.check_encoded_payloads(string, findings);

        findings.len() == initial_len
    }

    fn check_network_patterns_combined(
        &self,
        string: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) -> bool {
        let initial_len = findings.len();
        self.check_network_patterns(string, findings);
        if findings.len() == initial_len {
            self.check_suspicious_url_patterns(string, findings);
        }
        findings.len() == initial_len
    }

    fn check_malicious_patterns_only(
        &self,
        string: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) -> bool {
        let initial_len = findings.len();
        self.check_malicious_patterns(string, findings);
        self.check_encoded_payloads(string, findings);
        findings.len() == initial_len
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

            if name.contains('/')
                && context.ends_with(" Name")
                && !context.starts_with("Class")
                && !context.starts_with("Superclass")
                && !context.starts_with("Interface")
            {
                let simple_name = get_simple_name(name);
                if simple_name.contains('/') && simple_name == name && self.options.verbose {
                    println!("      Suspicious name contains '/': {} - {}", context, name);
                }
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

        let fields_sample_size = (details.fields.len() / 20).max(3).min(details.fields.len());
        for f in details.fields.iter().take(fields_sample_size) {
            check(&f.name, "Field Name");
        }

        let methods_sample_size = (details.methods.len() / 20)
            .max(3)
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

    fn get_cached_findings(&self, hash: u64) -> Option<Arc<Vec<(FindingType, String)>>> {
        self.result_cache.get(&hash)
    }

    pub(crate) fn normalize_findings(&self, findings: &mut Vec<(FindingType, String)>) {
        findings.sort_unstable();
        findings.dedup();
    }

    fn cache_findings_new(&self, hash: u64, findings: &[(FindingType, String)]) {
        let vec = findings.to_vec();
        let arc = Arc::new(vec);
        let _ = self.result_cache.get_with(hash, || arc.clone());
    }

    pub(crate) fn calculate_danger_score(
        &self,
        findings: &[(FindingType, String)],
        resource_info: Option<&ResourceInfo>,
    ) -> u8 {
        if findings.is_empty() {
            return 1;
        }

        let mut type_counts: HashMap<FindingType, usize> = HashMap::new();
        for (finding_type, _) in findings {
            *type_counts.entry(*finding_type).or_insert(0) += 1;
        }

        if *type_counts.get(&FindingType::DiscordWebhook).unwrap_or(&0) > 0 {
            return 10;
        }

        let mut score_acc: usize = 0;
        for (ftype, count) in &type_counts {
            let weight = ftype.base_score() as usize;
            let cap = ftype.max_contribution() as usize;
            let contrib = (count * weight).min(cap);
            score_acc += contrib;
        }

        if let Some(ri) = resource_info {
            if ri.is_dead_class_candidate {
                score_acc += 3;
            }
        }

        let suspicious_url_count = *type_counts.get(&FindingType::SuspiciousUrl).unwrap_or(&0);
        let suspicious_keyword_count = *type_counts
            .get(&FindingType::SuspiciousKeyword)
            .unwrap_or(&0);
        let suspicious_api_count = *type_counts.get(&FindingType::SuspiciousApi).unwrap_or(&0);
        let encoded_payload_count = *type_counts.get(&FindingType::EncodedPayload).unwrap_or(&0);
        let tampered_class_count = *type_counts.get(&FindingType::TamperedClass).unwrap_or(&0);
        let suspicious_archive_count = *type_counts
            .get(&FindingType::SuspiciousArchiveEntry)
            .unwrap_or(&0);
        let native_library_count = *type_counts.get(&FindingType::NativeLibrary).unwrap_or(&0);
        let ip_address_count = *type_counts.get(&FindingType::IpAddress).unwrap_or(&0)
            + *type_counts.get(&FindingType::IpV6Address).unwrap_or(&0);

        if suspicious_url_count > 0
            && (suspicious_keyword_count > 0 || ip_address_count > 0 || suspicious_api_count > 0)
        {
            score_acc += 5;
        }

        if encoded_payload_count > 0
            && (suspicious_keyword_count > 0 || suspicious_api_count > 0 || suspicious_url_count > 0)
        {
            score_acc += 3;
        }

        if tampered_class_count > 0 {
            score_acc += 2;
        }

        if suspicious_archive_count > 0 && native_library_count > 0 {
            score_acc += 2;
        }

        if type_counts.len() >= 3 {
            score_acc += 2;
        }

        (score_acc as i32).clamp(1, 10) as u8
    }

    pub(crate) fn generate_danger_explanation(
        &self,
        score: u8,
        findings: &[(FindingType, String)],
        resource_info: Option<&ResourceInfo>,
    ) -> Vec<String> {
        if findings.is_empty() {
            return vec!["No suspicious elements detected.".to_string()];
        }

        let mut explanations = Vec::new();

        let warn_prefix = "(!) ";
        let ok_prefix = "[+] ";

        if score >= 8 {
            explanations.push(format!(
                "{}HIGH RISK: This file contains multiple high-risk indicators!",
                warn_prefix
            ));
        } else if score >= 5 {
            explanations.push(format!(
                "{}MODERATE RISK: This file contains several suspicious elements.",
                warn_prefix
            ));
        } else if score >= 3 {
            explanations.push(format!(
                "{}LOW RISK: This file contains some potentially concerning elements.",
                warn_prefix
            ));
        } else {
            explanations.push(format!(
                "{}MINIMAL RISK: Few or no concerning elements detected.",
                ok_prefix
            ));
        }

        let mut by_type: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (finding_type, value) in findings {
            by_type
                .entry(*finding_type)
                .or_default()
                .push(value.clone());
        }

        if let Some(webhooks) = by_type.get(&FindingType::DiscordWebhook) {
            if !webhooks.is_empty() {
                explanations.push(format!(
                    "CRITICAL: Found {} Discord webhook(s)! These are extremely dangerous and commonly used for data exfiltration, logging stolen information.",
                    webhooks.len()
                ));
            }
        }

        if let Some(urls) = by_type.get(&FindingType::SuspiciousUrl) {
            if !urls.is_empty() {
                explanations.push(format!(
                    "Found {} suspicious URL(s) that may be used for data exfiltration.",
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

        if let Some(api_markers) = by_type.get(&FindingType::SuspiciousApi) {
            if !api_markers.is_empty() {
                explanations.push(format!(
                    "Uses {} high-risk Java API marker(s) related to command execution, reflection, class loading, or instrumentation.",
                    api_markers.len()
                ));
            }
        }

        if let Some(encoded_payloads) = by_type.get(&FindingType::EncodedPayload) {
            if !encoded_payloads.is_empty() {
                explanations.push(format!(
                    "Contains {} high-entropy encoded blob(s) that may hide payloads, encrypted configuration, or staged code.",
                    encoded_payloads.len()
                ));
            }
        }

        if let Some(tampered_classes) = by_type.get(&FindingType::TamperedClass) {
            if !tampered_classes.is_empty() {
                explanations.push(
                    "Contains malformed or non-standard class magic bytes. This is commonly used to evade static scanners and rely on a custom ClassLoader.".to_string()
                );
            }
        }

        if let Some(native_libraries) = by_type.get(&FindingType::NativeLibrary) {
            if !native_libraries.is_empty() {
                explanations.push(format!(
                    "Bundles {} native library resource(s). Embedded native code should be reviewed carefully because it bypasses normal JVM bytecode inspection.",
                    native_libraries.len()
                ));
            }
        }

        if let Some(archive_entries) = by_type.get(&FindingType::SuspiciousArchiveEntry) {
            if !archive_entries.is_empty() {
                explanations.push(format!(
                    "Contains {} suspicious embedded resource(s) such as scripts, executables, agent manifests, or heavily packed files.",
                    archive_entries.len()
                ));
            }
        }

        if resource_info.is_some_and(|ri| ri.is_dead_class_candidate) {
            explanations.push(
                "Contains custom JVM bytecode (0xDEAD) which may indicate use of a custom classloader to evade detection.".to_string()
            );
        }

        explanations
    }

    fn handle_cached_findings(
        &self,
        cached_findings_arc: Arc<Vec<(FindingType, String)>>,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let cached_findings: &[(FindingType, String)] = cached_findings_arc.as_ref();

        if !cached_findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(cached_findings, resource_info.as_ref());
            let danger_explanation = self.generate_danger_explanation(
                danger_score,
                cached_findings,
                resource_info.as_ref(),
            );

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: cached_findings_arc.clone(),
                class_details: None,
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }

    fn handle_non_standard_class(
        &self,
        data: &[u8],
        data_hash: u64,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
        findings: &mut Vec<(FindingType, String)>,
    ) -> Result<Option<ScanResult>, ScanError> {
        let magic_preview = if data.is_empty() {
            "empty file".to_string()
        } else {
            data.iter()
                .take(4)
                .map(|byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(" ")
        };

        let tampered_message = if data.starts_with(b"\xDE\xAD") {
            "Non-standard class magic 0xDEAD detected; likely requires a custom ClassLoader"
                .to_string()
        } else {
            format!("Invalid class magic bytes: {}", magic_preview)
        };

        findings.push((FindingType::TamperedClass, tampered_message));
        self.normalize_findings(findings);

        if let Ok(mut found_flag) = self.found_custom_jvm_indicator.lock() {
            *found_flag = true;
        }

        self.cache_findings_new(data_hash, findings);

        if !findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(findings, resource_info.as_ref());
            let danger_explanation =
                self.generate_danger_explanation(danger_score, findings, resource_info.as_ref());

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: Arc::new(findings.to_owned()),
                class_details: None,
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }

    fn analyze_class_details(
        &self,
        class_details: &ClassDetails,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if self.options.mode == DetectionMode::Obfuscation
            || self.options.mode == DetectionMode::All
        {
            self.check_name_obfuscation(class_details, findings);
        }

        let string_set: HashSet<&str> = class_details.strings.iter().map(String::as_str).collect();

        self.record_api_usage(
            &string_set,
            PROCESS_EXECUTION_MARKERS,
            "Process execution API usage",
            findings,
        );
        self.record_api_usage(
            &string_set,
            REFLECTION_MARKERS,
            "Reflection-based access",
            findings,
        );
        self.record_api_usage(
            &string_set,
            DYNAMIC_LOADING_MARKERS,
            "Dynamic class loading or definition",
            findings,
        );
        self.record_api_usage(
            &string_set,
            SCRIPT_ENGINE_MARKERS,
            "Script engine execution",
            findings,
        );
        self.record_api_usage(
            &string_set,
            JAVA_AGENT_MARKERS,
            "Java agent instrumentation",
            findings,
        );
        self.record_api_usage(
            &string_set,
            ATTACH_API_MARKERS,
            "JVM attach API usage",
            findings,
        );
        self.record_api_usage(
            &string_set,
            NATIVE_BRIDGE_MARKERS,
            "Native bridge or Unsafe API usage",
            findings,
        );

        drop(string_set);
    }

    fn record_api_usage(
        &self,
        string_set: &HashSet<&str>,
        markers: &[&str],
        message: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if markers.iter().any(|marker| string_set.contains(marker)) {
            findings.push((FindingType::SuspiciousApi, message.to_string()));
        }
    }

    fn prepare_strings_for_scanning<'a>(&self, class_details: &'a ClassDetails) -> Vec<&'a String> {
        let strings_to_scan = class_details
            .strings
            .iter()
            .filter(|s| !s.is_empty() && s.len() >= 3 && !is_cached_safe_string(s))
            .take(2000)
            .collect::<Vec<_>>();

        strings_to_scan
    }

    fn scan_strings_by_mode(
        &self,
        strings_to_scan: &[&String],
        findings: &mut Vec<(FindingType, String)>,
    ) {
        match self.options.mode {
            DetectionMode::All => {
                self.scan_strings_parallel(strings_to_scan, findings, Self::check_all_patterns);
            }
            DetectionMode::Network => {
                self.scan_strings_parallel(
                    strings_to_scan,
                    findings,
                    Self::check_network_patterns_combined,
                );
            }
            DetectionMode::Malicious => {
                self.scan_strings_parallel(
                    strings_to_scan,
                    findings,
                    Self::check_malicious_patterns_only,
                );
            }
            _ => {}
        }
    }

    fn scan_strings_parallel(
        &self,
        strings_to_scan: &[&String],
        findings: &mut Vec<(FindingType, String)>,
        check_fn: fn(&Self, &str, &mut Vec<(FindingType, String)>) -> bool,
    ) {
        let partials: Vec<Vec<(FindingType, String)>> = strings_to_scan
            .par_iter()
            .map(|s| {
                let mut local = Vec::new();
                let s_ref = s.as_str();
                let (s_to_check, truncated_due_to_boundary) = self.truncate_scan_string(s_ref);

                if truncated_due_to_boundary {
                    self.push_truncation_finding(s_ref, &mut local);
                }

                if check_fn(self, s_to_check, &mut local) {
                    cache_safe_string(s_ref);
                }

                local
            })
            .collect();

        for mut partial in partials {
            findings.append(&mut partial);
        }
    }

    fn truncate_scan_string<'a>(&self, input: &'a str) -> (&'a str, bool) {
        if input.len() <= Self::MAX_SCAN_STRING_LEN {
            return (input, false);
        }

        if input.is_char_boundary(Self::MAX_SCAN_STRING_LEN) {
            return (&input[..Self::MAX_SCAN_STRING_LEN], false);
        }

        let mut end = Self::MAX_SCAN_STRING_LEN;
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }

        if end == 0 {
            ("", false)
        } else {
            (&input[..end], true)
        }
    }

    fn push_truncation_finding(&self, s_ref: &str, findings: &mut Vec<(FindingType, String)>) {
        if self.options.verbose {
            println!(
                "      Warning: possible obfuscated/non-UTF8 string truncated: {}",
                truncate_string(s_ref, 60)
            );
        }

        findings.push((
            FindingType::ObfuscationUnicode,
            format!(
                "Obfuscated string truncated: {}",
                truncate_string(s_ref, 60)
            ),
        ));
    }

    fn create_scan_result(
        &self,
        mut findings: Vec<(FindingType, String)>,
        class_details: ClassDetails,
        original_path_str: &str,
        resource_info: Option<ResourceInfo>,
    ) -> Result<Option<ScanResult>, ScanError> {
        self.normalize_findings(&mut findings);

        if !findings.is_empty() || self.options.verbose {
            let danger_score = self.calculate_danger_score(&findings, resource_info.as_ref());
            let danger_explanation =
                self.generate_danger_explanation(danger_score, &findings, resource_info.as_ref());

            Ok(Some(ScanResult {
                file_path: original_path_str.to_string(),
                matches: Arc::new(findings),
                class_details: Some(class_details),
                resource_info,
                danger_score,
                danger_explanation,
            }))
        } else {
            Ok(None)
        }
    }
}
