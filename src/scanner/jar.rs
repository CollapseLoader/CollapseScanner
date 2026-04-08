use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use zip::ZipArchive;

use crate::config::SYSTEM_CONFIG;
use crate::errors::ScanError;
use crate::scanner::scan::CollapseScanner;
use crate::types::{FindingType, ResourceInfo, ScanResult};

const MAX_NESTED_ARCHIVE_DEPTH: usize = 2;
const HIGHLY_COMPRESSED_SIZE_THRESHOLD: u64 = 256 * 1024;
const HIGH_COMPRESSION_RATIO_THRESHOLD: f64 = 40.0;

const NESTED_ARCHIVE_EXTENSIONS: &[&str] = &["jar", "zip", "jmod"];
const SCRIPT_RESOURCE_EXTENSIONS: &[&str] = &["bat", "cmd", "ps1", "vbs", "js", "hta", "wsf", "sh"];
const EXECUTABLE_RESOURCE_EXTENSIONS: &[&str] = &["exe", "scr", "com", "msi"];
const NATIVE_LIBRARY_EXTENSIONS: &[&str] = &["dll", "so", "dylib", "jnilib"];

impl CollapseScanner {
    pub(crate) fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let start_time = Instant::now();
        let file = File::open(jar_path)?;
        let mut archive = ZipArchive::new(file)?;
        let total_files = archive.len();
        let mut skipped_count = 0;

        if self.options.verbose {
            println!("[*] Scanning JAR file: {}", jar_path.display());
        }

        let max_entry_size = SYSTEM_CONFIG.max_file_size * 1024 * 1024;

        let pb_template = format!("[*] [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} ({{percent}}%) Processing: {{msg}}");
        let progress_bar = Arc::new(Mutex::new(ProgressBar::new(total_files as u64)));
        progress_bar.lock().unwrap().set_style(
            ProgressStyle::default_bar()
                .template(&pb_template)?
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let processed_count = Arc::new(AtomicUsize::new(0));
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.total = total_files;
                gp.current = 0;
                gp.message = "Processing JAR entries...".to_string();
            }
        }

        let results_arc = Arc::new(Mutex::new(Vec::with_capacity(total_files)));

        rayon::scope(|scope| {
            for i in 0..total_files {
                let mut archive_file = match archive.by_index(i) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!(
                            "(!) Error accessing entry {} in {}: {}",
                            i,
                            jar_path.display(),
                            e
                        );
                        continue;
                    }
                };

                let original_entry_name = match archive_file.enclosed_name() {
                    Some(p) => p.to_string_lossy().replace('\\', "/"),
                    None => String::from_utf8_lossy(archive_file.name_raw()).replace('\\', "/"),
                };

                if archive_file.is_dir() || !self.should_scan(&original_entry_name) {
                    skipped_count += 1;
                    continue;
                }

                let file_size = archive_file.size() as usize;
                if file_size > max_entry_size {
                    if let Some(result) = self.create_oversized_entry_result(
                        &original_entry_name,
                        archive_file.size(),
                    ) {
                        results_arc.lock().unwrap().push(result);
                    } else if self.options.verbose {
                        eprintln!(
                            "(!) Skipping oversized entry ({} bytes): {}",
                            archive_file.size(),
                            original_entry_name
                        );
                    }
                    skipped_count += 1;
                    continue;
                }

                let mut buffer = Vec::with_capacity(file_size);
                if let Err(e) = archive_file.read_to_end(&mut buffer) {
                    eprintln!(
                        "(!) Error reading content of {}: {}",
                        original_entry_name, e
                    );
                    continue;
                }

                let compressed_size = archive_file.compressed_size();
                let arc_buf = Arc::new(buffer);
                let name_clone = original_entry_name;
                let progress_bar_clone = progress_bar.clone();
                let processed_count_clone = processed_count.clone();
                let results_clone = results_arc.clone();

                scope.spawn(move |_| {
                    if let Ok(mut entry_results) = self.process_jar_entry(
                        &name_clone,
                        arc_buf.as_ref(),
                        compressed_size,
                        &progress_bar_clone,
                        &processed_count_clone,
                    ) {
                        results_clone.lock().unwrap().append(&mut entry_results);
                    }
                });
            }
        });

        let results = Arc::into_inner(results_arc)
            .expect("All threads should have finished")
            .into_inner()
            .unwrap();

        progress_bar.lock().unwrap().finish_with_message(format!(
            "Finished processing {} files ({} skipped, {} analyzed)",
            total_files,
            skipped_count,
            processed_count.load(Ordering::Relaxed)
        ));

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.current = gp.total;
                gp.message = format!(
                    "Finished processing {} files",
                    processed_count.load(Ordering::Relaxed)
                );
            }
        }

        if self.options.verbose {
            println!(
                "[+] JAR scan completed in {:.2}s",
                start_time.elapsed().as_secs_f64()
            );
        }

        Ok(results)
    }

    pub fn process_jar_entry(
        &self,
        original_entry_name: &str,
        buffer: &[u8],
        compressed_size: u64,
        progress_bar: &Arc<Mutex<ProgressBar>>,
        processed_count: &Arc<AtomicUsize>,
    ) -> Result<Vec<ScanResult>, ScanError> {
        progress_bar
            .lock()
            .unwrap()
            .set_message(original_entry_name.to_string());

        let scan_results = self.scan_archive_entry_contents(
            original_entry_name,
            original_entry_name,
            buffer,
            Some(compressed_size),
            0,
        )?;

        let count = processed_count.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.cancelled {
                    gp.message = "Scan cancelled".to_string();
                    return Ok(Vec::new());
                }
                gp.current = count;
                gp.message = original_entry_name.to_string();
            }
        }

        progress_bar.lock().unwrap().inc(1);

        Ok(scan_results)
    }

    fn scan_archive_entry_contents(
        &self,
        display_path: &str,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
        archive_depth: usize,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let resource_info = self.analyze_resource(display_path, buffer)?;
        let mut results = Vec::new();

        if let Some(result) = self.create_resource_result(
            display_path,
            resource_name,
            buffer,
            compressed_size,
            &resource_info,
        ) {
            results.push(result);
        }

        if resource_info.is_class_file || resource_info.is_dead_class_candidate {
            if let Some(scan_result) =
                self.scan_class_data(buffer, display_path, Some(resource_info.clone()))?
            {
                results.push(scan_result);
            }
        }

        if archive_depth < MAX_NESTED_ARCHIVE_DEPTH
            && self.should_recurse_into_archive(resource_name, buffer)
        {
            results.extend(self.scan_nested_archive_buffer(
                display_path,
                buffer,
                archive_depth + 1,
            )?);
        }

        Ok(results)
    }

    fn scan_nested_archive_buffer(
        &self,
        container_path: &str,
        buffer: &[u8],
        archive_depth: usize,
    ) -> Result<Vec<ScanResult>, ScanError> {
        let cursor = Cursor::new(buffer);
        let mut archive = match ZipArchive::new(cursor) {
            Ok(archive) => archive,
            Err(_) => return Ok(Vec::new()),
        };

        let max_entry_size = SYSTEM_CONFIG.max_file_size * 1024 * 1024;
        let mut results = Vec::new();

        for index in 0..archive.len() {
            let mut archive_file = match archive.by_index(index) {
                Ok(file) => file,
                Err(error) => {
                    if self.options.verbose {
                        eprintln!(
                            "(!) Error accessing nested entry {} in {}: {}",
                            index,
                            container_path,
                            error
                        );
                    }
                    continue;
                }
            };

            let relative_name = match archive_file.enclosed_name() {
                Some(path) => path.to_string_lossy().replace('\\', "/"),
                None => String::from_utf8_lossy(archive_file.name_raw()).replace('\\', "/"),
            };

            if archive_file.is_dir() || !self.should_scan(&relative_name) {
                continue;
            }

            let display_path = format!("{}!/{relative_name}", container_path);
            let file_size = archive_file.size() as usize;
            if file_size > max_entry_size {
                if let Some(result) = self.create_oversized_entry_result(&display_path, archive_file.size()) {
                    results.push(result);
                }
                continue;
            }

            let compressed_size = archive_file.compressed_size();
            let mut nested_buffer = Vec::with_capacity(file_size);
            if let Err(error) = archive_file.read_to_end(&mut nested_buffer) {
                if self.options.verbose {
                    eprintln!(
                        "(!) Error reading nested entry {} from {}: {}",
                        relative_name,
                        container_path,
                        error
                    );
                }
                continue;
            }

            results.extend(self.scan_archive_entry_contents(
                &display_path,
                &relative_name,
                &nested_buffer,
                Some(compressed_size),
                archive_depth,
            )?);
        }

        Ok(results)
    }

    fn create_resource_result(
        &self,
        display_path: &str,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
        resource_info: &ResourceInfo,
    ) -> Option<ScanResult> {
        let mut findings = self.collect_resource_findings(resource_name, buffer, compressed_size);
        if findings.is_empty() {
            return None;
        }

        self.normalize_findings(&mut findings);
        let danger_score = self.calculate_danger_score(&findings, Some(resource_info));
        let danger_explanation =
            self.generate_danger_explanation(danger_score, &findings, Some(resource_info));

        Some(ScanResult {
            file_path: display_path.to_string(),
            matches: Arc::new(findings),
            class_details: None,
            resource_info: Some(resource_info.clone()),
            danger_score,
            danger_explanation,
        })
    }

    fn create_oversized_entry_result(&self, entry_name: &str, size: u64) -> Option<ScanResult> {
        let lower_name = entry_name.to_ascii_lowercase();
        let is_class_candidate = lower_name.ends_with(".class") || lower_name.ends_with(".class/");
        let is_interesting_resource = is_class_candidate
            || self.has_extension(&lower_name, NESTED_ARCHIVE_EXTENSIONS)
            || self.has_extension(&lower_name, SCRIPT_RESOURCE_EXTENSIONS)
            || self.has_extension(&lower_name, EXECUTABLE_RESOURCE_EXTENSIONS)
            || self.has_extension(&lower_name, NATIVE_LIBRARY_EXTENSIONS);

        if !is_interesting_resource {
            return None;
        }

        let mut findings = vec![(
            FindingType::SuspiciousArchiveEntry,
            format!(
                "Oversized entry was not fully inspected ({} bytes exceeds {} MB limit)",
                size,
                SYSTEM_CONFIG.max_file_size
            ),
        )];

        if self.has_extension(&lower_name, NATIVE_LIBRARY_EXTENSIONS) {
            findings.push((
                FindingType::NativeLibrary,
                format!("Oversized native library resource: {}", entry_name),
            ));
        }

        self.normalize_findings(&mut findings);

        let resource_info = ResourceInfo {
            path: entry_name.to_string(),
            size,
            is_class_file: is_class_candidate,
            is_dead_class_candidate: false,
        };
        let danger_score = self.calculate_danger_score(&findings, Some(&resource_info));
        let danger_explanation =
            self.generate_danger_explanation(danger_score, &findings, Some(&resource_info));

        Some(ScanResult {
            file_path: entry_name.to_string(),
            matches: Arc::new(findings),
            class_details: None,
            resource_info: Some(resource_info),
            danger_score,
            danger_explanation,
        })
    }

    fn collect_resource_findings(
        &self,
        resource_name: &str,
        buffer: &[u8],
        compressed_size: Option<u64>,
    ) -> Vec<(FindingType, String)> {
        let lower_name = resource_name.to_ascii_lowercase();
        let mut findings = Vec::new();

        if self.has_extension(&lower_name, SCRIPT_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!("Embedded script resource: {}", resource_name),
            ));
        }

        if self.has_extension(&lower_name, EXECUTABLE_RESOURCE_EXTENSIONS) {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!("Embedded executable resource: {}", resource_name),
            ));
        }

        if self.has_extension(&lower_name, NATIVE_LIBRARY_EXTENSIONS) {
            findings.push((
                FindingType::NativeLibrary,
                format!("Embedded native library: {}", resource_name),
            ));
        }

        if let Some(binary_kind) = Self::detect_binary_magic(buffer) {
            let finding_type = if self.has_extension(&lower_name, NATIVE_LIBRARY_EXTENSIONS) {
                FindingType::NativeLibrary
            } else {
                FindingType::SuspiciousArchiveEntry
            };

            findings.push((
                finding_type,
                format!("Embedded binary payload header ({binary_kind}) in {}", resource_name),
            ));
        }

        if lower_name == "meta-inf/manifest.mf" {
            self.inspect_manifest(resource_name, buffer, &mut findings);
        }

        if let Some(compressed_size) = compressed_size.filter(|size| *size > 0) {
            let uncompressed_size = buffer.len() as u64;
            let ratio = uncompressed_size as f64 / compressed_size as f64;
            if uncompressed_size >= HIGHLY_COMPRESSED_SIZE_THRESHOLD
                && ratio >= HIGH_COMPRESSION_RATIO_THRESHOLD
            {
                findings.push((
                    FindingType::SuspiciousArchiveEntry,
                    format!(
                        "Highly compressed resource ({ratio:.1}x ratio): {}",
                        resource_name
                    ),
                ));
            }
        }

        findings
    }

    fn inspect_manifest(
        &self,
        resource_name: &str,
        buffer: &[u8],
        findings: &mut Vec<(FindingType, String)>,
    ) {
        let manifest = String::from_utf8_lossy(buffer);
        let mut matched_headers = Vec::new();

        for header in [
            "Premain-Class",
            "Agent-Class",
            "Launcher-Agent-Class",
            "Can-Redefine-Classes",
            "Can-Retransform-Classes",
            "Permissions: all-permissions",
        ] {
            if manifest.contains(header) {
                matched_headers.push(header);
            }
        }

        if !matched_headers.is_empty() {
            findings.push((
                FindingType::SuspiciousArchiveEntry,
                format!(
                    "Manifest requests instrumentation or elevated permissions ({}) in {}",
                    matched_headers.join(", "),
                    resource_name
                ),
            ));
        }
    }

    fn should_recurse_into_archive(&self, resource_name: &str, buffer: &[u8]) -> bool {
        let lower_name = resource_name.to_ascii_lowercase();
        self.has_extension(&lower_name, NESTED_ARCHIVE_EXTENSIONS) || Self::has_zip_magic(buffer)
    }

    fn has_extension(&self, resource_name: &str, extensions: &[&str]) -> bool {
        Path::new(resource_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.iter().any(|candidate| ext.eq_ignore_ascii_case(candidate)))
    }

    fn has_zip_magic(buffer: &[u8]) -> bool {
        buffer.starts_with(b"PK\x03\x04")
            || buffer.starts_with(b"PK\x05\x06")
            || buffer.starts_with(b"PK\x07\x08")
    }

    fn detect_binary_magic(buffer: &[u8]) -> Option<&'static str> {
        if buffer.starts_with(b"MZ") {
            Some("PE")
        } else if buffer.starts_with(b"\x7FELF") {
            Some("ELF")
        } else if buffer.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
            || buffer.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
            || buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
            || buffer.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        {
            Some("Mach-O")
        } else {
            None
        }
    }

    pub fn analyze_resource(
        &self,
        original_path_str: &str,
        data: &[u8],
    ) -> Result<ResourceInfo, ScanError> {
        let is_class_name_candidate =
            original_path_str.ends_with(".class") || original_path_str.ends_with(".class/");

        let is_standard_class_file = is_class_name_candidate && data.starts_with(b"\xCA\xFE\xBA\xBE");

        let is_dead_class_candidate = is_class_name_candidate && !is_standard_class_file;

        Ok(ResourceInfo {
            path: original_path_str.to_string(),
            size: data.len() as u64,
            is_class_file: is_standard_class_file,
            is_dead_class_candidate,
        })
    }
}
