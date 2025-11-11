use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use zip::ZipArchive;

use crate::config::SYSTEM_CONFIG;
use crate::errors::ScanError;
use crate::scanner::scan::CollapseScanner;
use crate::types::{ResourceInfo, ScanResult};

impl CollapseScanner {
    pub(crate) fn scan_jar_file(&self, jar_path: &Path) -> Result<Vec<ScanResult>, ScanError> {
        let start_time = Instant::now();
        let file = File::open(jar_path)?;
        let mut archive = ZipArchive::new(file)?;
        let total_files = archive.len();
        let mut skipped_count = 0;
        let mut results = Vec::new();

        if self.options.verbose {
            println!("{} Scanning JAR file: {}", "🔎".blue(), jar_path.display());
        }

        let buffer_size = SYSTEM_CONFIG.buffer_size.min(4 * 1024 * 1024);
        let avg_entry_size = total_files.saturating_sub(1).max(1) * 1024;
        let optimal_buffer = (avg_entry_size * 2).min(buffer_size).min(1024 * 1024);

        let mut file_data_vec = Vec::with_capacity(total_files.min(1000));
        let mut total_memory_used = 0u64;
        let max_total_memory = 100 * 1024 * 1024;

        for i in 0..total_files {
            let mut zip_file = match archive.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "{} Error accessing entry {} in {}: {}",
                        "⚠️ ".yellow(),
                        i,
                        jar_path.display(),
                        e
                    );
                    continue;
                }
            };

            let original_entry_name = match zip_file.enclosed_name() {
                Some(p) => p.to_string_lossy().replace('\\', "/"),
                None => String::from_utf8_lossy(zip_file.name_raw()).replace('\\', "/"),
            };

            if !self.should_scan(&original_entry_name) {
                skipped_count += 1;
                continue;
            }

            let file_size = zip_file.size() as usize;
            if file_size > optimal_buffer {
                skipped_count += 1;
                continue;
            }

            if total_memory_used + file_size as u64 > max_total_memory {
                break;
            }

            let mut buffer = Vec::with_capacity(file_size);
            if let Err(e) = zip_file.read_to_end(&mut buffer) {
                eprintln!(
                    "{} Error reading content of {}: {}",
                    "⚠️ ".yellow(),
                    original_entry_name,
                    e
                );
                continue;
            }

            total_memory_used += buffer.len() as u64;
            file_data_vec.push((original_entry_name, buffer));
        }

        let pb_template = format!("{} [{{elapsed_precise}}] {{bar:40.cyan/blue}} {{pos:>7}}/{{len:7}} ({{percent}}%) Processing: {{msg}}", "🔍".green());

        let progress_bar = Arc::new(Mutex::new(ProgressBar::new(file_data_vec.len() as u64)));
        progress_bar.lock().unwrap().set_style(
            ProgressStyle::default_bar()
                .template(&pb_template)?
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let processed_count = Arc::new(AtomicUsize::new(0));

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.total = file_data_vec.len();
                gp.current = 0;
                gp.message = "Processing JAR entries...".to_string();
            }
        }

        let scan_results: Vec<_> = file_data_vec
            .par_iter()
            .with_max_len(10)
            .map(|(original_entry_name, buffer)| {
                if let Some(ref prog_arc) = self.options.progress {
                    if let Ok(gp) = prog_arc.lock() {
                        if gp.cancelled {
                            return Ok((
                                None,
                                ResourceInfo {
                                    path: original_entry_name.clone(),
                                    size: buffer.len() as u64,
                                    is_class_file: false,
                                    is_dead_class_candidate: false,
                                },
                            ));
                        }
                    }
                }

                self.process_jar_entry(original_entry_name, buffer, &progress_bar, &processed_count)
            })
            .collect();

        for scan_result in scan_results {
            match scan_result {
                Ok((Some(scan_result), _)) => {
                    results.push(scan_result);
                }
                Ok((None, _)) => {}
                Err(e) => {
                    eprintln!("{} Error processing JAR entry: {}", "⚠️ ".yellow(), e);
                }
            }
        }

        progress_bar.lock().unwrap().finish_with_message(format!(
            "Finished processing {} files ({} skipped, {} analyzed)",
            total_files,
            skipped_count,
            file_data_vec.len()
        ));

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.current = gp.total;
                gp.message = format!("Finished processing {} files", file_data_vec.len());
            }
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

    pub fn process_jar_entry(
        &self,
        original_entry_name: &str,
        buffer: &[u8],
        progress_bar: &Arc<Mutex<ProgressBar>>,
        processed_count: &Arc<AtomicUsize>,
    ) -> Result<(Option<ScanResult>, ResourceInfo), ScanError> {
        let pb_guard = progress_bar.lock().unwrap();
        pb_guard.set_message(original_entry_name.to_string());
        drop(pb_guard);

        let resource_info = self.analyze_resource(original_entry_name, buffer)?;

        let scan_result = if resource_info.is_class_file || resource_info.is_dead_class_candidate {
            self.scan_class_data(buffer, original_entry_name, Some(resource_info.clone()))?
        } else {
            None
        };

        let count = processed_count.fetch_add(1, Ordering::Relaxed);
        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                if gp.cancelled {
                    gp.message = "Scan cancelled".to_string();
                    return Ok((None, resource_info));
                }
                gp.current = count + 1;
                gp.message = original_entry_name.to_string();
            }
        }

        if count.is_multiple_of(10) {
            let pb_guard = progress_bar.lock().unwrap();
            pb_guard.inc(10);
            drop(pb_guard);
        }

        Ok((scan_result, resource_info))
    }

    pub fn analyze_resource(
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
            is_dead_class_candidate,
        })
    }
}
