use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use walkdir::WalkDir;

use colored::Colorize;

use crate::errors::ScanError;
use crate::scanner::scan::CollapseScanner;
use crate::types::ScanResult;

impl CollapseScanner {
    pub(crate) fn should_scan(&self, internal_path: &str) -> bool {
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

    pub(crate) fn load_ignore_list_from_file(path: &Path) -> Result<HashSet<String>, io::Error> {
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
        if let Some(max_size) = self.options.max_file_size {
            if let Ok(metadata) = path.metadata() {
                if metadata.len() > max_size as u64 {
                    if self.options.verbose {
                        println!(
                            "{} Skipping large file: {} ({} MB > {} MB)",
                            "🚫".dimmed(),
                            path.display(),
                            metadata.len() / (1024 * 1024),
                            max_size / (1024 * 1024)
                        );
                    }
                    return Ok(Vec::new());
                }
            }
        }

        if path.is_dir() {
            self.scan_directory(path)
        } else if path.extension().is_some_and(|ext| ext == "jar") {
            self.scan_jar_file(path)
        } else if path.extension().is_some_and(|ext| ext == "class") {
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
                .is_some_and(|ext| ext == "jar" || ext == "class")
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

        let progress = Arc::new(Mutex::new(ProgressBar::new(scannable_files.len() as u64)));
        progress.lock().unwrap().set_style(progress_style);
        progress.lock().unwrap().set_message("Analyzing files...");

        if let Some(ref prog_arc) = self.options.progress {
            if let Ok(mut gp) = prog_arc.lock() {
                gp.total = scannable_files.len();
                gp.current = 0;
                gp.message = "Analyzing files...".to_string();
            }
        }

        let processed_count = Arc::new(AtomicUsize::new(0));

        let scan_results: Vec<_> = scannable_files
            .par_iter()
            .with_max_len(100)
            .map(|path| {
                if let Some(ref prog_arc) = self.options.progress {
                    if let Ok(gp) = prog_arc.lock() {
                        if gp.cancelled {
                            return Ok(Vec::new());
                        }
                    }
                }

                let result = self.scan_path(path);

                let count = processed_count.fetch_add(1, Ordering::Relaxed);
                if let Some(ref prog_arc) = self.options.progress {
                    if let Ok(mut gp) = prog_arc.lock() {
                        if gp.cancelled {
                            gp.message = "Scan cancelled".to_string();
                            return Ok(Vec::new());
                        }
                        gp.current = count + 1;
                        gp.total = scannable_files.len();
                        gp.message = format!("Scanning: {}", path.display());
                    }
                }
                if count.is_multiple_of(10) {
                    let progress_guard = progress.lock().unwrap();
                    if self.options.verbose {
                        progress_guard.set_message(format!("Scanning: {}", path.display()));
                    }
                    progress_guard.inc(10);
                    drop(progress_guard);
                }

                result
            })
            .collect();

        progress
            .lock()
            .unwrap()
            .finish_with_message(format!("Finished scanning {} files", scannable_files.len()));

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
}
