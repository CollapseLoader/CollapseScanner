use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;

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
        if path.extension().is_some_and(|ext| ext == "jar") {
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
}
