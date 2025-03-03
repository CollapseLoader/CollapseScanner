mod database;

use colored::*;
use database::GOOD_LINKS;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use url::Url;
use zip::ZipArchive;

#[derive(Debug, Clone)]
struct ScanResult {
    file_path: String,
    matches: Vec<(String, String)>,
}

struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    url_regex: Regex,
}

impl CollapseScanner {
    fn new() -> Result<CollapseScanner, io::Error> {
        let good_links: HashSet<_> = GOOD_LINKS.iter().cloned().collect();

        lazy_static! {
            static ref IP_REGEX_STATIC: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
            static ref URL_REGEX_STATIC: Regex =
                Regex::new(r"\b(?:https?|ftp|ssh|telnet|file)://[^\s/$.?#].[^\s]*\b").unwrap();
        }

        Ok(CollapseScanner {
            good_links,
            ip_regex: IP_REGEX_STATIC.clone(),
            url_regex: URL_REGEX_STATIC.clone(),
        })
    }

    fn scan_jar(
        &self,
        jar_path: &str,
        multi_progress: &MultiProgress,
    ) -> Result<Vec<ScanResult>, io::Error> {
        let file = File::open(jar_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                eprintln!("Error: The file '{}' was not found.", jar_path);
            }
            e
        })?;

        let mut archive = ZipArchive::new(file)?;

        let pb = multi_progress.add(ProgressBar::new(archive.len() as u64));

        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .expect("Failed to create progress bar template")
                .progress_chars("#>-"),
        );

        let mut results = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => continue,
            };

            if file.name().ends_with(".class") {
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                if let Some(scan_result) =
                    self.scan_class_file_content(&buffer, &outpath.to_string_lossy())
                {
                    if scan_result.matches.len() == 1 {
                        let (match_type, matched_string) = &scan_result.matches[0];
                        let msg = format!(
                            "File: {} - Type: {}, Value: {}",
                            scan_result.file_path.cyan(),
                            match_type.green(),
                            matched_string.red()
                        );
                        pb.println(msg);
                    } else {
                        let msg = format!("File: {}", scan_result.file_path.cyan());
                        pb.println(msg);
                        for (match_type, matched_string) in &scan_result.matches {
                            let msg2 = format!(
                                "  Type: {}, Value: {}",
                                match_type.green(),
                                matched_string.red()
                            );
                            pb.println(msg2);
                        }
                    }

                    results.push(scan_result);
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Scan complete");
        Ok(results)
    }

    fn scan_class_file_content(&self, buffer: &[u8], file_path: &str) -> Option<ScanResult> {
        let mut matches = Vec::new();
        let content = String::from_utf8_lossy(buffer);

        for cap in self.ip_regex.captures_iter(&content) {
            let ip = cap.get(0).unwrap().as_str();
            if !self.good_links.contains(ip) {
                matches.push(("IP".to_string(), ip.to_string()));
            }
        }

        for cap in self.url_regex.captures_iter(&content) {
            let url_str = cap.get(0).unwrap().as_str();
            if let Ok(url) = Url::parse(url_str) {
                if let Some(host) = url.host_str() {
                    if !self.good_links.contains(host) {
                        matches.push(("URL".to_string(), url_str.to_string()));
                    }
                } else {
                    matches.push(("URL".to_string(), url_str.to_string()));
                }
            } else {
                matches.push(("Invalid URL".to_string(), url_str.to_string()));
            }
        }

        if !matches.is_empty() {
            Some(ScanResult {
                file_path: file_path.to_string(),
                matches,
            })
        } else {
            None
        }
    }
}

fn main() -> Result<(), io::Error> {
    println!(
        "\n{} - Jar scanning tool for links and ips\n{} scanner may not be accurate!\n",
        "CollapseScanner".bold().bright_blue(),
        "warning:".yellow()
    );

    print!("Enter the path to the JAR file: ");
    io::stdout().flush()?;

    let mut jar_path = String::new();
    io::stdin().read_line(&mut jar_path)?;
    let jar_path = jar_path.trim();

    let scanner = CollapseScanner::new()?;
    let multi_progress = MultiProgress::new();

    let scan_results = scanner.scan_jar(jar_path, &multi_progress)?;

    println!("Scan complete, {} results:", scan_results.len());

    for result in scan_results.iter() {
        if result.matches.len() == 1 {
            let (match_type, matched_string) = &result.matches[0];
            println!(
                "File: {} - Type: {}, Value: {}",
                result.file_path.cyan(),
                match_type.green(),
                matched_string.red()
            );
        } else {
            println!("File: {}", result.file_path.cyan());
            for (match_type, matched_string) in &result.matches {
                println!(
                    "  Type: {}, Value: {}",
                    match_type.green(),
                    matched_string.red()
                );
            }
        }
    }
    Ok(())
}
