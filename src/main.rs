mod database;

use colored::*;
use database::GOOD_LINKS;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use url::Url;
use zip::ZipArchive;
// Import Arc and Mutex

#[derive(Debug, Clone)]
struct ScanResult {
    file_path: String,
    matches: Vec<(String, String)>,
}

struct CollapseScanner {
    good_links: HashSet<String>,
    ip_regex: Regex,
    url_regex: Regex,
    log_file: Option<Arc<Mutex<File>>>, // Make log_file an Option
}

impl CollapseScanner {
    fn new(log_file_path: Option<String>) -> Result<CollapseScanner, io::Error> {
        let good_links: HashSet<_> = GOOD_LINKS.iter().cloned().collect();

        lazy_static! {
            static ref IP_REGEX_STATIC: Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
            static ref URL_REGEX_STATIC: Regex =
                Regex::new(r"\b(?:https?|ftp|ssh|telnet|file)://[^\s/$.?#].[^\s]*\b").unwrap();
        }

        let log_file = if let Some(path) = log_file_path {
            Some(Arc::new(Mutex::new(
                OpenOptions::new().create(true).append(true).open(path)?,
            )))
        } else {
            None
        };

        Ok(CollapseScanner {
            good_links,
            ip_regex: IP_REGEX_STATIC.clone(),
            url_regex: URL_REGEX_STATIC.clone(),
            log_file,
        })
    }

    fn scan_file(&self, file_path: &str, multi_progress: &MultiProgress) -> Result<(), io::Error> {
        let path = Path::new(file_path);

        if path.is_dir() {
            self.scan_directory(file_path, multi_progress)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("jar") {
            self.scan_jar(file_path, multi_progress)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("class") {
            let mut file = File::open(file_path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            if let Some(scan_result) = self.scan_class_file_content(&buffer, file_path) {
                self.print_live_results(&scan_result, multi_progress);
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported file type: {}", file_path),
            ));
        }
        Ok(())
    }

    fn scan_directory(
        &self,
        dir_path: &str,
        multi_progress: &MultiProgress,
    ) -> Result<(), io::Error> {
        for entry in fs::read_dir(dir_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                self.scan_directory(&path.to_string_lossy(), multi_progress)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("jar") {
                self.scan_jar(&path.to_string_lossy(), multi_progress)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("class") {
                let mut file = File::open(&path)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                if let Some(scan_result) =
                    self.scan_class_file_content(&buffer, &path.to_string_lossy())
                {
                    self.print_live_results(&scan_result, multi_progress);
                }
            }
        }
        Ok(())
    }

    fn scan_jar(&self, jar_path: &str, multi_progress: &MultiProgress) -> Result<(), io::Error> {
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
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - {msg}",
                )
                .expect("Failed to create progress bar template")
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Scanning {}", jar_path));

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
                    self.print_live_results(&scan_result, multi_progress);
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message(format!("Finished scanning {}", jar_path));
        Ok(())
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

    fn print_live_results(&self, scan_result: &ScanResult, multi_progress: &MultiProgress) {
        let pb = multi_progress.add(ProgressBar::new(scan_result.matches.len() as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}")
                .expect("Failed to create progress bar template"),
        );

        let file_header = format!("File: {}", scan_result.file_path);
        let separator = "=".repeat(file_header.len());

        let msg = format!("\n{}", file_header.cyan());
        pb.println(msg);
        pb.println(format!("{}", separator.cyan()));

        // Log file header and separator
        if let Some(log_file) = &self.log_file {
            if let Ok(mut log_file) = log_file.lock() {
                let _ = writeln!(log_file, "{}", file_header);
                let _ = writeln!(log_file, "{}", separator);
            }
        }
        for (match_type, matched_string) in &scan_result.matches {
            let msg2 = format!(
                "  Type: {}, Value: {}",
                match_type.green(),
                matched_string.red()
            );
            pb.println(msg2);
            pb.inc(1);

            // Log each match
            if let Some(log_file) = &self.log_file {
                if let Ok(mut log_file) = log_file.lock() {
                    let _ = writeln!(
                        log_file,
                        "  Type: {}, Value: {}",
                        match_type, matched_string
                    );
                }
            }
        }
        pb.finish_and_clear();

        // Log an extra newline for separation between file results in log file
        if let Some(log_file) = &self.log_file {
            if let Ok(mut log_file) = log_file.lock() {
                let _ = writeln!(log_file, ""); // newline
            }
        }
    }
}

fn print_banner() {
    let banner = r#"
   ____      _ _
  / ___|___ | | | __ _ _ __  ___  ___
 | |   / _ \| | |/ _` | '_ \/ __|/ _ \
 | |__| (_) | | | (_| | |_) \__ \  __/
  \____\___/|_|_|\__,_| .__/|___/\___|
                      |_|
  ____
 / ___|  ___ __ _ _ __  _ __   ___ _ __
 \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) | (_| (_| | | | | | | |  __/ |
 |____/ \___\__,_|_| |_|_| |_|\___|_|
    "#;
    for line in banner.lines() {
        println!("{}", line.bold().bright_blue());
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!(
        "\t    version: {}",
        env!("CARGO_PKG_VERSION").bright_magenta()
    );
    println!();
    println!("Fast and efficient JAR/class file scanner for malicious links and IPs\n");
}

fn print_usage(program_name: &str) {
    println!("Usage: {} [OPTIONS] [FILE_OR_DIRECTORY]\n", program_name);
    println!("Options:");
    println!("  -h, --help\t\tPrint this help message and exit.");
    println!("  --log <FILE>\t\tLog the results to a file.");
    println!("\nArguments:");
    println!("  [FILE_OR_DIRECTORY]\tThe JAR file, class file, or directory to scan.");
    println!("\t\t\tIf not provided, the program will prompt for input.");
    println!();
    println!("Scans for suspicious URLs and IP addresses within JAR and class files.");
}

fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    let program_name = &args[0];

    let mut file_path = String::new();
    let mut log_file_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_usage(program_name);
                return Ok(());
            }
            "--log" => {
                i += 1;
                if i < args.len() {
                    log_file_path = Some(args[i].clone());
                } else {
                    eprintln!("Error: --log requires a file path.");
                    print_usage(program_name);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--log requires a file path",
                    ));
                }
            }
            arg if arg.starts_with("-") => {
                eprintln!("Error: Unknown option '{}'.", arg);
                print_usage(program_name);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unknown option",
                ));
            }
            _ => {
                if file_path.is_empty() {
                    file_path = args[i].clone();
                } else {
                    eprintln!("Error: Multiple file/directory paths provided.");
                    print_usage(program_name);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Multiple file paths",
                    ));
                }
            }
        }
        i += 1;
    }

    if file_path.is_empty() {
        print_banner();
    }

    if file_path.is_empty() {
        print!("Enter the path to the JAR file, class file, or directory: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut file_path)?;
        file_path = file_path.trim().to_string();
    }
    if file_path.is_empty() {
        eprintln!("Error: No file or directory path provided.");
        print_usage(program_name);
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "No file path provided",
        ));
    }

    let scanner = CollapseScanner::new(log_file_path)?;
    let multi_progress = MultiProgress::new();

    scanner.scan_file(&file_path, &multi_progress)?;

    Ok(())
}
