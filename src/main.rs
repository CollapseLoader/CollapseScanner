use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use zip::ZipArchive;

pub mod database;

struct Scanner {
    file: String,
    options: Arc<Mutex<HashMap<String, bool>>>,
    links: Arc<Mutex<Vec<(String, String)>>>,
    good_links: Vec<String>,
}

impl Scanner {
    fn new(file: &str, good_links: Vec<String>) -> Self {
        Scanner {
            file: file.to_string(),
            options: Arc::new(Mutex::new(HashMap::new())),
            links: Arc::new(Mutex::new(Vec::new())),
            good_links,
        }
    }

    fn report(&self) -> String {
        let options = self.options.lock().unwrap();
        let options_view = options
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}: {}",
                    key.replace('_', " ").to_uppercase().bold(),
                    if *value { "Yes".green() } else { "No".red() }
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        let links = self.links.lock().unwrap();
        let links_count = links.len();
        let links_list = links
            .iter()
            .map(|(filename, link)| format!("{} | {}", link.blue(), filename.yellow()))
            .collect::<Vec<String>>()
            .join("\n");

        format!(
            "{}: {}\n{}\n\n{}:\n{}",
            "Links Found".bold().green(),
            links_count.to_string().bold(),
            options_view,
            "Detailed Links".bold().green(),
            links_list
        )
    }

    fn scan(&mut self, num_threads: usize) -> String {
        println!("{}", format!("Scanning: {}...", self.file).bold().cyan());

        if !self.file.ends_with(".jar") {
            println!("{}", "File is not a jar executable!".red());
            return String::new();
        }

        let file = File::open(&self.file).unwrap();
        let mut zip = ZipArchive::new(file).unwrap();

        self.process_manifest(&mut zip);
        self.process_files(&mut zip, num_threads);

        self.report()
    }

    fn process_manifest(&mut self, zip: &mut ZipArchive<File>) {
        match zip.by_name("META-INF/MANIFEST.MF") {
            Ok(mut file) => {
                let mut manifest = String::new();
                file.read_to_string(&mut manifest).unwrap();
                if let Some(start) = manifest.find("Main-Class") {
                    let end = manifest[start..].find('\n').unwrap_or(manifest.len());
                    let main_class_info = &manifest[start..start + end];
                    println!("{}", format!("{}", main_class_info).green());
                }
            }
            Err(e) => println!("{}", format!("Error processing manifest: {}", e).red()),
        }
    }

    fn process_files(&mut self, zip: &mut ZipArchive<File>, num_threads: usize) {
        let options = Arc::clone(&self.options);
        let links = Arc::clone(&self.links);

        let mut file_datas = Vec::new();

        for i in 0..zip.len() {
            let mut file = zip.by_index(i).unwrap();
            let filename = file.name().to_string();
            let lower_filename = filename.to_lowercase();

            if lower_filename.contains("net/minecraft") {
                let mut options = options.lock().unwrap();
                options.insert("minecraft".to_string(), true);
            }
            if lower_filename.contains("fabric.mod.json") {
                let mut options = options.lock().unwrap();
                options.insert("fabric".to_string(), true);
            }
            if lower_filename.contains("mods.toml") {
                let mut options = options.lock().unwrap();
                options.insert("forge".to_string(), true);
            }
            if lower_filename.contains("rpc") {
                let mut options = options.lock().unwrap();
                options.insert("discord_RPC".to_string(), true);
            }

            if lower_filename.ends_with(".class") {
                let mut data = Vec::new();
                if let Err(e) = file.read_to_end(&mut data) {
                    println!(
                        "{}",
                        format!("Error reading class file {}: {}", filename, e).red()
                    );
                } else {
                    file_datas.push((filename, data));
                }
            }
        }

        let total_files = file_datas.len() as u64;

        let good_links = self.good_links.clone();

        let mut handles = Vec::new();

        let chunk_size = (total_files as usize + num_threads - 1) / num_threads;

        for chunk in file_datas.chunks(chunk_size) {
            let chunk = chunk.to_owned();
            let links = Arc::clone(&links);
            let good_links = good_links.clone();

            let handle = thread::spawn(move || {
                for (filename, data) in chunk {
                    let data_str = String::from_utf8_lossy(&data);
                    let url_regex =
                        Regex::new(r"\b(?:https?|ftp|ssh|telnet|file)://[^\s/$.?#].[^\s]*\b")
                            .unwrap();
                    let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();

                    for url_match in url_regex.find_iter(&data_str) {
                        let link: String = url_match
                            .as_str()
                            .chars()
                            .filter(|c| c.is_ascii_graphic())
                            .collect();
                        if !good_links.iter().any(|g| link.contains(g)) {
                            let mut links = links.lock().unwrap();
                            links.push((filename.clone(), link.clone()));
                            println!(
                                "{}",
                                format!("Found link: {} | {}", link.cyan(), filename.yellow())
                                    .green()
                            );
                        }
                    }

                    for ip_match in ip_regex.find_iter(&data_str) {
                        let ip_address = ip_match.as_str().to_string();
                        let mut links = links.lock().unwrap();
                        links.push((filename.clone(), ip_address.clone()));
                        println!(
                            "{}",
                            format!(
                                "Found IP address: {} | {}",
                                ip_address.cyan(),
                                filename.yellow()
                            )
                            .green()
                        );
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut log_to_file = false;

    if args.contains(&"--log".to_string()) {
        log_to_file = true;
    }

    println!(
        "\n{} - Multithreading jar scanning tool for links and ips\n{} scanner may not be accurate!\n",
        "CollapseScanner".bold().bright_blue(),
        "warning:".yellow()
    );

    print!("{}", "Enter the path to the jar file: ".bold());
    io::stdout().flush().expect("Failed to flush stdout");
    let mut file_path = String::new();
    io::stdin()
        .read_line(&mut file_path)
        .expect("Failed to read line");
    let file_path = file_path.trim();

    print!("{}", "Enter the number of threads to use (4): ".bold());
    io::stdout().flush().expect("Failed to flush stdout");
    let mut threads_input = String::new();
    io::stdin()
        .read_line(&mut threads_input)
        .expect("Failed to read line");
    let num_threads: usize = threads_input.trim().parse().unwrap_or(4);

    let mut scanner = Scanner::new(file_path, database::GOOD_LINKS.to_vec());
    let report = scanner.scan(num_threads);
    println!("{}", report);

    if log_to_file {
        let mut log_file = File::create("scan_report.log").expect("Failed to create log file");
        log_file
            .write_all(report.as_bytes())
            .expect("Failed to write to log file");
        println!("{}", "Report saved to scan_report.log".green().bold());
    }
}
