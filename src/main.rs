#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, CentralPanel, Context, ScrollArea, TextEdit, TopBottomPanel};
use eframe::CreationContext;
use egui::Slider;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use zip::ZipArchive;

pub mod database;

struct Scanner {
    file: String,
    options: Arc<Mutex<HashMap<String, bool>>>,
    links: Arc<Mutex<Vec<(String, String)>>>,
    good_links: Vec<String>,
    log_channel: Arc<Mutex<Vec<String>>>,
}

impl Scanner {
    fn new(file: &str, good_links: Vec<String>, log_channel: Arc<Mutex<Vec<String>>>) -> Self {
        Scanner {
            file: file.to_string(),
            options: Arc::new(Mutex::new(HashMap::new())),
            links: Arc::new(Mutex::new(Vec::new())),
            good_links,
            log_channel,
        }
    }

    fn report(&self) -> String {
        let options = self.options.lock().unwrap();
        let options_view = options
            .iter()
            .map(|(key, value)| {
                format!(
                    "{}: {}",
                    key.replace('_', " ").to_uppercase(),
                    if *value { "Yes" } else { "No" }
                )
            })
            .collect::<Vec<String>>()
            .join("\n");

        let links = self.links.lock().unwrap();
        let links_count = links.len();
        let links_list = links
            .iter()
            .map(|(filename, link)| format!("{} | {}", link, filename))
            .collect::<Vec<String>>()
            .join("\n");

        format!(
            "Links Found: {}\n{}\n\nDetailed Links:\n{}",
            links_count, options_view, links_list
        )
    }

    fn scan(&mut self, num_threads: usize) -> String {
        {
            let mut log_channel = self.log_channel.lock().unwrap();
            log_channel.push(format!("Starting scan: {}...", &self.file));
        }

        if !self.file.ends_with(".jar") {
            let mut log_channel = self.log_channel.lock().unwrap();
            log_channel.push("File is not a JAR executable!".to_string());
            return String::new();
        }

        let file = match File::open(&self.file) {
            Ok(file) => file,
            Err(e) => {
                let mut log_channel = self.log_channel.lock().unwrap();
                log_channel.push(format!("Error opening file: {}", e));
                return String::new();
            }
        };

        let mut zip = match ZipArchive::new(file) {
            Ok(zip) => zip,
            Err(e) => {
                let mut log_channel = self.log_channel.lock().unwrap();
                log_channel.push(format!("Error opening ZIP archive: {}", e));
                return String::new();
            }
        };

        self.process_manifest(&mut zip);
        self.process_files(&mut zip, num_threads);

        self.report()
    }

    fn process_manifest(&mut self, zip: &mut ZipArchive<File>) {
        let mut log_channel = self.log_channel.lock().unwrap();
        match zip.by_name("META-INF/MANIFEST.MF") {
            Ok(mut file) => {
                let mut manifest = String::new();
                if let Err(e) = file.read_to_string(&mut manifest) {
                    log_channel.push(format!("Error reading manifest: {}", e));
                } else {
                    if let Some(start) = manifest.find("Main-Class") {
                        let end = manifest[start..].find('\n').unwrap_or(manifest.len());
                        let main_class_info = &manifest[start..start + end];
                        log_channel.push(format!("Manifest Info: {}", main_class_info));
                    } else {
                        log_channel.push("Main-Class not found in manifest.".to_string());
                    }
                }
            }
            Err(e) => log_channel.push(format!("Error processing manifest: {}", e)),
        }
    }

    fn process_files(&mut self, zip: &mut ZipArchive<File>, num_threads: usize) {
        let options = Arc::clone(&self.options);
        let links = Arc::clone(&self.links);
        let log_channel = Arc::clone(&self.log_channel);

        let mut file_datas = Vec::new();

        {
            let mut log_channel = log_channel.lock().unwrap();
            log_channel.push("Processing files in ZIP archive...".to_string());
        }

        for i in 0..zip.len() {
            let mut file = match zip.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    let mut log_channel = log_channel.lock().unwrap();
                    log_channel.push(format!("Error accessing file at index {}: {}", i, e));
                    continue;
                }
            };
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
                    let mut log_channel = log_channel.lock().unwrap();
                    log_channel.push(format!("Error reading class file {}: {}", filename, e));
                } else {
                    file_datas.push((filename, data));
                }
            }
        }

        let total_files = file_datas.len() as u64;
        let good_links = self.good_links.clone();
        let mut handles = Vec::new();
        let chunk_size = (total_files as usize + num_threads - 1) / num_threads;

        {
            let mut log_channel = log_channel.lock().unwrap();
            log_channel.push(format!(
                "Starting scan with {} threads, {} files to process.",
                num_threads, total_files
            ));
        }

        for chunk in file_datas.chunks(chunk_size) {
            let chunk = chunk.to_owned();
            let links = Arc::clone(&links);
            let good_links = good_links.clone();
            let log_channel = Arc::clone(&log_channel);

            let handle = thread::spawn(move || {
                let url_regex =
                    Regex::new(r"\b(?:https?|ftp|ssh|telnet|file)://[^\s/$.?#].[^\s]*\b").unwrap();
                let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();

                for (filename, data) in chunk {
                    let data_str = String::from_utf8_lossy(&data);

                    for url_match in url_regex.find_iter(&data_str) {
                        let link: String = url_match
                            .as_str()
                            .chars()
                            .filter(|c| c.is_ascii_graphic())
                            .collect();
                        if !good_links.iter().any(|g| link.contains(g)) {
                            let mut links = links.lock().unwrap();
                            links.push((filename.clone(), link.clone()));
                            let mut log_channel = log_channel.lock().unwrap();
                            log_channel
                                .push(format!("Found suspicious URL: {} in {}", link, filename));
                        }
                    }

                    for ip_match in ip_regex.find_iter(&data_str) {
                        let ip_address = ip_match.as_str().to_string();
                        let mut links = links.lock().unwrap();
                        links.push((filename.clone(), ip_address.clone()));
                        let mut log_channel = log_channel.lock().unwrap();
                        log_channel
                            .push(format!("Found IP address: {} in {}", ip_address, filename));
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        {
            let mut log_channel = log_channel.lock().unwrap();
            log_channel.push("Scanning completed.".to_string());
        }
    }
}

pub(crate) fn load_icon() -> egui::IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let icon = include_bytes!("../resources/icon.ico");
        let image = image::load_from_memory(icon)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    egui::IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}

fn main() {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_min_inner_size(egui::vec2(800.0, 400.0))
            .with_inner_size(egui::vec2(800.0, 400.0))
            .with_icon(std::sync::Arc::new(load_icon())),
        ..Default::default()
    };
    eframe::run_native(
        "CollapseScanner",
        native_options,
        Box::new(|cc| Ok(Box::new(MyApp::new(cc)))),
    )
    .unwrap();
}

struct MyApp {
    file_path: String,
    num_threads: usize,
    report: Arc<Mutex<String>>,
    scanning: Arc<AtomicBool>,
    log_channel: Arc<Mutex<Vec<String>>>,
    log_text: String,
    report_text: String,
}

impl MyApp {
    fn new(_cc: &CreationContext) -> Self {
        Self {
            file_path: String::new(),
            num_threads: 4,
            report: Arc::new(Mutex::new(String::new())),
            scanning: Arc::new(AtomicBool::new(false)),
            log_channel: Arc::new(Mutex::new(Vec::new())),
            log_text: String::new(),
            report_text: String::new(),
        }
    }

    fn scan(&mut self, ctx: &Context) {
        self.scanning.store(true, Ordering::SeqCst);
        {
            let mut log_channel = self.log_channel.lock().unwrap();
            log_channel.clear();
            log_channel.push("Initializing scan...".to_string());
        }

        let file_path = self.file_path.clone();
        let num_threads = self.num_threads;
        let good_links = database::GOOD_LINKS
            .iter()
            .map(|&s| s.to_string())
            .collect();
        let log_channel = Arc::clone(&self.log_channel);
        let scanning = Arc::clone(&self.scanning);
        let report = Arc::clone(&self.report);

        let ctx = ctx.clone();

        thread::spawn(move || {
            let mut scanner = Scanner::new(&file_path, good_links, log_channel);
            let generated_report = scanner.scan(num_threads);

            *report.lock().unwrap() = generated_report;
            scanning.store(false, Ordering::SeqCst);

            ctx.request_repaint();
        });
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        for dropped_file in &ctx.input(|i| i.raw.dropped_files.clone()) {
            if let Some(path) = &dropped_file.path {
                self.file_path = path.to_string_lossy().to_string();
                self.scan(ctx);
            }
        }

        self.log_text = self.get_log_text();
        self.report_text = self.get_report_text();

        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                ui.label("File Path:");

                ui.add(
                    egui::TextEdit::singleline(&mut self.file_path)
                        .hint_text("Enter the path to the JAR file or drag and drop here"),
                );

                ui.label("Threads:");
                ui.add(Slider::new(&mut self.num_threads, 1..=64));

                if ui
                    .add_enabled(
                        !self.scanning.load(Ordering::SeqCst),
                        egui::Button::new("Scan"),
                    )
                    .clicked()
                    && !self.scanning.load(Ordering::SeqCst)
                {
                    self.scan(ctx);
                }
            });

            ui.add_space(10.0);
        });

        CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Scanning Logs");
            });
            ui.add_space(5.0);

            ui.group(|ui| {
                ui.set_min_height(200.0);
                ui.push_id(0, |ui| {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.add(
                                TextEdit::multiline(&mut self.log_text)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(10)
                                    // .interactive(false)
                                    .text_color(egui::Color32::LIGHT_BLUE),
                            );
                        });
                });
            });
            ui.add_space(15.0);

            ui.vertical_centered(|ui| {
                ui.heading("Scan Report");
            });
            ui.add_space(5.0);

            ui.group(|ui| {
                ui.set_min_height(200.0);
                ui.push_id(1, |ui| {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            if self.report_text.is_empty() {
                                ui.label("No report available.");
                            } else {
                                ui.add(
                                    TextEdit::multiline(&mut self.report_text)
                                        .font(egui::TextStyle::Monospace)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(10)
                                        .interactive(false),
                                );
                            }
                        });
                });
            });
        });
    }
}

impl MyApp {
    fn get_log_text(&self) -> String {
        let log_channel = self.log_channel.lock().unwrap();
        log_channel.join("\n")
    }

    fn get_report_text(&self) -> String {
        let report = self.report.lock().unwrap();
        report.clone()
    }
}
