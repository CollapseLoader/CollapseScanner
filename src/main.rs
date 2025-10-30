#![allow(clippy::collapsible_else_if)]

mod config;
mod database;
mod detection;
mod errors;
mod parser;
mod scanner;
mod types;
mod utils;

use clap::Parser;
use colored::*;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::scanner::CollapseScanner;
use crate::types::{DetectionMode, FindingType, ScanResult, ScannerOptions};

#[derive(Parser)]
#[clap(
    name = "CollapseScanner",
    author,
    version,
    about = "Advanced JAR/class file analysis and reverse engineering tool",
    long_about = "CollapseScanner is a powerful static analysis tool designed for security researchers, \
                  malware analysts, and developers to analyze Java JAR files and class files. It detects \
                  suspicious patterns, network communications, cryptographic operations, and obfuscation \
                  techniques that may indicate malicious behavior or security vulnerabilities."
)]
struct Args {
    #[clap(value_parser)]
    path: Option<String>,

    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    #[clap(long)]
    strings: bool,

    #[clap(long)]
    extract: bool,

    #[clap(long, value_parser)]
    output: Option<String>,

    #[clap(long)]
    json: bool,

    #[clap(value_enum, long, default_value = "all")]
    mode: DetectionMode,

    #[clap(long, value_parser)]
    ignore_keywords: Option<PathBuf>,

    #[clap(long, action = clap::ArgAction::Append, value_parser)]
    exclude: Vec<String>,

    #[clap(long, action = clap::ArgAction::Append, value_parser)]
    find: Vec<String>,

    #[clap(long, value_parser, default_value_t = 0)]
    threads: usize,

    #[clap(long, value_parser)]
    max_file_size: Option<usize>,

    #[clap(long)]
    fast_mode: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    show: bool,
}

fn print_banner() {
    println!(
        "\n{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        concat!(
            "║                           CollapseScanner v",
            env!("CARGO_PKG_VERSION"),
            "                             ║"
        )
        .bright_blue()
        .bold()
    );
    println!(
        "{}",
        "║                      Advanced JAR/Class Analysis Tool                        ║"
            .bright_blue()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .bright_blue()
            .bold()
    );
}

fn create_scanner_options(args: &Args) -> ScannerOptions {
    ScannerOptions {
        extract_strings: args.strings,
        extract_resources: args.extract,
        output_dir: args
            .output
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| ScannerOptions::default().output_dir),
        export_json: args.json,
        mode: args.mode,
        verbose: args.verbose,
        ignore_keywords_file: args.ignore_keywords.clone(),
        exclude_patterns: args.exclude.clone(),
        find_patterns: args.find.clone(),
        max_file_size: args.max_file_size.map(|mb| mb * 1024 * 1024),
        fast_mode: args.fast_mode,
    }
}

fn configure_threading(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.threads > 0 {
        if args.threads > 1024 {
            eprintln!(
                "{} Warning: Thread count {} is very high. Consider using fewer threads (recommended: 1-64).",
                "⚠️".yellow(),
                args.threads
            );
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .map_err(io::Error::other)?;
        if args.verbose {
            println!(
                "{} Using {} threads for processing.",
                "🧵".blue(),
                args.threads
            );
        }
    } else if args.verbose {
        println!(
            "{} Using automatic number of threads (Rayon default).",
            "🧵".blue()
        );
    }
    Ok(())
}

fn validate_and_prepare_path(
    args: &Args,
    options: &ScannerOptions,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if options.verbose
        && (options.extract_resources || options.extract_strings || options.export_json)
    {
        println!(
            "{} Using output directory: {}",
            "➡️".cyan(),
            options.output_dir.display()
        );
    }
    let path_arg = args.path.clone().unwrap_or_else(|| ".".to_string());
    let path = PathBuf::from(&path_arg);
    if !path.exists() {
        eprintln!(
            "{} Error: Target path does not exist: {}",
            "❌".red().bold(),
            path.display()
        );
        eprintln!(
            "{} Hint: Check the path spelling and ensure the file/directory exists.",
            "💡".cyan()
        );
        std::process::exit(1);
    }

    if (options.extract_resources || options.extract_strings || options.export_json)
        && !options.output_dir.exists()
    {
        if let Err(e) = fs::create_dir_all(&options.output_dir) {
            eprintln!(
                "{} Error: Failed to create output directory {}: {}",
                "❌".red().bold(),
                options.output_dir.display(),
                e
            );
            std::process::exit(1);
        }
    }
    Ok(path)
}

fn print_scan_configuration(path: &Path, args: &Args, scanner: &CollapseScanner) {
    println!(
        "\n{} {}",
        "🎯".green().bold(),
        "Target:".bright_white().bold()
    );
    println!("   {}", path.display().to_string().bright_white());

    println!(
        "\n{} {}",
        "🔧".yellow().bold(),
        "Detection Mode:".bright_white().bold()
    );
    println!(
        "   {} ({})",
        format!("{:?}", args.mode).bright_white(),
        match args.mode {
            DetectionMode::All => "Comprehensive analysis of all patterns",
            DetectionMode::Network => "Network-related patterns only",
            DetectionMode::Crypto => "Cryptographic patterns only",
            DetectionMode::Malicious => "Malicious code patterns only",
            DetectionMode::Obfuscation => "Obfuscation detection only",
        }
        .dimmed()
    );

    print_optional_configurations(scanner, args);
}

fn print_optional_configurations(scanner: &CollapseScanner, args: &Args) {
    if !scanner.options.exclude_patterns.is_empty() {
        println!(
            "\n{} {}",
            "🚫".yellow().bold(),
            "Exclude Patterns:".bright_white().bold()
        );
        for pattern in &scanner.options.exclude_patterns {
            println!("   • {}", pattern.dimmed());
        }
    }

    if !scanner.options.find_patterns.is_empty() {
        println!(
            "\n{} {}",
            "🔍".yellow().bold(),
            "Find Patterns:".bright_white().bold()
        );
        for pattern in &scanner.options.find_patterns {
            println!("   • {}", pattern.dimmed());
        }
    }

    if let Some(p) = &scanner.options.ignore_keywords_file {
        println!(
            "\n{} {}",
            "📄".yellow().bold(),
            "Ignore Keywords File:".bright_white().bold()
        );
        println!("   {}", p.display().to_string().dimmed());
    }

    if args.verbose {
        println!(
            "\n{} {}",
            "🔊".yellow().bold(),
            "Verbose Mode:".bright_white().bold()
        );
        println!("   {}", "Enabled".bright_white());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let options = create_scanner_options(&args);

    print_banner();

    configure_threading(&args)?;

    let scanner = CollapseScanner::new(options.clone())?;
    let path = validate_and_prepare_path(&args, &options)?;
    print_scan_configuration(&path, &args, &scanner);
    println!(
        "\n{} {}",
        "🚀".bright_green().bold(),
        "Initializing scan...".bright_green()
    );

    let scan_start_time = std::time::Instant::now();

    match scanner.scan_path(&path) {
        Ok(results) => {
            let significant_results: Vec<&ScanResult> = results
                .iter()
                .filter(|r| {
                    !r.matches.is_empty() || scanner.options.export_json || scanner.options.verbose
                })
                .collect();

            if significant_results.is_empty() {
                let potentially_scannable = if path.is_file() {
                    path.extension()
                        .is_some_and(|ext| ext == "jar" || ext == "class")
                } else if path.is_dir() {
                    WalkDir::new(&path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .any(|e| {
                            e.file_type().is_file()
                                && e.path()
                                    .extension()
                                    .is_some_and(|ext| ext == "jar" || ext == "class")
                        })
                } else {
                    false
                };

                println!(
                    "\n{}",
                    "╔══════════════════════════════════════════════════════════════════════════════╗"
                        .bright_blue()
                        .bold()
                );
                println!(
                    "{}",
                    "║                              SCAN RESULTS                                    ║"
                        .bright_blue()
                        .bold()
                );
                println!(
                    "{}",
                    "╚══════════════════════════════════════════════════════════════════════════════╝"
                        .bright_blue()
                        .bold()
                );

                if !potentially_scannable {
                    println!(
                        "\n{} {}",
                        "🤷".yellow().bold(),
                        "No scannable files (.jar, .class) found in the target path.".yellow()
                    );
                } else if !scanner.options.exclude_patterns.is_empty()
                    || !scanner.options.find_patterns.is_empty()
                {
                    println!(
                        "\n{} {}",
                        "✅".green().bold(),
                        "No findings in files matching filter criteria.".green()
                    );
                } else {
                    println!(
                        "\n{} {}",
                        "✅".green().bold(),
                        "No findings matching current criteria.".green()
                    );
                }
            } else {
                let mut findings_by_type: HashMap<FindingType, usize> = HashMap::new();
                let mut total_findings = 0;

                let mut sorted_significant_results = significant_results;
                sorted_significant_results.sort_by_key(|r| &r.file_path);

                for result in &sorted_significant_results {
                    for (finding_type, _) in &result.matches {
                        *findings_by_type.entry(finding_type.clone()).or_insert(0) += 1;
                        total_findings += 1;
                    }
                }

                if args.show {
                    println!(
                    "\n{}",
                    "╔══════════════════════════════════════════════════════════════════════════════╗"
                        .bright_blue()
                        .bold()
                    );
                    println!(
                    "{}",
                    "║                              FINDINGS REPORT                                 ║"
                        .bright_blue()
                        .bold()
                    );
                    println!(
                    "{}",
                    "╚══════════════════════════════════════════════════════════════════════════════╝"
                        .bright_blue()
                        .bold()
                    );

                    for result in &sorted_significant_results {
                        if let Some(ri) = &result.resource_info {
                            let class_type = if ri.is_dead_class_candidate {
                                " (Custom JVM Class Candidate)"
                            } else {
                                ""
                            };

                            println!(
                                "\n{} {}",
                                "📄".bright_cyan().bold(),
                                format!("File: {}{}", result.file_path, class_type)
                                    .bright_cyan()
                                    .bold()
                            );

                            if scanner.options.verbose {
                                println!(
                                    "   {} Size: {} bytes | Entropy: {:.2} | Danger Score: {}/10",
                                    "📊".dimmed(),
                                    ri.size,
                                    ri.entropy,
                                    result.danger_score
                                );

                                if result.matches.is_empty() {
                                    println!(
                                        "   {}",
                                        "No specific findings in this file.".dimmed()
                                    );
                                }
                            }
                        } else if result.class_details.is_some() {
                            println!(
                                "   {} {}",
                                "ℹ️".dimmed(),
                                "(Standard Class - Info Missing)".dimmed()
                            );
                        }

                        let mut sorted_matches = result.matches.clone();
                        sorted_matches.sort_by_key(|(t, v)| (format!("{}", t), v.clone()));

                        for (finding_type, value) in &sorted_matches {
                            let (icon, color) = finding_type.with_emoji();

                            println!(
                                "     {} {}: {}",
                                icon.color(color).bold(),
                                finding_type.to_string().color(color).bold(),
                                value.bright_white()
                            );
                        }

                        if scanner.options.verbose && !result.danger_explanation.is_empty() {
                            println!("     {} Risk Assessment:", "⚠️".yellow().bold());
                            for explanation in &result.danger_explanation {
                                println!("        • {}", explanation.dimmed());
                            }
                        }
                    }
                }

                println!(
                    "\n{}",
                    "╔══════════════════════════════════════════════════════════════════════════════╗"
                        .bright_blue()
                        .bold()
                );
                println!(
                    "{}",
                    "║                              SCAN SUMMARY                                    ║"
                        .bright_blue()
                        .bold()
                );
                println!(
                    "{}",
                    "╚══════════════════════════════════════════════════════════════════════════════╝"
                        .bright_blue()
                        .bold()
                );

                if total_findings > 0 {
                    let files_with_findings = sorted_significant_results.len();
                    let mut weighted_sum: u32 = 0;
                    let mut weight_total: u32 = 0;
                    let mut max_danger_score: u8 = 0;
                    for r in &sorted_significant_results {
                        let w: u32 = if r.danger_score >= 8 { 5 } else { 1 };
                        weighted_sum += (r.danger_score as u32) * w;
                        weight_total += w;
                        if r.danger_score > max_danger_score {
                            max_danger_score = r.danger_score;
                        }
                    }

                    let avg_danger_score = if !sorted_significant_results.is_empty() {
                        let weighted_avg = if weight_total > 0 {
                            (weighted_sum as f32 / weight_total as f32).round() as u8
                        } else {
                            1
                        };
                        if max_danger_score == 10 {
                            10
                        } else {
                            std::cmp::max(weighted_avg, max_danger_score).clamp(1, 10)
                        }
                    } else {
                        1
                    };

                    let score_color = match avg_danger_score {
                        1 => "green",
                        2 => "bright_green",
                        3 => "cyan",
                        4 => "bright_cyan",
                        5 => "yellow",
                        6 => "bright_yellow",
                        7 => "magenta",
                        8 => "red",
                        9 => "red",
                        10 => "red",
                        _ => "green",
                    };

                    let risk_level = match avg_danger_score {
                        8..=10 => "HIGH RISK",
                        5..=7 => "MODERATE RISK",
                        3..=4 => "LOW RISK",
                        _ => "MINIMAL RISK",
                    };

                    let scan_duration = scan_start_time.elapsed();
                    let total_files_scanned = results.len();
                    let scan_rate = if scan_duration.as_secs_f64() > 0.0 {
                        total_files_scanned as f64 / scan_duration.as_secs_f64()
                    } else {
                        0.0
                    };

                    println!(
                        "\n{} {}: {} | {}: {} | {}: {} ({}/10)",
                        "📊".bright_white().bold(),
                        "Total Findings".bright_white(),
                        total_findings.to_string().bright_white().bold(),
                        "Files with Findings".bright_white(),
                        files_with_findings.to_string().bright_white(),
                        "Risk Level".bright_white(),
                        risk_level.color(score_color).bold(),
                        avg_danger_score
                    );

                    println!(
                        "{} {}: {:.2}s | {}: {} | {}: {:.1} files/sec",
                        "⏱️".bright_white().bold(),
                        "Scan Time".bright_white(),
                        scan_duration.as_secs_f64(),
                        "Total Files Scanned".bright_white(),
                        total_files_scanned.to_string().bright_white(),
                        "Processing Rate".bright_white(),
                        scan_rate
                    );

                    println!(
                        "\n{} {}",
                        "🔍".yellow().bold(),
                        "Findings Breakdown:".yellow().bold()
                    );

                    let mut all_findings: HashMap<FindingType, std::collections::HashSet<String>> =
                        HashMap::new();

                    for result in &sorted_significant_results {
                        for (finding_type, value) in &result.matches {
                            all_findings
                                .entry(finding_type.clone())
                                .or_default()
                                .insert(value.clone());
                        }
                    }

                    for (finding_type, values) in &all_findings {
                        let (icon, color) = finding_type.with_emoji();

                        println!(
                            "\n  {} {} ({})",
                            icon.color(color).bold(),
                            finding_type.to_string().color(color).bold(),
                            values.len().to_string().bright_white()
                        );

                        let mut sorted_values: Vec<&String> = values.iter().collect();
                        sorted_values.sort();

                        for (i, value) in sorted_values.iter().enumerate() {
                            if i < 5 {
                                println!("    • {}", value.bright_white());
                            } else if i == 5 {
                                println!(
                                    "    • ... and {} more",
                                    (values.len() - 5).to_string().dimmed()
                                );
                                break;
                            }
                        }
                    }
                } else {
                    let scan_duration = scan_start_time.elapsed();
                    let total_files_scanned = results.len();
                    let scan_rate = if scan_duration.as_secs_f64() > 0.0 {
                        total_files_scanned as f64 / scan_duration.as_secs_f64()
                    } else {
                        0.0
                    };

                    println!(
                        "\n{} {}",
                        "✅".green().bold(),
                        "No specific findings detected based on current criteria.".green()
                    );

                    println!(
                        "{} {}: {:.2}s | {}: {} | {}: {:.1} files/sec",
                        "⏱️".bright_white().bold(),
                        "Scan Time".bright_white(),
                        scan_duration.as_secs_f64(),
                        "Total Files Scanned".bright_white(),
                        total_files_scanned.to_string().bright_white(),
                        "Processing Rate".bright_white(),
                        scan_rate
                    );
                }
            }

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm {
                println!(
                    "\n{} {}",
                    "👻".cyan().bold(),
                    "Custom JVM Warning:".yellow().bold()
                );
                println!(
                    "   {}",
                    "Files with unusual magic bytes detected. These may require custom JVM or ClassLoader.".yellow()
                );
            }

            if scanner.options.export_json {
                let json_output_path = scanner.options.output_dir.join(format!(
                    "{}_scan_results.json",
                    path.file_stem()
                        .unwrap_or_else(|| std::ffi::OsStr::new("scan"))
                        .to_string_lossy()
                ));
                let mut sorted_results = results;
                sorted_results.sort_by_key(|r| r.file_path.clone());
                let json_data = serde_json::to_string_pretty(&sorted_results)?;

                match File::create(&json_output_path) {
                    Ok(mut json_file) => {
                        if let Err(e) = json_file.write_all(json_data.as_bytes()) {
                            eprintln!(
                                "{} Error writing JSON results to {}: {}",
                                "⚠️".yellow(),
                                json_output_path.display(),
                                e
                            );
                        } else {
                            println!("\n{} {}", "💾".green().bold(), "Export Complete:".green());
                            println!(
                                "   JSON results saved to: {}",
                                json_output_path.display().to_string().bright_white()
                            );
                        }
                    }
                    Err(e) => eprintln!(
                        "{} Error creating JSON results file {}: {}",
                        "⚠️".yellow(),
                        json_output_path.display(),
                        e
                    ),
                }
            }
            if scanner.options.extract_resources {
                println!(
                    "\n{} {}",
                    "📦".green().bold(),
                    "Extraction Complete:".green()
                );
                println!(
                    "   Resources extracted to: {}",
                    scanner
                        .options
                        .output_dir
                        .display()
                        .to_string()
                        .bright_white()
                );
            }
            if scanner.options.extract_strings {
                println!(
                    "\n{} {}",
                    "🔤".green().bold(),
                    "Extraction Complete:".green()
                );
                println!(
                    "   Strings extracted to: {}",
                    scanner
                        .options
                        .output_dir
                        .display()
                        .to_string()
                        .bright_white()
                );
            }
        }
        Err(e) => {
            eprintln!("\n{} {}", "❌ Error during scan:".red().bold(), e);
            if options.verbose {
                eprintln!(
                    "{} Debug info: This error occurred while processing the target path.",
                    "🔍".dimmed()
                );
                eprintln!("{} Check file permissions, disk space, and ensure JAR/class files are not corrupted.", "💡".cyan());
            }
            std::process::exit(1);
        }
    }

    Ok(())
}
