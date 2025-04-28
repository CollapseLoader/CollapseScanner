#![allow(clippy::collapsible_else_if)]

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
use std::path::PathBuf;
use walkdir::WalkDir;

use crate::scanner::CollapseScanner;
use crate::types::{DetectionMode, FindingType, ScanResult, ScannerOptions};

#[derive(Parser)]
#[clap(
    author,
    version,
    about = "CollapseScanner - Advanced JAR/class file analysis and reverse engineering tool"
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
    ignore_suspicious: Option<PathBuf>,

    #[clap(long, value_parser)]
    ignore_crypto: Option<PathBuf>,

    #[clap(long, action = clap::ArgAction::Append, value_parser)]
    exclude: Vec<String>,

    #[clap(long, action = clap::ArgAction::Append, value_parser)]
    find: Vec<String>,

    #[clap(long, value_parser, default_value_t = 0)]
    threads: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let options = ScannerOptions {
        extract_strings: args.strings,
        extract_resources: args.extract,
        output_dir: args
            .output
            .map(PathBuf::from)
            .unwrap_or_else(|| ScannerOptions::default().output_dir),
        export_json: args.json,
        mode: args.mode,
        verbose: args.verbose,
        ignore_suspicious_file: args.ignore_suspicious,
        ignore_crypto_file: args.ignore_crypto,
        exclude_patterns: args.exclude,
        find_patterns: args.find,
    };

    println!(
        "\n{}",
        "==== CollapseScanner - Enhanced Analysis ===="
            .bright_blue()
            .bold()
    );

    if options.extract_resources || options.extract_strings || options.export_json {
        if let Err(e) = fs::create_dir_all(&options.output_dir) {
            eprintln!(
                "{} Failed to create output directory {}: {}",
                "❌".red(),
                options.output_dir.display(),
                e
            );
            return Err(Box::new(e));
        }
    }

    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
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

    let scanner = CollapseScanner::new(options.clone())?;

    if options.verbose
        && (options.extract_resources || options.extract_strings || options.export_json)
    {
        println!(
            "{} Using output directory: {}",
            "➡️".cyan(),
            options.output_dir.display()
        );
    }
    let path_arg = args.path.unwrap_or_else(|| ".".to_string());
    let path = PathBuf::from(&path_arg);
    if !path.exists() {
        eprintln!("{} Path does not exist: {}", "❌".red(), path.display());
        std::process::exit(1);
    }
    println!(
        "{} Target: {}",
        "🎯".green(),
        path.display().to_string().bright_white()
    );
    println!(
        "{} Mode: {}",
        "🔧".yellow(),
        format!("{:?}", args.mode).bright_white()
    );
    if !scanner.options.exclude_patterns.is_empty() {
        println!(
            "{} Exclude Patterns: {}",
            "🚫".yellow(),
            scanner.options.exclude_patterns.join(", ").dimmed()
        );
    }
    if !scanner.options.find_patterns.is_empty() {
        println!(
            "{} Find Patterns: {}",
            "🔍".yellow(),
            scanner.options.find_patterns.join(", ").dimmed()
        );
    }

    if let Some(p) = &scanner.options.ignore_suspicious_file {
        println!(
            "{} Ignoring Suspicious: {}",
            "📄".yellow(),
            p.display().to_string().dimmed()
        );
    }
    if let Some(p) = &scanner.options.ignore_crypto_file {
        println!(
            "{} Ignoring Crypto: {}",
            "📄".yellow(),
            p.display().to_string().dimmed()
        );
    }
    if args.verbose {
        println!("{} Verbose: {}", "🔊".yellow(), "Enabled".bright_white());
    }
    println!("{}", "🚀 Starting scan...".bright_green());

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
                        .map_or(false, |ext| ext == "jar" || ext == "class")
                } else if path.is_dir() {
                    WalkDir::new(&path)
                        .into_iter()
                        .filter_map(|e| e.ok())
                        .any(|e| {
                            e.file_type().is_file()
                                && e.path()
                                    .extension()
                                    .map_or(false, |ext| ext == "jar" || ext == "class")
                        })
                } else {
                    false
                };

                if !potentially_scannable {
                    println!(
                        "\n{}",
                        "🤷 No scannable files (.jar, .class) found in the target path.".yellow()
                    );
                } else if !scanner.options.exclude_patterns.is_empty()
                    || !scanner.options.find_patterns.is_empty()
                {
                    println!(
                        "\n{}",
                        "✅ No findings in files matching filter criteria.".green()
                    );
                } else {
                    println!("\n{}", "✅ No findings matching current criteria.".green());
                }
            } else {
                println!("\n{}", "⚠️  Findings Report:".bright_yellow().bold());
                let mut findings_by_type: HashMap<FindingType, usize> = HashMap::new();
                let mut total_findings = 0;

                let mut sorted_significant_results = significant_results;
                sorted_significant_results.sort_by_key(|r| &r.file_path);

                for result in sorted_significant_results {
                    println!(
                        "\n{}",
                        format!("📄 File: {}", result.file_path).bright_cyan()
                    );
                    if scanner.options.verbose {
                        if let Some(ri) = &result.resource_info {
                            let class_type = if ri.is_class_file {
                                " (Standard Class)"
                            } else if ri.is_dead_class_candidate {
                                " (Custom JVM Class Candidate)"
                            } else if ri.path.ends_with(".class") || ri.path.ends_with(".class/") {
                                " (Non-standard Class File)"
                            } else {
                                ""
                            };
                            println!(
                                "   {} Size: {} bytes, Entropy: {:.2}{}",
                                "📊".dimmed(),
                                ri.size,
                                ri.entropy,
                                class_type.dimmed()
                            );
                        } else if result.class_details.is_some() {
                            println!(
                                "   {} {}",
                                "ℹ️".dimmed(),
                                "(Standard Class - Info Missing)".dimmed()
                            );
                        }
                        if result.matches.is_empty() {
                            println!("   {}", "No specific findings in this file.".dimmed());
                        }
                    }

                    let mut sorted_matches = result.matches.clone();
                    sorted_matches.sort_by_key(|(t, v)| (format!("{}", t), v.clone()));

                    for (finding_type, value) in &sorted_matches {
                        *findings_by_type.entry(finding_type.clone()).or_insert(0) += 1;
                        total_findings += 1;
                        let (icon, color) = match finding_type {
                            FindingType::IpAddress | FindingType::IpV6Address => {
                                ("🌐", "bright_red")
                            }
                            FindingType::Url => ("🔗", "bright_red"),
                            FindingType::Crypto => ("🔒", "bright_yellow"),
                            FindingType::SuspiciousKeyword => ("❗", "red"),
                            FindingType::ObfuscationLongName => ("📏", "bright_magenta"),
                            FindingType::ObfuscationChars => ("❓", "magenta"),
                            FindingType::ObfuscationUnicode => ("㊙️ ", "magenta"),
                            FindingType::HighEntropy => ("🔥", "yellow"),
                        };
                        println!(
                            "  {} {}: {}",
                            icon.color(color).bold(),
                            finding_type.to_string().color(color).bold(),
                            value.bright_white()
                        );
                    }
                }

                println!("\n{}", "==== Scan Summary ====".bright_blue().bold());
                if total_findings > 0 {
                    println!(
                        "{} Total Findings: {}",
                        "📈".yellow(),
                        total_findings.to_string().bright_white().bold()
                    );
                    let mut sorted_findings: Vec<_> = findings_by_type.iter().collect();
                    sorted_findings.sort_by_key(|(k, _)| format!("{}", k));

                    for (finding_type, count) in sorted_findings {
                        let color = match finding_type {
                            FindingType::IpAddress
                            | FindingType::IpV6Address
                            | FindingType::Url
                            | FindingType::SuspiciousKeyword => "bright_red",
                            FindingType::Crypto | FindingType::HighEntropy => "bright_yellow",
                            FindingType::ObfuscationLongName
                            | FindingType::ObfuscationChars
                            | FindingType::ObfuscationUnicode => "bright_magenta",
                        };
                        println!(
                            "  - {}: {}",
                            finding_type.to_string().color(color),
                            count.to_string().bright_white()
                        );
                    }
                } else {
                    println!(
                        "{}",
                        "✅ No specific findings detected based on current criteria.".green()
                    );
                }
            }

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm {
                println!("{}",
                     format!( "{} {}",
                             "👻".cyan().bold(),
                              "Warning: Files starting with unusual magic bytes were detected. These likely require a custom JVM or ClassLoader to execute correctly."
                     ).yellow()
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
                            println!(
                                "\n{} Detailed scan results saved to: {}",
                                "💾".green(),
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
                    "{} Resources extracted to: {}",
                    "📦".green(),
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
                    "{} Strings extracted to: {}",
                    "🔤".green(),
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
            eprintln!("\n{} {}", "❌ Error during scan:".bright_red().bold(), e);
            std::process::exit(1);
        }
    }

    Ok(())
}
