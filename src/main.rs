mod config;
mod detection;
mod errors;
mod filters;
mod parser;
mod scanner;
mod types;
mod utils;

#[cfg(feature = "gui")]
mod gui;

#[cfg(all(feature = "cli", not(feature = "gui")))]
use {
    crate::scanner::scan::CollapseScanner,
    crate::types::{DetectionMode, FindingType, ScanResult, ScannerOptions},
    clap::Parser,
    colored::Colorize,
    serde_json::json,
    std::collections::HashMap,
    std::io::{self},
    std::path::{Path, PathBuf},
    walkdir::WalkDir,
};

#[cfg(all(feature = "cli", not(feature = "gui")))]
#[derive(Parser)]
#[clap(
    name = "CollapseScanner",
    author,
    version,
    about = "Advanced JAR/class file analysis and reverse engineering tool",
    long_about = "CollapseScanner is a powerful static analysis tool designed for security researchers, \
                  malware analysts, and developers to analyze Java JAR files and class files. It detects \
                  suspicious patterns, network communications and obfuscation \
                  techniques that may indicate malicious behavior or security vulnerabilities."
)]
struct Args {
    #[clap(value_parser)]
    path: Option<String>,

    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    #[clap(long, value_parser)]
    buffer_size_mb: Option<usize>,

    #[clap(long, value_parser)]
    result_cache_size: Option<usize>,

    #[clap(long, value_parser)]
    safe_string_cache_capacity: Option<usize>,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    parallel_scanning: bool,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    no_parallel_scanning: bool,

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
    available_memory_mb: Option<usize>,

    #[clap(long, value_parser)]
    max_file_size: Option<usize>,

    #[clap(long, action = clap::ArgAction::SetTrue)]
    show: bool,
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
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

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn create_scanner_options(args: &Args) -> ScannerOptions {
    ScannerOptions {
        mode: args.mode,
        verbose: args.verbose,
        ignore_keywords_file: args.ignore_keywords.clone(),
        exclude_patterns: args.exclude.clone(),
        find_patterns: args.find.clone(),
        progress: None,
    }
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn apply_env_overrides(args: &Args) {
    if let Some(mb) = args.buffer_size_mb {
        std::env::set_var("COLLAPSE_BUFFER_SIZE_MB", mb.to_string());
    }

    if let Some(size) = args.result_cache_size {
        std::env::set_var("COLLAPSE_RESULT_CACHE_SIZE", size.to_string());
    }

    if let Some(cap) = args.safe_string_cache_capacity {
        std::env::set_var("COLLAPSE_STRING_CACHE_CAPACITY", cap.to_string());
    }

    if args.parallel_scanning {
        std::env::set_var("COLLAPSE_PARALLEL_SCANNING", "1");
    }

    if args.no_parallel_scanning {
        std::env::set_var("COLLAPSE_PARALLEL_SCANNING", "0");
    }

    if let Some(mb) = args.available_memory_mb {
        std::env::set_var("COLLAPSE_AVAILABLE_MEMORY_OVERRIDE_MB", mb.to_string());
    }
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn configure_threading(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(64 * 1024 * 1024);

    if args.threads > 0 {
        if args.threads > 1024 {
            eprintln!(
                "{} Warning: Thread count {} is very high. Consider using fewer threads (recommended: 1-64).",
                "⚠️".yellow(),
                args.threads
            );
        }
        builder = builder.num_threads(args.threads);
        if args.verbose {
            println!(
                "{} Using {} threads for processing.",
                "🧵".blue(),
                args.threads
            );
        }
    } else if args.verbose {
        println!(
            "{} Using automatic number of threads (Rayon default) with increased stack size.",
            "🧵".blue()
        );
    }

    builder.build_global().map_err(io::Error::other)?;
    Ok(())
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn validate_and_prepare_path(args: &Args) -> Result<PathBuf, Box<dyn std::error::Error>> {
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

    Ok(path)
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
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
            DetectionMode::Malicious => "Malicious code patterns only",
            DetectionMode::Obfuscation => "Obfuscation detection only",
        }
        .dimmed()
    );

    print_optional_configurations(scanner, args);
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
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

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn calculate_scan_score(
    sorted_significant_results: &[&ScanResult],
) -> (u8, &'static str, &'static str) {
    if sorted_significant_results.is_empty() {
        return (1, "green", "MINIMAL RISK");
    }

    let mut weighted_sum: u32 = 0;
    let mut weight_total: u32 = 0;
    let mut max_danger_score: u8 = 0;

    for r in sorted_significant_results {
        let w: u32 = if r.danger_score >= 8 { 5 } else { 1 };
        weighted_sum += (r.danger_score as u32) * w;
        weight_total += w;
        if r.danger_score > max_danger_score {
            max_danger_score = r.danger_score;
        }
    }

    let avg_danger_score = {
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

    (avg_danger_score, score_color, risk_level)
}

#[cfg(feature = "gui")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    gui::app::run_gui()?;
    Ok(())
}

#[cfg(all(not(feature = "gui"), feature = "cli"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_cli()
}

#[cfg(all(feature = "cli", not(feature = "gui")))]
fn run_cli() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    apply_env_overrides(&args);
    let options = create_scanner_options(&args);

    if !args.json {
        print_banner();
    }

    configure_threading(&args)?;

    let scanner = CollapseScanner::new(options.clone())?;
    let path = validate_and_prepare_path(&args)?;

    if !args.json {
        print_scan_configuration(&path, &args, &scanner);
        println!(
            "\n{} {}",
            "🚀".bright_green().bold(),
            "Initializing scan...".bright_green()
        );
    }

    let scan_start_time = std::time::Instant::now();

    match scanner.scan_path(&path) {
        Ok(results) => {
            let significant_results: Vec<&ScanResult> = results
                .iter()
                .filter(|r| !r.matches.is_empty() || scanner.options.verbose)
                .collect();

            if args.json {
                let mut sorted_significant_results = significant_results.clone();
                sorted_significant_results.sort_by_key(|r| &r.file_path);

                let (avg_danger_score, _, risk_level) =
                    calculate_scan_score(&sorted_significant_results);

                let total_findings: usize = sorted_significant_results
                    .iter()
                    .map(|r| r.matches.len())
                    .sum();

                let json_output = json!({
                    "scan_time_seconds": scan_start_time.elapsed().as_secs_f64(),
                    "total_files_scanned": results.len(),
                    "total_findings": total_findings,
                    "risk_level": risk_level,
                    "score": avg_danger_score,
                    "results": sorted_significant_results
                });

                println!("{}", serde_json::to_string_pretty(&json_output)?);
                return Ok(());
            }

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
                    for (finding_type, _) in result.matches.iter() {
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

                    let mut findings_by_type: HashMap<FindingType, Vec<(String, String)>> =
                        HashMap::new();

                    for result in &sorted_significant_results {
                        for (finding_type, value) in result.matches.iter() {
                            findings_by_type
                                .entry(finding_type.clone())
                                .or_default()
                                .push((result.file_path.clone(), value.clone()));
                        }
                    }

                    let mut finding_types: Vec<FindingType> =
                        findings_by_type.keys().cloned().collect();
                    finding_types.sort_by_key(|t| t.to_string());

                    for ftype in &finding_types {
                        let entries = findings_by_type.get(ftype).unwrap();
                        let (icon, color) = ftype.with_emoji();

                        println!(
                            "\n  {} {} ({})",
                            icon.color(color).bold(),
                            ftype.to_string().color(color).bold(),
                            entries.len().to_string().bright_white()
                        );

                        let mut sorted_entries = entries.clone();
                        sorted_entries.sort_by(|a, b| {
                            let file_cmp = a.0.cmp(&b.0);
                            if file_cmp == std::cmp::Ordering::Equal {
                                a.1.cmp(&b.1)
                            } else {
                                file_cmp
                            }
                        });

                        for (file_path, value) in sorted_entries {
                            println!(
                                "    • {}: {}",
                                file_path.bright_cyan(),
                                value.bright_white()
                            );
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
                    let (avg_danger_score, score_color, risk_level) =
                        calculate_scan_score(&sorted_significant_results);

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
                        for (finding_type, value) in result.matches.iter() {
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

                    if !args.show {
                        println!(
                            "\n{} {}",
                            "💡".cyan().bold(),
                            "Tip: Use the '--show' flag to display detailed findings.".cyan()
                        );
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
                        "{} {}: {:.2}s | {}: {:.1} files/sec",
                        "⏱️".bright_white().bold(),
                        "Scan Time".bright_white(),
                        scan_duration.as_secs_f64(),
                        "Processing Rate".bright_white(),
                        scan_rate
                    );
                }
            }

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm && !args.json {
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
        }
        Err(e) => {
            if args.json {
                let error_json = json!({
                    "error": e.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&error_json)?);
                std::process::exit(1);
            }
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
