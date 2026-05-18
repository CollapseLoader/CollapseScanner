mod config;
mod detection;
mod errors;
mod filters;
mod output;
mod parser;
mod scanner;
mod types;
mod utils;

use {
    crate::output::{
        print_detailed_file_report, print_finding_statistics, print_severity_matrix,
        print_top_risky_files,
    },
    crate::scanner::scan::CollapseScanner,
    crate::types::{DetectionMode, FindingType, ScanResult, ScannerOptions},
    clap::Parser,
    colored::Colorize,
    serde_json::json,
    std::collections::{HashMap, HashSet},
    std::fs,
    std::io::{self},
    std::path::{Path, PathBuf},
    std::time::Duration,
    walkdir::WalkDir,
};

#[derive(Parser)]
#[clap(
    name = "CollapseScanner",
    author,
    version,
    about = "Static triage for Java JARs, class files, and nested archive contents",
    long_about = "CollapseScanner inspects Java artifacts without running them. It looks for risky APIs, hardcoded infrastructure, token-like secrets, obfuscation, native payloads, and archive anomalies."
)]
struct Args {
    #[clap(value_parser, help = "JAR, class file, or directory to scan")]
    path: Option<String>,

    #[clap(short, long, action = clap::ArgAction::SetTrue, help = "Print parser and scanning details")]
    verbose: bool,

    #[clap(long, hide = true)]
    strings: bool,

    #[clap(long, hide = true)]
    extract: bool,

    #[clap(long, value_parser, help = "Write a JSON report to this path")]
    output: Option<String>,

    #[clap(
        long,
        help = "Print machine-readable JSON instead of the terminal report"
    )]
    json: bool,

    #[clap(
        value_enum,
        long,
        default_value = "all",
        help = "Detection group to run"
    )]
    mode: DetectionMode,

    #[clap(long, value_parser, help = "File with suspicious keywords to suppress")]
    ignore_keywords: Option<PathBuf>,

    #[clap(long, action = clap::ArgAction::Append, value_parser, help = "Skip paths matching this wildcard pattern")]
    exclude: Vec<String>,

    #[clap(long, action = clap::ArgAction::Append, value_parser, help = "Only scan paths matching this wildcard pattern")]
    find: Vec<String>,

    #[clap(
        long,
        value_parser,
        default_value_t = 0,
        help = "Worker threads to use; 0 lets Rayon decide"
    )]
    threads: usize,
}

const BANNER_BOX: &str =
    "+------------------------------------------------------------------------------+";
const BANNER_BOTTOM: &str =
    "+------------------------------------------------------------------------------+";

fn print_banner() {
    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!(
        "{}",
        concat!(
            "|                           CollapseScanner v",
            env!("CARGO_PKG_VERSION"),
            "                             |"
        )
        .bright_blue()
        .bold()
    );
    println!(
        "{}",
        "|                     Java artifact triage, without execution                   |"
            .bright_blue()
            .bold()
    );
    println!("{}", BANNER_BOTTOM.bright_blue().bold());
}

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

fn configure_threading(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(64 * 1024 * 1024);

    if args.threads > 0 {
        if args.threads > 1024 {
            eprintln!(
                "(!) Thread count {} is very high. A range around 1-64 is usually enough.",
                args.threads
            );
        }
        builder = builder.num_threads(args.threads);
        if args.verbose {
            println!("[*] Using {} worker thread(s).", args.threads);
        }
    } else if args.verbose {
        println!("[*] Using Rayon default worker count.");
    }

    builder.build_global().map_err(io::Error::other)?;
    Ok(())
}

fn validate_and_prepare_path(args: &Args) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path_arg = args.path.clone().unwrap_or_else(|| ".".to_string());
    let path = PathBuf::from(&path_arg);
    if !path.exists() {
        eprintln!("[X] Target path does not exist: {}", path.display());
        eprintln!("[i] Check the path spelling and try again.");
        std::process::exit(1);
    }
    Ok(path)
}

fn mode_description(mode: DetectionMode) -> &'static str {
    match mode {
        DetectionMode::All => "all checks",
        DetectionMode::Network => "network indicators",
        DetectionMode::Malicious => "malicious APIs, keywords, and secrets",
        DetectionMode::Obfuscation => "obfuscation indicators",
    }
}

fn print_scan_configuration(path: &Path, args: &Args, scanner: &CollapseScanner) {
    println!("\n{}", "Scan setup".bright_white().bold());
    println!("  Target : {}", path.display().to_string().bright_white());
    println!(
        "  Mode   : {} ({})",
        args.mode.to_string().bright_white(),
        mode_description(args.mode).dimmed()
    );

    print_optional_configurations(scanner, args);
}

fn print_optional_configurations(scanner: &CollapseScanner, args: &Args) {
    if !scanner.options.exclude_patterns.is_empty() {
        println!("  Exclude:");
        for pattern in &scanner.options.exclude_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if !scanner.options.find_patterns.is_empty() {
        println!("  Match only:");
        for pattern in &scanner.options.find_patterns {
            println!("    - {}", pattern.dimmed());
        }
    }

    if let Some(p) = &scanner.options.ignore_keywords_file {
        println!("  Ignore : {}", p.display().to_string().dimmed());
    }

    if args.verbose {
        println!("  Verbose: {}", "enabled".bright_white());
    }
}

fn calculate_scan_score(results: &[&ScanResult]) -> (u8, &'static str, &'static str) {
    if results.is_empty() {
        return (1, "green", "MINIMAL RISK");
    }

    let mut weighted_sum: u32 = 0;
    let mut weight_total: u32 = 0;
    let mut max_danger_score: u8 = 0;

    for result in results {
        let weight = if result.danger_score >= 8 { 5 } else { 1 };
        weighted_sum += (result.danger_score as u32) * weight;
        weight_total += weight;
        max_danger_score = max_danger_score.max(result.danger_score);
    }

    let weighted_avg = (weighted_sum as f32 / weight_total as f32).round() as u8;
    let score = if max_danger_score == 10 {
        10
    } else {
        weighted_avg.max(max_danger_score).clamp(1, 10)
    };

    let score_color = match score {
        1 => "green",
        2 => "bright_green",
        3 => "cyan",
        4 => "bright_cyan",
        5 => "yellow",
        6 => "bright_yellow",
        7 => "magenta",
        8..=10 => "red",
        _ => "green",
    };

    let risk_level = match score {
        8..=10 => "HIGH RISK",
        5..=7 => "MODERATE RISK",
        3..=4 => "LOW RISK",
        _ => "MINIMAL RISK",
    };

    (score, score_color, risk_level)
}

fn print_section_header(title: &str) {
    println!("\n{}", BANNER_BOX.bright_blue().bold());
    println!("{}", format!("| {:<76} |", title).bright_blue().bold());
    println!("{}", BANNER_BOTTOM.bright_blue().bold());
}

fn format_scan_stats(duration: Duration, total_files: usize) -> (f64, f64) {
    let scan_time = duration.as_secs_f64();
    let scan_rate = if scan_time > 0.0 {
        total_files as f64 / scan_time
    } else {
        0.0
    };
    (scan_time, scan_rate)
}

fn build_json_report(
    results: &[ScanResult],
    significant_results: &[&ScanResult],
    elapsed: Duration,
) -> serde_json::Value {
    let (score, _, risk_level) = calculate_scan_score(significant_results);
    let total_findings: usize = significant_results.iter().map(|r| r.matches.len()).sum();

    json!({
        "scan_time_seconds": elapsed.as_secs_f64(),
        "total_files_scanned": results.len(),
        "files_with_findings": significant_results.len(),
        "total_findings": total_findings,
        "risk_level": risk_level,
        "score": score,
        "results": significant_results
    })
}

fn write_json_report(
    output_path: &str,
    report: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(output_path, serde_json::to_string_pretty(report)?)?;
    Ok(())
}

fn has_scannable_files(path: &Path) -> bool {
    if path.is_file() {
        return path
            .extension()
            .is_some_and(|ext| ext == "jar" || ext == "class");
    }

    if path.is_dir() {
        return WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                e.file_type().is_file()
                    && e.path()
                        .extension()
                        .is_some_and(|ext| ext == "jar" || ext == "class")
            });
    }

    false
}

fn collect_finding_stats(
    results: &[&ScanResult],
) -> (usize, HashMap<FindingType, HashSet<String>>) {
    let mut total_findings = 0;
    let mut all_findings: HashMap<FindingType, HashSet<String>> = HashMap::new();

    for result in results {
        for (finding_type, value) in result.matches.iter() {
            total_findings += 1;
            all_findings
                .entry(*finding_type)
                .or_default()
                .insert(value.clone());
        }
    }

    (total_findings, all_findings)
}

fn print_finding_breakdown(all_findings: &HashMap<FindingType, HashSet<String>>) {
    println!("\n{}", "Finding breakdown".bright_white().bold());

    let mut sorted_types: Vec<_> = all_findings.keys().collect();
    sorted_types.sort_by_key(|ft| std::cmp::Reverse(ft.base_score()));

    for finding_type in sorted_types {
        let values = &all_findings[finding_type];
        let (icon, color) = finding_type.with_symbol();
        let severity = match finding_type.base_score() {
            score if score >= 8 => "CRITICAL",
            score if score >= 5 => "HIGH",
            score if score >= 3 => "MEDIUM",
            _ => "LOW",
        };

        println!(
            "\n  {} {} [{}] ({})",
            icon.color(color).bold(),
            finding_type.to_string().color(color).bold(),
            severity.color(color).bold(),
            values.len().to_string().bright_white()
        );

        let mut sorted_values: Vec<&String> = values.iter().collect();
        sorted_values.sort();

        for (idx, value) in sorted_values.iter().take(10).enumerate() {
            println!("      [{}] {}", idx + 1, value.bright_white());
        }
        if sorted_values.len() > 10 {
            println!("      ... and {} more", sorted_values.len() - 10);
        }
    }
}

fn print_empty_scan_result(path: &Path, scanner: &CollapseScanner) {
    print_section_header("SCAN RESULTS");

    if !has_scannable_files(path) {
        println!(
            "\n[-] {}",
            "No .jar or .class files were found in the target path.".yellow()
        );
    } else if !scanner.options.exclude_patterns.is_empty()
        || !scanner.options.find_patterns.is_empty()
    {
        println!(
            "\n[+] {}",
            "No findings in files that matched your filters.".green()
        );
    } else {
        println!("\n[+] {}", "No findings for the selected mode.".green());
    }
}

fn print_text_report(
    results: &[ScanResult],
    significant_results: Vec<&ScanResult>,
    path: &Path,
    scanner: &CollapseScanner,
    elapsed: Duration,
) {
    if significant_results.is_empty() {
        print_empty_scan_result(path, scanner);
        return;
    }

    let mut sorted_results = significant_results;
    sorted_results.sort_by_key(|r| &r.file_path);

    let (total_findings, all_findings) = collect_finding_stats(&sorted_results);

    print_section_header("SCAN SUMMARY");

    if total_findings == 0 {
        let (scan_time, scan_rate) = format_scan_stats(elapsed, results.len());
        println!(
            "\n[+] {}",
            "No specific findings in the selected mode.".green()
        );
        println!(
            "[*] Scan time: {:.2}s | Processing rate: {:.1} files/sec",
            scan_time, scan_rate
        );
        return;
    }

    let (score, score_color, risk_level) = calculate_scan_score(&sorted_results);
    let (scan_time, scan_rate) = format_scan_stats(elapsed, results.len());

    println!(
        "\nRisk: {} ({}/10)",
        risk_level.color(score_color).bold(),
        score
    );
    println!(
        "Findings: {} across {} file(s)",
        total_findings.to_string().bright_white().bold(),
        sorted_results.len().to_string().bright_white().bold()
    );
    println!(
        "Scanned: {} file(s) in {:.2}s ({:.1} files/sec)",
        results.len().to_string().bright_white(),
        scan_time,
        scan_rate
    );

    print_finding_breakdown(&all_findings);
    print_severity_matrix(&sorted_results);
    print_finding_statistics(&sorted_results);
    print_top_risky_files(&sorted_results, 8);
    print_detailed_file_report(&sorted_results);
}

fn handle_json_output(
    args: &Args,
    results: &[ScanResult],
    significant_results: &[&ScanResult],
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sorted_results = significant_results.to_vec();
    sorted_results.sort_by_key(|r| &r.file_path);

    let json_output = build_json_report(results, &sorted_results, elapsed);
    if let Some(output_path) = &args.output {
        write_json_report(output_path, &json_output)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&json_output)?);
    }

    Ok(())
}

fn maybe_write_text_mode_json_report(
    args: &Args,
    results: &[ScanResult],
    scanner: &CollapseScanner,
    elapsed: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(output_path) = &args.output {
        let mut output_results: Vec<&ScanResult> = results
            .iter()
            .filter(|r| !r.matches.is_empty() || scanner.options.verbose)
            .collect();
        output_results.sort_by_key(|r| &r.file_path);

        let report = build_json_report(results, &output_results, elapsed);
        write_json_report(output_path, &report)?;
        println!(
            "\n[+] JSON report written to {}",
            output_path.bright_white()
        );
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let options = create_scanner_options(&args);

    if !args.json {
        print_banner();
    }

    configure_threading(&args)?;

    let scanner = CollapseScanner::new(options.clone())?;
    let path = validate_and_prepare_path(&args)?;

    if !args.json {
        print_scan_configuration(&path, &args, &scanner);
        println!("\n>>> {}", "Scanning...".bright_green());
    }

    let scan_start_time = std::time::Instant::now();

    match scanner.scan_path(&path) {
        Ok(results) => {
            let elapsed = scan_start_time.elapsed();
            let significant_results: Vec<&ScanResult> = results
                .iter()
                .filter(|r| !r.matches.is_empty() || scanner.options.verbose)
                .collect();

            if args.json {
                handle_json_output(&args, &results, &significant_results, elapsed)?;
                return Ok(());
            }

            print_text_report(&results, significant_results, &path, &scanner, elapsed);

            let found_custom_jvm = *scanner.found_custom_jvm_indicator.lock().unwrap();
            if found_custom_jvm {
                println!("\n(!) {}", "Custom JVM warning".yellow().bold());
                println!(
                    "   {}",
                    "Some class files use unusual magic bytes. Review them with custom ClassLoader behavior in mind.".yellow()
                );
            }

            maybe_write_text_mode_json_report(&args, &results, &scanner, elapsed)?;
        }
        Err(error) => {
            if args.json {
                let error_json = json!({
                    "error": error.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&error_json)?);
                std::process::exit(1);
            }

            eprintln!("\n[X] {}", "Scan failed".red().bold());
            eprintln!("   {}", error);
            if options.verbose {
                eprintln!("   [i] Check file permissions, disk space, and archive integrity.");
            }
            std::process::exit(1);
        }
    }

    Ok(())
}
