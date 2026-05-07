use crate::output::{print_detailed_file_report, print_finding_statistics, print_severity_matrix};
use crate::types::ScanResult;
use colored::Colorize;
use std::fs::File;
use std::io::{self, Write};

pub fn run_interactive_mode(results: &[ScanResult]) {
    let mut significant_results: Vec<&ScanResult> =
        results.iter().filter(|r| !r.matches.is_empty()).collect();

    println!(
        "\n{}",
        "╔══════════════════════════════════════════════════════════════════════════════╗"
            .bright_cyan()
    );
    println!(
        "{}",
        format!("║ {:^76} ║", "INTERACTIVE EXPLORER MODE".bold())
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════════════════════════════════╝"
            .bright_cyan()
    );
    println!("Type 'help' for a list of commands.\n");

    loop {
        print!("{} ", "collapse ~>".bright_green().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }
        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        match parts[0].to_lowercase().as_str() {
            "help" | "?" => {
                println!("\n{}", "Available Commands:".bold());
                println!("  detailed          - Full report for all suspicious files");
                println!("  summary           - Scan summary and severity matrix");
                println!("  files             - List all suspicious files");
                println!("  inspect <idx>     - Inspect specific file by index");
                println!("  sort <risk|path>  - Sort results by danger_score or file_path");
                println!("  export <path.json>- Export findings to JSON");
                println!("  clear             - Clear screen");
                println!("  exit              - Exit explorer");
            }
            "detailed" => print_detailed_file_report(&significant_results),
            "summary" => {
                print_severity_matrix(&significant_results);
                print_finding_statistics(&significant_results);
            }
            "files" => {
                for (i, res) in significant_results.iter().enumerate() {
                    println!("[{}] Risk {} | {}", i + 1, res.danger_score, res.file_path);
                }
            }
            "inspect" => {
                if let Some(idx) = parts.get(1).and_then(|s| s.parse::<usize>().ok()) {
                    if idx > 0 && idx <= significant_results.len() {
                        print_detailed_file_report(&[significant_results[idx - 1]]);
                    } else {
                        println!("Error: Index out of range");
                    }
                }
            }
            "sort" => {
                match parts.get(1).copied().unwrap_or("risk") {
                    "risk" => {
                        significant_results.sort_by_key(|r| std::cmp::Reverse(r.danger_score))
                    }
                    "path" => significant_results.sort_by_key(|r| r.file_path.clone()),
                    _ => println!("Usage: sort <risk|path>"),
                }
                println!("Results sorted by {}.", parts.get(1).unwrap_or(&"risk"));
            }
            "export" => {
                if let Some(path) = parts.get(1) {
                    if let Ok(file) = File::create(path) {
                        if serde_json::to_writer_pretty(file, &significant_results).is_ok() {
                            println!("Exported to {}", path);
                        } else {
                            println!("Error: Export failed");
                        }
                    } else {
                        println!("Error: Cannot create file");
                    }
                } else {
                    println!("Usage: export <file.json>");
                }
            }
            "clear" => print!("{}[2J{}[1;1H", 27 as char, 27 as char),
            "exit" | "quit" | "q" => break,
            _ => println!("Unknown command. Type 'help'."),
        }
    }
}
