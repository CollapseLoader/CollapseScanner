use crate::types::{FindingType, ScanResult};
use colored::{ColoredString, Colorize};
use std::collections::HashMap;

fn risk_label(score: u8) -> ColoredString {
    match score {
        s if s >= 8 => "CRITICAL".red().bold(),
        s if s >= 5 => "HIGH".bright_red().bold(),
        s if s >= 3 => "MEDIUM".yellow().bold(),
        _ => "LOW".green().bold(),
    }
}

pub fn print_detailed_file_report(results: &[&ScanResult]) {
    println!("\n{}", "Detailed findings".bright_cyan().bold());

    for result in results {
        if result.matches.is_empty() {
            continue;
        }

        println!("\n  {}", result.file_path.bright_white().bold());

        if let Some(ri) = &result.resource_info {
            if ri.is_dead_class_candidate {
                println!("     [!] Non-standard class marker detected");
            }
        }

        println!(
            "     Risk: {} ({}/10)",
            risk_label(result.danger_score),
            result.danger_score
        );

        let mut grouped: HashMap<FindingType, Vec<String>> = HashMap::new();
        for (ft, value) in result.matches.iter() {
            grouped.entry(*ft).or_default().push(value.clone());
        }

        for ft in &[
            FindingType::DiscordWebhook,
            FindingType::TamperedClass,
            FindingType::SuspiciousUrl,
            FindingType::SuspiciousApi,
            FindingType::CredentialSecret,
            FindingType::EncodedPayload,
            FindingType::IpAddress,
            FindingType::SuspiciousKeyword,
            FindingType::Url,
            FindingType::NativeLibrary,
            FindingType::SuspiciousArchiveEntry,
            FindingType::IpV6Address,
            FindingType::ObfuscationUnicode,
        ] {
            if let Some(values) = grouped.get(ft) {
                let (icon, color) = ft.with_symbol();
                println!(
                    "     {} {} ({})",
                    icon.color(color).bold(),
                    ft.to_string().color(color).bold(),
                    values.len()
                );
                for (idx, value) in values.iter().take(3).enumerate() {
                    println!("        [{}] {}", idx + 1, value);
                }
                if values.len() > 3 {
                    println!("        ... and {} more", values.len() - 3);
                }
            }
        }

        if !result.danger_explanation.is_empty() {
            println!("     Why:");
            for explanation in result.danger_explanation.iter().take(2) {
                println!("        - {}", explanation);
            }
        }
    }
}

pub fn print_severity_matrix(results: &[&ScanResult]) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;

    for result in results {
        match result.danger_score {
            s if s >= 8 => critical += 1,
            s if s >= 5 => high += 1,
            s if s >= 3 => medium += 1,
            _ => low += 1,
        }
    }

    println!("\n{}", "Severity distribution".bright_cyan().bold());
    println!(
        "    {} Critical   {} High   {} Medium   {} Low",
        format!("[{}]", critical).bright_red().bold(),
        format!("[{}]", high).red().bold(),
        format!("[{}]", medium).yellow().bold(),
        format!("[{}]", low).green().bold()
    );

    let total = critical + high + medium + low;
    if total > 0 {
        let bar_width = 50;
        let crit_pct = (critical as f64 / total as f64 * bar_width as f64) as usize;
        let high_pct = (high as f64 / total as f64 * bar_width as f64) as usize;
        let med_pct = (medium as f64 / total as f64 * bar_width as f64) as usize;
        let low_pct = bar_width - crit_pct - high_pct - med_pct;

        print!("    ");
        print!("{}", "#".repeat(crit_pct).red());
        print!("{}", "#".repeat(high_pct).bright_red());
        print!("{}", "#".repeat(med_pct).yellow());
        print!("{}", "#".repeat(low_pct).green());
        println!();
    }
}

pub fn print_finding_statistics(results: &[&ScanResult]) {
    println!("\n{}", "Finding counts".bright_cyan().bold());

    let mut type_stats: HashMap<FindingType, usize> = HashMap::new();

    for result in results {
        for (ft, _) in result.matches.iter() {
            *type_stats.entry(*ft).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = type_stats.iter().collect();
    sorted.sort_by_key(|(_ft, count)| std::cmp::Reverse(**count));

    for (ft, count) in sorted {
        let (icon, color) = ft.with_symbol();
        println!(
            "    {} {} x {}",
            icon.color(color).bold(),
            ft.to_string().color(color),
            count.to_string().bright_white().bold()
        );
    }
}

pub fn print_top_risky_files(results: &[&ScanResult], limit: usize) {
    let mut sorted = results
        .iter()
        .filter(|result| !result.matches.is_empty())
        .copied()
        .collect::<Vec<_>>();

    sorted.sort_by(|a, b| {
        b.danger_score
            .cmp(&a.danger_score)
            .then_with(|| b.matches.len().cmp(&a.matches.len()))
            .then_with(|| a.file_path.cmp(&b.file_path))
    });

    if sorted.is_empty() {
        return;
    }

    println!("\n{}", "Start here".bright_cyan().bold());
    for (idx, result) in sorted.into_iter().take(limit).enumerate() {
        println!(
            "    [{}] {} ({}/10, {} finding{})",
            idx + 1,
            result.file_path.bright_white().bold(),
            result.danger_score,
            result.matches.len(),
            if result.matches.len() == 1 { "" } else { "s" }
        );
    }
}
