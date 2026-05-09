# CollapseScanner

CollapseScanner is a fast, local-first static analysis tool for Java JARs, class files, and archive contents. It is designed for security researchers, malware analysts, and developers who need to triage suspicious Java artifacts quickly without running them.

The scanner focuses on high-signal indicators in Java bytecode, class metadata, strings, and archive structure. It is not a decompiler and not a sandbox. Instead, it is a triage tool that helps you find the parts of a sample worth deeper investigation.

## What it can detect

CollapseScanner groups detections into a few practical categories:

### Network and exfiltration indicators

- IPv4 addresses
- IPv6 addresses
- URLs
- suspicious URLs and domains
- Discord webhooks

These detections are useful for spotting hardcoded infrastructure, command-and-control endpoints, and common exfiltration channels.

### Suspicious Java API usage

CollapseScanner detects Java APIs that are frequently associated with malware, loaders, or advanced evasion logic, including:

- process execution via `Runtime.exec` and `ProcessBuilder`
- reflection usage such as `Class.getDeclaredMethod` and related APIs
- dynamic class loading and class definition
- script engine execution
- Java agent and instrumentation APIs
- JVM attach APIs
- native bridge / low-level APIs such as JNA and `Unsafe`

The scanner also extracts nearby literal arguments from bytecode where possible, which makes findings more actionable. For example, it can surface likely command strings or reflected member names instead of only reporting that an API was used.

### Obfuscation and packing indicators

- high-entropy Base64-like payloads
- high-entropy hex payloads
- Unicode-based obfuscation in class, method, or field names
- tampered or malformed class files

These checks are intended to highlight samples that are intentionally hiding behavior or attempting to break normal tooling.

### Archive and native content indicators

- suspicious archive entries
- native libraries
- package contents that do not look consistent with a normal Java distribution

These findings help identify mixed-language payloads, embedded native components, and archive-level anomalies.

## How it works

CollapseScanner parses Java class structure directly from the class file format and combines several analysis layers:

- constant-pool inspection for strings, classes, methods, and references
- bytecode inspection for method invocation context
- string heuristics for URLs, IPs, commands, and suspicious keywords
- archive and resource inspection for packaging anomalies
- scoring and normalization to rank the most relevant findings

This approach gives the scanner more context than raw string matching alone, while remaining fast enough for archive-scale triage.

## How it compares

### Compared with decompilers such as JADX, CFR, or FernFlower

CollapseScanner is not trying to reconstruct source code. Decompilers are better when you need readable Java or Kotlin output and are willing to inspect code manually. CollapseScanner is better for first-pass triage because it is faster, local, and focused on detection rather than source recovery.

### Compared with generic string scanners or YARA-style rules

String scanners are good at finding literal indicators, but they usually miss context. CollapseScanner understands Java class structure and bytecode enough to attach context to some API calls, which makes it better at identifying why a string matters and where it is used.

### Compared with sandboxing or dynamic analysis

Sandboxes can observe runtime behavior, network traffic, and process creation. CollapseScanner cannot do that. What it offers instead is speed, safety, and offline analysis. It is best used before dynamic analysis, or when you only have static artifacts and want to prioritize the suspicious ones.

### Practical summary

- Use a decompiler when you want to understand control flow and source-like code.
- Use CollapseScanner when you want to triage a lot of Java artifacts quickly and extract suspicious indicators.
- Use a sandbox when you need behavioral confirmation.

## Features

- fast parallel scanning of JARs and class files
- detailed suspicious API detection
- string, URL, IP, and domain analysis
- archive and resource inspection
- interactive CLI explorer after scanning
- JSON export for reporting or downstream tooling
- risk scoring and severity summaries

## Installation

### From source

Requires [Rust](https://rustup.rs/).

```bash
git clone https://github.com/CollapseLoader/CollapseScanner.git
cd CollapseScanner
cargo run --release
```

## Usage

```bash
# Scan a JAR, class file, or directory
collapsescanner <path>

# Run with all detection enabled
collapsescanner <path> --mode all

# Run and then enter the interactive explorer
collapsescanner <path>
```

### Interactive commands

Once CollapseScanner finishes a scan, it can open an interactive CLI for reviewing results.

| Command              | Description                                  |
| -------------------- | -------------------------------------------- |
| `detailed`           | Show full reports for suspicious files       |
| `summary`            | Show scan statistics and the severity matrix |
| `files`              | List files with suspicious findings          |
| `inspect <idx>`      | Inspect a specific result in detail          |
| `sort <risk\|path>`  | Sort results by risk level or file path      |
| `export <file.json>` | Export findings to JSON                      |
| `clear`              | Clear the terminal                           |
| `exit`               | Leave interactive mode                       |

## Reporting

A scan result typically includes:

- the file path
- structured findings with symbols and severity
- class metadata when the target is a Java class
- a danger score and short explanation
- optional JSON output for external analysis pipelines

Example output:

```text
[#] Total Findings: 13 | Files with Findings: 10 | Risk Level: MODERATE RISK (5/10)

[?] Findings Breakdown:
  Suspicious Java API [MEDIUM] (3)
      [1] Process execution API usage: Likely running "cmd.exe /c ..."
  Encoded Payload [LOW] (4)
      [1] High-entropy Base64-like blob (480 chars)

[*] Severity Distribution
    [0] Critical   [1] High   [7] Medium   [2] Low
```

## Limitations

CollapseScanner is intentionally static. It does not execute code, follow live network activity, or fully emulate the JVM. Its job is to identify likely-risky content quickly and give you enough context to decide what to inspect next.

Because of that, the scanner is strongest when used as an initial triage layer before manual review or dynamic analysis.

## Security and privacy

- static analysis only
- no code execution
- local-first processing
