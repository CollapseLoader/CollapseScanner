# 🌌 CollapseScanner

**CollapseScanner** is a high-performance, interactive static analysis tool designed for security researchers, malware analysts, and developers. It specializes in deeply inspecting Java JAR and class files to find malicious patterns, ways that data might be stolen, and complex tricks used to hide harmful code.

---

## 🚀 Key Features

- **Deep Inspection** 🔍:
  - **Network Analysis**: Identifies hardcoded IP addresses (IPv4/IPv6) and suspicious URLs.
  - **Malicious Pattern Detection**: Detects process execution (`Runtime.exec`, `ProcessBuilder`), reflection abuse, dynamic class loading, and script engine execution.
  - **Exfiltration Detection**: Specific high-severity detection for Discord Webhooks and external data exfiltration sites.
  - **Encoded Payloads**: Heuristic detection for high-entropy Base64/Hex blobs that often mask malicious payloads.

- **Interactive Explorer** 🖥️:
  - After scanning, enter an interactive CLI session to:
    - View **detailed file analysis** of suspicious files.
    - **Sort** results by risk or path.
    - **Export** findings directly to JSON for external reporting.
    - Navigate findings with a numbered explorer.

- **Performance & Optimization** ⚡:
  - **Multi-threaded Scanning**: Leverages `Rayon` for parallel analysis of JAR entries.
  - **Smart Caching**: Two-level cache (Bloom Filter + LRU) ensures extremely fast processing by skipping redundant scans of known safe strings.
  - **Memory-Adaptive**: Dynamically configures buffer and cache limits based on your system's available RAM.

---

## ⚙️ Installation

### From Source

Requires [Rust](https://rustup.rs/).

```bash
git clone https://github.com/CollapseLoader/CollapseScanner.git
cd CollapseScanner
cargo run --release
```

---

## 📝 Usage

```bash
# Basic scan of a JAR or directory
collapsescanner <path>

# Run with all detection enabled
collapsescanner <path> --mode all

# Run and then enter interactive explorer
collapsescanner <path>
```

### Interactive Commands (once in `collapse>` mode)

| Command              | Description                                     |
| :------------------- | :---------------------------------------------- |
| `detailed`           | Show full reports for all suspicious files      |
| `summary`            | View scan statistics and the severity matrix    |
| `files`              | List all files that contain suspicious findings |
| `inspect <idx>`      | Deep-dive into a specific file by its index     |
| `sort <risk\|path>`  | Sort results by danger level or file path       |
| `export <file.json>` | Save the findings to a JSON file                |
| `clear`              | Clear the terminal window                       |
| `exit`               | Leave the interactive mode                      |

---

## 📊 Detailed Reporting

CollapseScanner provides a multi-stage summary report upon completion:

1. **Severity Matrix**: A visual severity distribution (Critical, High, Medium, Low).
2. **Finding Statistics**: A categorized breakdown of all detections found.
3. **Interactive Explorer**: An easy-to-use CLI to navigate and export findings.

### Example Scan Output

```text
[#] Total Findings: 13 | Files with Findings: 10 | Risk Level: MODERATE RISK (5/10)

[?] Findings Breakdown:
  ⬢ Suspicious Java API [MEDIUM] (3)
      [1] Process execution API usage: Likely running "cmd.exe /c ..."
  ◈ Encoded Payload [LOW] (4)
      [1] High-entropy Base64-like blob (480 chars)

[*] SEVERITY DISTRIBUTION
    [0] Critical   [1] High   [7] Medium   [2] Low
    ██████████████████████████████████████████████████
```

---

## 🛡️ Security & Privacy

- **Static Analysis Only**: No code execution occurs.
- **Local First**: All analysis stays on your machine.
