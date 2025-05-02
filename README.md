# CollapseScanner

### An advanced JAR/class file reverse engineering and analysis tool designed to detect suspicious patterns in Java applications, mods, and plugins.

---

### ✨ Benefits

-   **Scan multiple detection categories** 🔍:

    -   **Network**: Detect potentially malicious IPv4/IPv6 addresses and URLs
    -   **Crypto**: Find cryptographic implementations and sensitive material
    -   **Malicious**: Identify suspicious code patterns (backdoors, exploits, etc.)
    -   **Obfuscation**: Detect obfuscated code, high entropy, and suspicious naming patterns

-   **Features** ⚙️:

    -   **Resource extraction**: Extract all resources from JAR files
    -   **String analysis**: Extract and analyze all strings from class files
    -   **Entropy calculation**: Calculate entropy of files to help identify obfuscated code

-   **Performance optimizations** 🚀:

    -   **Multi-threading**: Parallel processing of files for faster scanning
    -   **Fast mode**: Stop processing after first suspicious item
    -   **Path filtering**: Include or exclude paths matching patterns
    -   **Custom ignore lists**: Skip specified suspicious or crypto keywords

## ⚙️ Installation

### From Source

```bash
git clone https://github.com/CollapseLoader/CollapseScanner.git
```

```bash
cargo build --release
```

The binary will be available at target/release/collapsescanner

### From Releases

Download the latest release from the [releases page](https://github.com/CollapseLoader/CollapseScanner/releases).

## 📝 Usage

```bash
# Basic scan of a JAR file
collapsescanner file.jar

# Scan a directory for all JAR and class files
collapsescanner directory

# Different detection modes
collapsescanner file.jar --mode network
collapsescanner file.jar --mode crypto
collapsescanner file.jar --mode malicious
collapsescanner file.jar --mode obfuscation

# Extract all resources from the JAR
collapsescanner file.jar --extract

# Extract all strings from class files
collapsescanner file.jar --strings

# Specify output directory
collapsescanner file.jar --extract --output output/dir

# Export analysis to JSON
collapsescanner file.jar --json

# Run with 8 processing threads
collapsescanner file.jar --threads 8

# Path filtering
collapsescanner file.jar --exclude "assets/**" --exclude "*.log" --find "com/example/*"

# Skip specific keywords
collapsescanner file.jar --ignore_keywords_file ignore_keywords.txt
```

## 🔍 Command-line Options

| Option                   | Description                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `path`                   | Path to a JAR file, class file, or directory to scan                                |
| `--mode`                 | Detection mode: `network`, `crypto`, `malicious`, `obfuscation`, or `all` (default) |
| `--extract`              | Extract all resources from JAR files                                                |
| `--strings`              | Extract all strings from class files                                                |
| `--output`               | Specify the output directory (default: ./extracted)                                 |
| `--json`                 | Export results in JSON format                                                       |
| `-v, --verbose`          | Enable verbose output (shows size/entropy, etc.)                                    |
| `--threads`              | Number of threads to use for parallel processing (0 = automatic based on CPU cores) |
| `--exclude`              | Exclude paths matching the wildcard pattern (can be used multiple times)            |
| `--find`                 | Only scan paths matching the wildcard pattern (can be used multiple times)          |
| `--ignore_keywords_file` | Path to a .txt file with keywords to ignore (one per line)                          |

## 🛡️ Detection Capabilities

CollapseScanner analyzes Java class files to find:

-   **Network indicators**:

    -   IP addresses (IPv4 and IPv6)
    -   URLs and domains
    -   Network-related strings

-   **Cryptographic indicators**:

    -   Encryption algorithms (AES, DES, RSA)
    -   Hash functions (MD5, SHA)
    -   Key management and password handling

-   **Obfuscation indicators**:
    -   Excessively long names
    -   Suspicious character sequences
    -   Unicode characters in identifiers
    -   High entropy (potentially obfuscated) files
    -   Custom JVM bytecode detection (unusual magic bytes)

## 🛠️ Tools

<details><summary>Remapper</summary>

**Remapper** - A tool to fix JAR files that have been obfuscated using the "trailing slash" techique, which can cause issues with class decompiling and analysis.

### Usage

```bash
# If running from the source directory
cargo run --bin remapper input.jar output.jar
```

#### Example output:

```s
🔍 Remapper for "trailing slash" technique
📥 Input JAR:  .\obfuscated.jar
📤 Output JAR: output.jar
🔧 Building fixed JAR file...
  [00:00:10] [========================================] 18540/18540 entries
✅ Successfully fixed JAR -> output.jar
```

</details>

## Showcase

<details><summary>📋 Example Output</summary>

```
==== CollapseScanner - Enhanced Analysis ====
🎯 Target: suspicious.jar
🔧 Mode: All
🚀 Starting scan...

⚠️  Findings Report:

📄 File: suspicious.jar/com/example/malicious/Payload.class
  🌐 IPv4 Address: 192.168.1.100
  🌐 IPv6 Address: 9e53:c40f:5969:6a04:68b6:2c98:5c80:25fb
  🔗 URL: http://malicious-domain.com/c2
  🔒 Crypto Keyword: 'encrypt' in "AES encryption used here"
  ❗ Suspicious Keyword: 'payload' in "Executing payload"

==== Scan Summary ====
📈 Total Findings: 4
  - Crypto Keyword: 1
  - IPv4 Address: 1
  - IPv6 Address: 1
  - Suspicious Keyword: 1
  - URL: 1

📦 Resources extracted to ./extracted
🔤 Strings extracted to ./extracted
```

</details>
