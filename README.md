# CollapseScanner

**CollapseScanner** - An advanced JAR/class file reverse engineering and analysis tool designed to detect suspicious patterns in Java applications, mods, and plugins.

## 🌟 Features

-   🔍 **Scan multiple detection categories**:
    -   🌐 **Network**: Detect potentially malicious IPs and URLs
    -   🔒 **Crypto**: Find cryptographic implementations and sensitive material
    -   ⚠️ **Malicious**: Identify suspicious code patterns (backdoors, exploits, etc.)
-   📦 **Resource extraction**: Extract all resources from JAR files
-   🔤 **String analysis**: Extract and analyze all strings from class files
-   🔢 **Entropy calculation**: Calculate entropy of files to help identify obfuscated code

## ⚙️ Installation

### From Source

```bash
git clone https://github.com/dest4590/CollapseScanner.git
```

```bash
cargo build --release
```

The binary will be available at target/release/collapsescanner

## 📝 Usage

```bash
# Basic scan of a JAR file
collapsescanner path/to/file.jar

# Scan a directory for all JAR and class files
collapsescanner path/to/directory

# Different detection modes
collapsescanner path/to/file.jar --mode network
collapsescanner path/to/file.jar --mode crypto
collapsescanner path/to/file.jar --mode malicious

# Extract all resources from the JAR
collapsescanner path/to/file.jar --extract

# Extract all strings from class files
collapsescanner path/to/file.jar --strings

# Specify output directory
collapsescanner path/to/file.jar --extract --output path/to/output/dir

# Export analysis to JSON
collapsescanner path/to/file.jar --json
```

## 🔍 Command-line Options

| Option      | Description                                                          |
| ----------- | -------------------------------------------------------------------- |
| `path`      | Path to a JAR file, class file, or directory to scan                 |
| `--mode`    | Detection mode: `network`, `crypto`, `malicious`, or `all` (default) |
| `--extract` | Extract all resources from JAR files                                 |
| `--strings` | Extract all strings from class files                                 |
| `--output`  | Specify the output directory (default: ./extracted)                  |
| `--json`    | Export results in JSON format                                        |

## 🛡️ Detection Capabilities

CollapseScanner analyzes Java class files to find:

-   **Network indicators**:

    -   IP addresses (IPv4)
    -   URLs and domains
    -   Network-related strings

-   **Cryptographic indicators**:

    -   Encryption algorithms (AES, DES, RSA)
    -   Hash functions (MD5, SHA)
    -   Key management and password handling

-   **Suspicious patterns**:
    -   Backdoors
    -   Code injection
    -   Exploits
    -   Payloads
    -   Keyloggers
    -   Data theft mechanisms

## 📋 Example Output

```
==== CollapseScanner - Advanced JAR Reverse Engineering Tool ====
Scanning for suspicious and malicious patterns...

🔍 Found suspicious patterns:

📄 suspicious.jar/com/example/malicious/Payload.class
  🌐 IP Address: 192.168.1.100
  🔗 URL: http://malicious-domain.com/c2
  🔒 Crypto: encrypt: AES encryption used here
  ⚠️ Suspicious: payload: Executing payload

Total: 4 suspicious patterns

📦 Resources extracted to ./extracted
🔤 Strings extracted to ./extracted
```
