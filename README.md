# CollapseScanner

CollapseScanner is a local static scanner for Java artifacts. Point it at a `.jar`, a `.class` file, or a directory, and it will look for the parts you probably want to inspect first.

It does not run the sample. It does not decompile everything into source. It reads class structure, bytecode references, strings, and archive contents, then gives you a short risk-focused report.

## What it looks for

CollapseScanner checks for:

- hardcoded IPv4 and IPv6 addresses
- URLs, suspicious domains, and Discord webhooks
- token-like secrets and hardcoded credentials
- process execution, reflection, dynamic loading, attach APIs, instrumentation, JNA, and `Unsafe`
- high-entropy Base64 or hex blobs
- Unicode name obfuscation
- malformed or tampered class files
- embedded scripts, binaries, native libraries, and suspicious archive entries
- nested archives inside JARs

The goal is triage. If a file is noisy, packed, or reaching out to strange infrastructure, CollapseScanner should make that obvious quickly.

## Install

You need Rust.

```bash
git clone https://github.com/CollapseLoader/CollapseScanner.git
cd CollapseScanner
cargo build --release
```

The binary will be at:

```bash
target/release/collapsescanner
```

## Usage

```bash
# Scan a JAR, class file, or directory
collapsescanner <path>

# Scan only network indicators
collapsescanner <path> --mode network

# Scan only malicious APIs, keywords, and secrets
collapsescanner <path> --mode malicious

# Scan only obfuscation signals
collapsescanner <path> --mode obfuscation

# Write JSON for another tool
collapsescanner <path> --json --output report.json

# Scan only matching entries
collapsescanner mods/ --find "*.class" --exclude "META-INF/*"

# Use a fixed worker count
collapsescanner sample.jar --threads 8
```

## Output

The normal terminal report starts with a summary, then shows:

- risk score
- total findings and affected files
- finding breakdown
- severity distribution
- top files to inspect first
- detailed per-file findings

Example:

```text
Risk: MODERATE RISK (6/10)
Findings: 18 across 7 file(s)
Scanned: 240 file(s) in 1.42s (169.0 files/sec)

Finding breakdown
  [SECRET] Credential or Token [CRITICAL] (1)
      [1] Potential embedded credential: token=ab...A91f (44 chars)

Start here
    [1] com/example/Loader.class (8/10, 4 findings)
```

Use `--json` when you want stable machine-readable output. Use `--output` with or without `--json` to save the same JSON report to disk.

## Modes

`all` runs every detector and is the default.

`network` focuses on URLs, IPs, suspicious infrastructure, and webhooks.

`malicious` focuses on risky APIs, suspicious keywords, encoded payloads, and token-like secrets.

`obfuscation` focuses on class/name weirdness and tampered class indicators.

## Notes

CollapseScanner is static analysis. It will not see behavior that only appears at runtime, and it will not prove that a file is malicious. Treat the score as a triage hint, not a verdict.

It is usually a good first pass before opening a decompiler or running a sample in a sandbox.
