#                                                                     GopherStrike

<p align="center">
  <img src="assets/gopherstrike-logo.png" alt="GopherStrike Logo" width="200"/>
</p>

<p align="center">
  <b>A comprehensive Go-based offensive security framework for red teams and penetration testers.</b>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/yourusername/GopherStrike"><img src="https://goreportcard.com/badge/github.com/yourusername/GopherStrike" alt="Go Report Card"></a>
  <a href="https://github.com/yourusername/GopherStrike/actions"><img src="https://github.com/yourusername/GopherStrike/workflows/build/badge.svg" alt="Build Status"></a>
  <a href="https://codecov.io/gh/yourusername/GopherStrike"><img src="https://codecov.io/gh/yourusername/GopherStrike/branch/main/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/yourusername/GopherStrike/releases"><img src="https://img.shields.io/github/v/release/yourusername/GopherStrike" alt="Latest Release"></a>
</p>

## 🚀 What is GopherStrike?

**GopherStrike combines multiple security tools into a single, fast Go-based framework that security professionals can use for comprehensive offensive security operations.**

### ⚡ Why GopherStrike?

* **All-in-One Toolkit:** Combines port scanning, subdomain enumeration, OSINT, vulnerability scanning, and more in a unified interface
* **Performance-First:** Written in Go for high-performance concurrent operations
* **Easy to Use:** Simple terminal UI with intuitive navigation
* **Extensible:** Modular architecture makes it easy to add new tools
* **Cross-Platform:** Works on Linux, macOS, and Windows

## 📸 GopherStrike in Action

<p align="center">
  <img src="assets/gopherstrike-demo.gif" alt="GopherStrike Demo" width="700"/>
</p>

<details>
  <summary>📊 More Screenshots</summary>
  <p align="center">
    <img src="assets/screenshot-port-scanner.png" alt="Port Scanner" width="700"/>
    <img src="assets/screenshot-subdomain-scanner.png" alt="Subdomain Scanner" width="700"/>
    <img src="assets/screenshot-osint.png" alt="OSINT Tool" width="700"/>
  </p>
</details>

## 🔧 Installation

### Prerequisites

- Go 1.16 or higher
- Git
- Python 3.x (for certain tools)
- Nmap (for port scanning functionality)

### Option 1: Download Binary

```bash
# Download the latest release (replace X.Y.Z with version number)
curl -L https://github.com/TheBitty/GopherStrike/releases/download/vX.Y.Z/gopherstrike-$(uname -s)-$(uname -m) -o gopherstrike

# Make executable
chmod +x gopherstrike

# Run GopherStrike
./gopherstrike
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/TheBitty/GopherStrike.git

# Navigate to the project directory
cd GopherStrike

# Build the project
go build -o gopherstrike

# Run GopherStrike
./gopherstrike
```

### Option 3: Using Go Install

```bash
go install github.com/TheBitty/GopherStrike@latest
```

## 💻 Usage

GopherStrike provides a text-based menu interface for easy tool selection:

```bash
# Launch GopherStrike
./gopherstrike
```

### 🧰 Available Tools

| Tool | Description | Usage |
|------|-------------|-------|
| Port Scanner | Scan and identify open ports on target systems | `1` → Enter target IP/hostname → Select scan type |
| Subdomain Scanner | Discover subdomains of target domains | `2` → Enter target domain → Select scanning method |
| OSINT & Vulnerability Tool | Gather intelligence from public sources | `3` → Enter target → Select OSINT operations |
| Web Application Security Scanner | Find security issues in web applications | `4` → Enter target URL → Select scan type |
| S3 Bucket Scanner | Identify misconfigured S3 buckets | `5` → Enter target domain → Configure scan options |
| Email Harvester | Gather email addresses from a domain | `6` → Enter target domain → Configure search options |
| Directory Bruteforcer | Discover hidden directories on web servers | `7` → Enter target URL → Select wordlist |
| Report Generator | Create detailed security reports | `8` → Select report type and configure options |
| Host & Subdomain Resolver | Resolve hostnames and subdomains | `9` → Enter hostnames or load from file |

### ⚙️ Configuration

GopherStrike supports configuration via both command-line flags and a configuration file:

```bash
# Use a custom configuration file
./gopherstrike --config /path/to/config.yaml

# Enable verbose logging
./gopherstrike --verbose

# Show available configuration options
./gopherstrike --help
```

Default configuration values can be set in `~/.gopherstrike/config.yaml`:

```yaml
# Example configuration
logging:
  level: info
  file: "~/.gopherstrike/logs/gopherstrike.log"
  
tools:
  port_scanner:
    default_timeout: 2s
    threads: 100
  subdomain_scanner:
    wordlist: "~/.gopherstrike/wordlists/subdomains.txt"
    threads: 50
```

## 🛡️ Ethical Use

GopherStrike is designed for legitimate security testing with proper authorization. Users are responsible for complying with applicable laws and regulations. The developers assume no liability for misuse or damage caused by this tool.

## 🤝 Contributing

We welcome contributions! Please check out our [Contributing Guidelines](CONTRIBUTING.md) for details on how to get started.

## 📜 License

GopherStrike is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <i>If you find GopherStrike useful, please consider giving it a star ⭐</i>
</p>
