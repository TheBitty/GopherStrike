# GopherStrike InfoTracker - OSINT & Vulnerability Tool

## Overview

InfoTracker is a comprehensive OSINT (Open Source Intelligence) and vulnerability management tool built for the GopherStrike framework. It allows security researchers to look up vulnerabilities, gather server and firmware information, and correlate scan results with known vulnerabilities.

## Features

- **Vulnerability Database Integration**: Query and search the National Vulnerability Database (NVD) for CVEs
- **Server Information Gathering**: Collect and analyze server products, versions, and EOL status
- **Firmware Analysis**: Track device firmware details and identify potential vulnerabilities
- **Correlation Engine**: Match scan results against known vulnerabilities with confidence scoring
- **Risk Assessment**: Calculate overall risk scores based on vulnerabilities and system status

## Usage

### Main Menu

The tool offers the following main functions:

1. **Lookup Vulnerability**: Search for vulnerabilities by CVE ID, keywords, or product
2. **Gather Server Information**: Collect information about a server by analyzing its ports and responses
3. **Gather Firmware Information**: Enter firmware details to check for vulnerabilities
4. **Correlate Scan Results**: Match previous scan results with the vulnerability database
5. **Settings**: Configure API keys, confidence thresholds, and output formats

### Vulnerability Lookup

This feature allows you to search for vulnerabilities in several ways:

- **By CVE ID**: Look up a specific vulnerability (e.g., CVE-2021-44228)
- **By Keywords**: Search for vulnerabilities related to specific terms
- **By Product**: Find vulnerabilities affecting a particular product and version

### Server Information Gathering

Collect information about a server, including:

- Operating system and version
- Server products and versions
- Open ports and services
- HTTP headers and banners
- EOL (End of Life) status

The tool automatically correlates this information with the vulnerability database to identify potential vulnerabilities.

### Firmware Information

Enter details about device firmware to check for known vulnerabilities:

- Device type (router, switch, camera, etc.)
- Manufacturer and model
- Firmware version and release date
- EOL status

### Correlation Features

The correlation engine matches server and firmware information against known vulnerabilities using:

- Product and version matching
- OS detection
- EOL status checking
- Weighted confidence scoring
- Risk assessment

## Integration

InfoTracker integrates with existing GopherStrike framework components:

- Port scanner results can be analyzed for vulnerabilities
- Subdomain scanner information can be correlated with security risks
- Results are stored in the common logs directory structure

## Configuration

The following settings can be configured:

- NVD API Key: For faster and more reliable access to the NVD database
- Confidence Threshold: Minimum confidence level for vulnerability matches
- Output Format: Text, JSON, or CSV

## Requirements

InfoTracker requires:

- Internet connection for NVD database access
- Write access to logs directory for saving results

## Examples

### Example 1: Look up a specific CVE

```
Select a search option: 1
Enter CVE ID: CVE-2021-44228
```

### Example 2: Gather information about a web server

```
Enter target IP or hostname: example.com
Enter ports to scan: 80,443,8080
```

### Example 3: Check vulnerabilities for a router firmware

```
Device type: Router
Manufacturer: Cisco
Model: RV340
Firmware version: 1.0.03.17
```

## Output

Results can be viewed on screen and saved in multiple formats:

- JSON: For machine processing and integration with other tools
- Text: Human-readable format for analysis
- CSV: For importing into spreadsheets or databases

## Logs

All scan results are stored in the `logs/osint` directory with timestamps for future reference and correlation. 