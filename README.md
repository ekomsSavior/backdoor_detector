#  Backdoor Detector

A comprehensive security analysis tool designed to detect potential backdoors, vulnerabilities, and malicious code in software projects. This tool combines static analysis, YARA rule-based detection, vulnerability scanning, and runtime monitoring to identify security threats.

##  Features

- **YARA Rule Scanning**: Detect malware signatures and suspicious patterns
- **Static Code Analysis**: Find hardcoded secrets, credentials, and backdoor indicators
- **Vulnerability Scanning**: Integrates with multiple scanners (Safety, Trivy, npm audit, pip-audit)
- **Runtime Analysis**: Monitor network behavior during execution
- **Multiple Interfaces**: CLI, GUI (Tkinter), and Web (Flask) interfaces
- **Comprehensive Reporting**: HTML and JSON reports with detailed findings
- **Manual Review Checklist**: Generate security review checklists

##  Installation

### 1. Clone the Repository
```bash
git clone https://github.com/ekomsSavior/backdoor_detector.git
cd backdoor_detector
```

### 2. Install Dependencies

```bash

pip install yara-python psutil requests safety pip-audit --break-system-packages

pip install tkinter flask --break-system-packages

```

### 3. Install External Security Tools

For complete vulnerability scanning, install these tools:

- **Trivy**: install with:
  ```bash
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.68.2
  ```
- **npm**: Install Node.js from [nodejs.org](https://nodejs.org/)

##  Usage


### Web Interface- My fave way to use backdoor_detector:
```bash
python backdoor_detector.py --mode web --host 0.0.0.0 --port 8080
```
Then open your browser to: `http://localhost:8080`

### Command Line Interface (CLI)
```bash
# Basic scan
python backdoor_detector.py /path/to/your/project

# With custom options
python backdoor_detector.py /path/to/project \
  --runtime 60 \
  --output ./my_scan_results \
  --yara-rules ./custom_rules

# Scan with specific interface mode
python backdoor_detector.py /path/to/project --mode cli
```

### Graphical User Interface (GUI)
```bash
python backdoor_detector.py --mode gui
```

##  Scan Phases

The tool performs analysis in multiple phases:

1. **YARA Scanning**: Rule-based signature detection
2. **Static Analysis**: Hardcoded secrets and suspicious patterns
3. **Vulnerability Scanning**: Dependency analysis with multiple tools
4. **Manual Review Checklist**: Generate security review items
5. **Runtime Analysis**: Network behavior monitoring (if executable)
6. **Report Generation**: HTML and JSON reports

##  Important Notes

### Security Tools Requirement
Some features require external security tools:
- **Safety**: Python vulnerability scanner
- **Trivy**: Comprehensive vulnerability scanner
- **npm**: For Node.js projects
- **pip-audit**: Python package audit tool

### Runtime Analysis Limitations
- Runtime analysis only works if the software can be automatically executed
- Some software may require manual configuration
- Network monitoring requires `psutil` and appropriate permissions
- 
##  Configuration

### Custom YARA Rules
Place your custom YARA rules in the `yara_rules` directory with `.yar` or `.yara` extension.

### Output Directories
- CLI/GUI: Uses `--output` parameter (default: `scan_results`)
- Web Interface: Uses `web_scans/` directory

##  Output Reports

The tool generates:
1. **JSON Report**: Detailed machine-readable findings
2. **HTML Report**: Interactive web-based report with filtering
3. **Console Summary**: Quick overview of findings

##  DISCLAIMER

**IMPORTANT: only use on systems you have permission to test on**

![image0(1)](https://github.com/user-attachments/assets/e87779c0-d004-45df-9287-cc15aee85780)
