import subprocess
import re
import os
import sys
import time
import json
import socket
import threading
import webbrowser
import hashlib
import pickle
from pathlib import Path
from datetime import datetime
import platform
import tempfile
import shutil
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import traceback
import argparse

# Try to import optional dependencies
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from scapy.all import sniff, IP, TCP, UDP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    type: str
    severity: Severity
    file: str
    description: str
    details: Any
    rule: str = ""
    line_number: int = 0
    context: str = ""
    
    def to_dict(self):
        return {
            "type": self.type,
            "severity": self.severity.value,
            "file": self.file,
            "description": self.description,
            "details": self.details,
            "rule": self.rule,
            "line_number": self.line_number,
            "context": self.context[:500] if self.context else ""
        }

@dataclass
class ScanResult:
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime = None
    findings: List[Finding] = None
    summary: Dict = None
    manual_review_items: List = None
    yara_matches: List = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.manual_review_items is None:
            self.manual_review_items = []
        if self.yara_matches is None:
            self.yara_matches = []
        if self.summary is None:
            self.summary = {}
            
    def add_finding(self, finding: Finding):
        self.findings.append(finding)
    
    def get_stats(self) -> Dict:
        stats = {
            "total": len(self.findings),
            "by_severity": {},
            "by_type": {}
        }
        
        for finding in self.findings:
            severity = finding.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            finding_type = finding.type
            stats["by_type"][finding_type] = stats["by_type"].get(finding_type, 0) + 1
            
        return stats

class BackdoorDetector:
    def __init__(self, target_path: str, output_dir: str = "backdoor_scan_results", 
                 yara_rules_dir: str = "yara_rules"):
        """
        Initialize the backdoor detector.
        
        Args:
            target_path: Path to the software/project to analyze
            output_dir: Directory to store scan results
            yara_rules_dir: Directory containing YARA rules
        """
        self.target = Path(target_path).absolute()
        self.output_dir = Path(output_dir).absolute()
        self.yara_rules_dir = Path(yara_rules_dir).absolute()
        
        # Generate scan ID
        self.scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(self.target).encode()).hexdigest()[:8]}"
        
        # Initialize results
        self.result = ScanResult(
            scan_id=self.scan_id,
            target=str(self.target),
            start_time=datetime.now()
        )
        
        # Create output directory and parent directories if needed
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up old YARA rules and create new ones
        self._cleanup_and_create_yara_rules()
        
        # Initialize YARA rules if available
        self.yara_rules = None
        if HAS_YARA:
            self._load_yara_rules()
        
        # Define suspicious patterns
        self.suspicious_patterns = {
            "hardcoded_ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "suspicious_domains": r"\b(?:cnc|command|control|backdoor|malicious)\.(?:com|net|org|xyz|ru)\b",
            "raw_sockets": r"socket\.socket\(.*socket\.AF_INET.*socket\.SOCK_RAW",
            "stealth_ports": r"\b(?:31337|1337|666|23|2323|4444)\b",
            "master_passwords": r"\b(?:master|admin|root|backdoor|password|key)\s*[=:]\s*['\"][^'\"]+['\"]",
            "auth_bypass": r"\b(?:authenticate|login|auth|checkPassword)\s*\([^)]*\)\s*{\s*return\s*(?:true|YES)",
            "weak_crypto": r"\b(?:md5|sha1|des|rc4|base64_encode|base64_decode)\b",
            "xor_encryption": r"\s*\^\s*0x[0-9a-fA-F]+",
            "eval_exec": r"\b(?:eval|exec|executable|compile)\s*\(",
            "long_strings": r"['\"][^'\"]{500,}['\"]",
        }

    def _cleanup_and_create_yara_rules(self):
        """Clean up old YARA rules and create new ones with correct syntax."""
        # Create directory if it doesn't exist
        self.yara_rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up any existing .yar or .yara files
        for ext in ['.yar', '.yara']:
            for old_file in self.yara_rules_dir.glob(f"*{ext}"):
                try:
                    old_file.unlink()
                    logger.info(f"Removed old YARA rule: {old_file}")
                except Exception as e:
                    logger.warning(f"Failed to remove {old_file}: {e}")
        
        # Create new YARA rules with correct syntax
        self._create_correct_yara_rules()

    def _create_correct_yara_rules(self):
        """Create YARA rules with correct syntax (no curly braces for text strings)."""
        correct_rules = {
            "backdoor_signatures.yar": """rule backdoor_indicator {
    meta:
        description = "Common backdoor signatures"
        author = "BackdoorDetector"
        severity = "HIGH"
    strings:
        $socket_create = "socket("
        $bind = "bind("
        $listen = "listen("
        $accept = "accept("
        $shell = /bin[\\/\\\\]?(?:sh|bash|cmd|powershell)/
        $b1 = "backdoor"
        $b2 = "shell"
        $b3 = "reverse"
        $b4 = "bind"
        $b5 = "port"
        $b6 = "1337"
        $b7 = "31337"
        $b8 = "meterpreter"
        $b9 = "beacon"
        $b10 = "c2"
        $b11 = "command and control"
    condition:
        (any of ($b1,$b2,$b3,$b4,$b5,$b6,$b7,$b8,$b9,$b10,$b11)) and 
        2 of ($socket_create, $bind, $listen, $accept)
}

rule suspicious_network_activity {
    meta:
        description = "Suspicious network operations"
        severity = "MEDIUM"
    strings:
        $raw_socket = "SOCK_RAW"
        $packet_sniff = "recvfrom("
        $packet_send = "sendto("
        $promiscuous = "PROMISC"
    condition:
        ($raw_socket and $packet_sniff) or $promiscuous
}

rule credential_theft {
    meta:
        description = "Potential credential theft indicators"
        severity = "HIGH"
    strings:
        $p1 = "password"
        $p2 = "passwd"
        $p3 = "pwd"
        $p4 = "secret"
        $p5 = "token"
        $p6 = "key"
        $p7 = "credential"
        $p8 = "auth"
        $p9 = "login"
        $p10 = "authentication"
        $s1 = "keychain"
        $s2 = "credential manager"
        $s3 = "keyring"
        $s4 = "password manager"
        $s5 = "lsass"
        $s6 = "securityd"
        $s7 = "gnome-keyring"
        $e1 = "upload"
        $e2 = "send"
        $e3 = "post"
        $e4 = "exfiltrate"
        $e5 = "exfiltration"
        $e6 = "export"
        $e7 = "dump"
    condition:
        any of ($p1,$p2,$p3,$p4,$p5,$p6,$p7,$p8,$p9,$p10) and 
        any of ($s1,$s2,$s3,$s4,$s5,$s6,$s7) and 
        any of ($e1,$e2,$e3,$e4,$e5,$e6,$e7)
}

rule persistence_mechanisms {
    meta:
        description = "Common persistence mechanisms"
        severity = "MEDIUM"
    strings:
        $registry_run = "CurrentVersion\\\\Run"
        $service_install = "CreateService"
        $cron_job = "cron"
        $launch_agent = "LaunchAgent"
        $startup_folder = "Start Menu\\\\Programs\\\\Startup"
        $scheduled_task = "CreateTask"
    condition:
        any of them
}
""",
            "malware_patterns.yar": """rule packed_executable {
    meta:
        description = "Packed or obfuscated executable indicators"
        severity = "MEDIUM"
    strings:
        $s1 = "UPX"
        $s2 = "ASPack"
        $s3 = "PECompact"
        $s4 = "Themida"
        $s5 = "VMProtect"
        $s6 = "Armadillo"
        $s7 = "MPRESS"
        $s8 = "NsPack"
        $s9 = "telock"
        $s10 = "Obsidium"
        $s11 = "Enigma"
    condition:
        any of ($s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8,$s9,$s10,$s11)
}

rule process_injection {
    meta:
        description = "Process injection techniques"
        severity = "HIGH"
    strings:
        $virtual_alloc = "VirtualAllocEx"
        $write_process = "WriteProcessMemory"
        $create_remote = "CreateRemoteThread"
        $queue_user_apc = "QueueUserAPC"
        $set_window_hook = "SetWindowsHookEx"
    condition:
        3 of them
}

rule anti_debugging {
    meta:
        description = "Anti-debugging techniques"
        severity = "MEDIUM"
    strings:
        $is_debugger = "IsDebuggerPresent"
        $nt_query = "NtQueryInformationProcess"
        $check_remote = "CheckRemoteDebuggerPresent"
        $peb_debug = "BeingDebugged"
        $timing_check = "GetTickCount"
    condition:
        2 of them
}
"""
        }
        
        for filename, content in correct_rules.items():
            rule_file = self.yara_rules_dir / filename
            rule_file.write_text(content)
            logger.info(f"Created corrected YARA rule: {rule_file}")

    def _load_yara_rules(self):
        """Load YARA rules from directory."""
        if not HAS_YARA:
            logger.warning("YARA not installed. Install with: pip install yara-python")
            return
            
        if not self.yara_rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self.yara_rules_dir}")
            return
            
        try:
            # Compile all YARA files
            yara_files = list(self.yara_rules_dir.glob("*.yar")) + list(self.yara_rules_dir.glob("*.yara"))
            
            if not yara_files:
                logger.warning(f"No YARA rule files found in {self.yara_rules_dir}")
                return
                
            rules_dict = {}
            for yara_file in yara_files:
                try:
                    rules_dict[str(yara_file)] = str(yara_file)
                    logger.info(f"Loading YARA rule: {yara_file}")
                except Exception as e:
                    logger.error(f"Error loading YARA rule {yara_file}: {e}")
            
            if rules_dict:
                self.yara_rules = yara.compile(filepaths=rules_dict)
                logger.info(f"Successfully loaded {len(rules_dict)} YARA rules")
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            logger.error("This usually means there's a syntax error in your YARA rules.")
            logger.error("Check your YARA rule files for correct syntax.")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")

    def scan_with_yara(self) -> List[Dict]:
        """Scan files using YARA rules."""
        if not self.yara_rules:
            logger.warning("YARA rules not loaded. Skipping YARA scan.")
            return []
            
        findings = []
        scanned_files = 0
        
        for file_path in self.target.rglob("*"):
            if file_path.is_file():
                try:
                    # Skip large files
                    if file_path.stat().st_size > 10 * 1024 * 1024:  # 10 MB
                        continue
                        
                    scanned_files += 1
                    matches = self.yara_rules.match(str(file_path))
                    
                    for match in matches:
                        finding = Finding(
                            type="yara_match",
                            severity=Severity.HIGH if "severity" in match.meta and match.meta["severity"] == "HIGH" else Severity.MEDIUM,
                            file=str(file_path.relative_to(self.target)),
                            description=f"YARA rule match: {match.rule}",
                            details={
                                "rule": match.rule,
                                "tags": match.tags,
                                "meta": match.meta,
                                "strings": [str(s) for s in match.strings] if match.strings else []
                            },
                            rule=match.rule
                        )
                        findings.append(finding)
                        self.result.add_finding(finding)
                        
                except Exception as e:
                    logger.error(f"Error scanning {file_path} with YARA: {e}")
        
        logger.info(f"YARA scan completed: {scanned_files} files scanned, {len(findings)} matches found")
        return findings

    def scan_hardcoded_secrets(self) -> List[Finding]:
        """Scan for hardcoded secrets and credentials."""
        findings = []
        secret_patterns = {
            "api_key": r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"][^\'"]+[\'"]',
            "password": r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]+[\'"]',
            "secret": r'(?i)(secret|token|bearer)\s*[=:]\s*[\'"][^\'"]+[\'"]',
            "private_key": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "ssh_key": r'ssh-[a-z]{3} AAAA[0-9A-Za-z+/]+[=]{0,3}',
            "crypto_key": r'(?i)(?:aes|des|blowfish|rc4)[_-]?key\s*[=:]\s*[\'"][^\'"]+[\'"]',
        }
        
        for file_path in self.target.rglob("*"):
            if file_path.is_file() and not self._is_binary(file_path):
                try:
                    content = file_path.read_text(errors='ignore')
                    lines = content.split('\n')
                    
                    for i, line in enumerate(lines, 1):
                        for secret_type, pattern in secret_patterns.items():
                            matches = re.findall(pattern, line)
                            for match in matches:
                                finding = Finding(
                                    type="hardcoded_secret",
                                    severity=Severity.HIGH,
                                    file=str(file_path.relative_to(self.target)),
                                    description=f"Hardcoded {secret_type.replace('_', ' ')} found",
                                    details={"match": str(match)},
                                    line_number=i,
                                    context=line[:200]
                                )
                                findings.append(finding)
                                self.result.add_finding(finding)
                                
                except Exception as e:
                    logger.error(f"Error scanning {file_path} for secrets: {e}")
        
        return findings

    def scan_for_vulnerabilities(self) -> List[Finding]:
        """Scan for known vulnerabilities using various tools."""
        findings = []
        
        # Check for available vulnerability scanners
        scanners = {
            "safety": self._run_safety_scan,
            "trivy": self._run_trivy_scan,
            "npm_audit": self._run_npm_audit,
            "pip_audit": self._run_pip_audit,
        }
        
        for scanner_name, scanner_func in scanners.items():
            try:
                scanner_findings = scanner_func()
                findings.extend(scanner_findings)
                logger.info(f"{scanner_name} scan completed: {len(scanner_findings)} findings")
            except Exception as e:
                logger.warning(f"{scanner_name} scan failed: {e}")
        
        return findings

    def _run_safety_scan(self) -> List[Finding]:
        """Run safety vulnerability scanner."""
        findings = []
        
        req_files = ["requirements.txt", "Pipfile", "pyproject.toml"]
        for req_file in req_files:
            req_path = self.target / req_file
            if req_path.exists():
                try:
                    result = subprocess.run(
                        ["safety", "check", "-r", str(req_path), "--json"],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    
                    if result.returncode != 0 and result.stdout:
                        try:
                            vulns = json.loads(result.stdout)
                            for vuln in vulns.get("vulnerabilities", []):
                                finding = Finding(
                                    type="vulnerability",
                                    severity=Severity.HIGH,
                                    file=req_file,
                                    description=f"Vulnerable dependency: {vuln.get('package_name')}",
                                    details=vuln
                                )
                                findings.append(finding)
                                self.result.add_finding(finding)
                        except json.JSONDecodeError:
                            # Try to parse as text output
                            lines = result.stdout.split('\n')
                            for line in lines:
                                if "VULNERABILITY" in line or "CVE" in line:
                                    finding = Finding(
                                        type="vulnerability",
                                        severity=Severity.HIGH,
                                        file=req_file,
                                        description="Vulnerable dependency found",
                                        details=line.strip()
                                    )
                                    findings.append(finding)
                                    self.result.add_finding(finding)
                except FileNotFoundError:
                    logger.warning("safety not installed. Install with: pip install safety")
                except subprocess.TimeoutExpired:
                    logger.warning(f"safety scan timed out for {req_file}")
        
        return findings

    def _run_trivy_scan(self) -> List[Finding]:
        """Run Trivy vulnerability scanner."""
        findings = []
        
        try:
            # Check if trivy is installed
            subprocess.run(["trivy", "--version"], capture_output=True, check=True)
            
            # Scan the directory
            result = subprocess.run(
                ["trivy", "filesystem", "--format", "json", str(self.target)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.stdout:
                try:
                    report = json.loads(result.stdout)
                    for result in report.get("Results", []):
                        for vuln in result.get("Vulnerabilities", []):
                            finding = Finding(
                                type="vulnerability",
                                severity=Severity.HIGH if vuln.get("Severity", "").upper() in ["CRITICAL", "HIGH"] else Severity.MEDIUM,
                                file=result.get("Target", ""),
                                description=f"{vuln.get('VulnerabilityID')}: {vuln.get('Title', '')}",
                                details=vuln
                            )
                            findings.append(finding)
                            self.result.add_finding(finding)
                except json.JSONDecodeError:
                    logger.error("Failed to parse trivy output as JSON")
        except (FileNotFoundError, subprocess.CalledProcessError):
            logger.warning("trivy not installed. Install from: https://github.com/aquasecurity/trivy")
        except subprocess.TimeoutExpired:
            logger.warning("trivy scan timed out")
        
        return findings

    def _run_npm_audit(self) -> List[Finding]:
        """Run npm audit for Node.js projects."""
        findings = []
        
        package_json = self.target / "package.json"
        if package_json.exists():
            try:
                result = subprocess.run(
                    ["npm", "audit", "--json"],
                    cwd=self.target,
                    capture_output=True,
                    text=True,
                    timeout=120  # Increased timeout
                )
                
                if result.stdout:
                    try:
                        audit_result = json.loads(result.stdout)
                        for _, vuln in audit_result.get("vulnerabilities", {}).items():
                            finding = Finding(
                                type="vulnerability",
                                severity=Severity.HIGH if vuln.get("severity") == "high" else Severity.MEDIUM,
                                file="package.json",
                                description=f"npm vulnerability: {vuln.get('name')}",
                                details=vuln
                            )
                            findings.append(finding)
                            self.result.add_finding(finding)
                    except json.JSONDecodeError:
                        logger.error("Failed to parse npm audit output as JSON")
            except FileNotFoundError:
                logger.warning("npm not installed")
            except subprocess.TimeoutExpired:
                logger.warning("npm audit timed out")
        
        return findings

    def _run_pip_audit(self) -> List[Finding]:
        """Run pip-audit for Python projects."""
        findings = []
        
        try:
            # First check if pip-audit is installed
            subprocess.run(["pip-audit", "--version"], capture_output=True, check=True)
            
            result = subprocess.run(
                ["pip-audit", "--format", "json"],
                cwd=self.target,
                capture_output=True,
                text=True,
                timeout=120  # Increased timeout to 120 seconds
            )
            
            if result.stdout and result.stdout.strip():
                try:
                    vulns = json.loads(result.stdout)
                    if isinstance(vulns, dict) and "vulnerabilities" in vulns:
                        for vuln in vulns.get("vulnerabilities", []):
                            finding = Finding(
                                type="vulnerability",
                                severity=Severity.HIGH if vuln.get("severity", "high") == "high" else Severity.MEDIUM,
                                file="dependencies",
                                description=f"pip vulnerability: {vuln.get('name', 'Unknown')}",
                                details=vuln
                            )
                            findings.append(finding)
                            self.result.add_finding(finding)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse pip-audit output as JSON: {e}")
        except FileNotFoundError:
            logger.warning("pip-audit not installed. Install with: pip install pip-audit")
        except subprocess.CalledProcessError:
            logger.warning("pip-audit command failed. Make sure it's properly installed.")
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit timed out after 120 seconds")
        
        return findings

    def analyze_network_behavior(self, command: str = None, timeout: int = 30) -> Dict:
        """
        Run the software and monitor its network behavior.
        """
        if not command:
            command = self._detect_run_command()
            
        if not command:
            logger.warning("Could not detect run command. Skipping network analysis.")
            return {}
        
        logger.info(f"Running network analysis with command: {command}")
        
        network_data = {"connections": [], "dns_queries": []}
        
        if HAS_PSUTIL:
            monitor_thread = threading.Thread(
                target=self._network_monitor,
                args=(timeout, network_data)
            )
            monitor_thread.start()
            
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    proc = subprocess.Popen(
                        command,
                        shell=True,
                        cwd=temp_dir,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    # Wait with timeout
                    for _ in range(timeout * 2):
                        if proc.poll() is not None:
                            break
                        time.sleep(0.5)
                    else:
                        proc.terminate()
                        time.sleep(2)
                        if proc.poll() is None:
                            proc.kill()
                    
                    proc.communicate(timeout=5)
                    
            except Exception as e:
                logger.error(f"Error running command: {e}")
            
            monitor_thread.join(timeout + 5)
            
            # Analyze network data
            runtime_findings = self._analyze_network_data(network_data)
            for finding in runtime_findings:
                self.result.add_finding(finding)
            
            return {
                "command": command,
                "network_connections": network_data["connections"],
                "findings": runtime_findings
            }
        
        return {}

    def _network_monitor(self, duration: int, data: Dict):
        """Monitor network connections during runtime."""
        if not HAS_PSUTIL:
            return
            
        start_time = time.time()
        initial_connections = set()
        
        # Get initial connections
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                initial_connections.add((conn.laddr, conn.raddr))
        
        # Monitor new connections
        while time.time() - start_time < duration:
            time.sleep(1)
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_tuple = (conn.laddr, conn.raddr)
                    if conn_tuple not in initial_connections:
                        data["connections"].append({
                            "local": str(conn.laddr),
                            "remote": str(conn.raddr),
                            "pid": conn.pid,
                            "status": conn.status
                        })
                        initial_connections.add(conn_tuple)

    def _analyze_network_data(self, network_data: Dict) -> List[Finding]:
        """Analyze captured network data for suspicious patterns."""
        findings = []
        suspicious_ports = {31337, 1337, 666, 23, 2323, 4444, 8080, 9999, 5555}
        
        for conn in network_data["connections"]:
            remote = conn.get("remote")
            if remote:
                try:
                    ip, port_str = remote.rsplit(':', 1)
                    port = int(port_str)
                    
                    if port in suspicious_ports:
                        finding = Finding(
                            type="suspicious_network",
                            severity=Severity.MEDIUM,
                            file="runtime",
                            description=f"Connection to suspicious port {port}",
                            details=conn
                        )
                        findings.append(finding)
                    
                    if self._is_private_ip(ip) and port in [443, 80, 8080]:
                        finding = Finding(
                            type="internal_connection",
                            severity=Severity.LOW,
                            file="runtime",
                            description=f"Connection to internal service on port {port}",
                            details=conn
                        )
                        findings.append(finding)
                        
                except (ValueError, AttributeError):
                    continue
        
        return findings

    def generate_manual_review_checklist(self) -> List[Dict]:
        """Generate comprehensive manual review checklist."""
        checklist = [
            {
                "category": "Authentication & Authorization",
                "items": [
                    "Review all authentication functions for hardcoded credentials",
                    "Check for debug/backdoor accounts in production code",
                    "Verify privilege escalation paths",
                    "Review password reset mechanisms",
                    "Check session management implementation"
                ]
            },
            {
                "category": "Network Communication",
                "items": [
                    "Manually review all network connection code",
                    "Check for raw socket usage",
                    "Look for DNS tunneling techniques",
                    "Review all outgoing connections",
                    "Check for encrypted C2 channels",
                    "Look for heartbeat/phone-home functionality"
                ]
            },
            {
                "category": "Code Obfuscation",
                "items": [
                    "Review heavily obfuscated sections",
                    "Check for anti-debugging techniques",
                    "Review any packers or unpackers",
                    "Check for VM/sandbox detection",
                    "Look for timing-based evasion"
                ]
            },
            {
                "category": "Persistence Mechanisms",
                "items": [
                    "Check for auto-start registry entries",
                    "Review cron jobs/launch agents",
                    "Look for service installation code",
                    "Check for DLL injection",
                    "Review browser extensions"
                ]
            }
        ]
        
        self.result.manual_review_items = checklist
        return checklist

    def save_results(self) -> Path:
        """Save scan results to file."""
        self.result.end_time = datetime.now()
        
        # Calculate duration
        duration = (self.result.end_time - self.result.start_time).total_seconds()
        self.result.summary = {
            "duration_seconds": duration,
            "stats": self.result.get_stats()
        }
        
        # Save JSON report
        report_file = self.output_dir / f"{self.scan_id}.json"
        
        # Convert result to dict
        result_dict = {
            "scan_id": self.result.scan_id,
            "target": self.result.target,
            "start_time": self.result.start_time.isoformat(),
            "end_time": self.result.end_time.isoformat() if self.result.end_time else None,
            "summary": self.result.summary,
            "findings": [f.to_dict() for f in self.result.findings],
            "manual_review_items": self.result.manual_review_items,
            "yara_matches": self.result.yara_matches
        }
        
        with open(report_file, 'w') as f:
            json.dump(result_dict, f, indent=2, default=str)
        
        # Generate HTML report
        html_file = self._generate_html_report(report_file)
        
        logger.info(f"Results saved to: {report_file}")
        logger.info(f"HTML report: {html_file}")
        
        return html_file

    def _generate_html_report(self, json_report_path: Path) -> Path:
        """Generate HTML report from JSON results."""
        html_file = self.output_dir / f"{self.scan_id}.html"
        
        # Read JSON data
        with open(json_report_path, 'r') as f:
            data = json.load(f)
        
        # Create HTML template
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Backdoor Scan Report - {data['scan_id']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
                .severity-badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin: 0 5px; }}
                .severity-critical {{ background: #dc3545; color: white; }}
                .severity-high {{ background: #fd7e14; color: white; }}
                .severity-medium {{ background: #ffc107; color: black; }}
                .severity-low {{ background: #28a745; color: white; }}
                .severity-info {{ background: #17a2b8; color: white; }}
                .finding-card {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; background: #fff; }}
                .finding-card:hover {{ box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
                .details {{ background: #f8f9fa; padding: 10px; margin-top: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; }}
                .chart-container {{ width: 100%; height: 300px; margin: 20px 0; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 15px; border-radius: 5px; border: 1px solid #ddd; text-align: center; }}
                .stat-number {{ font-size: 24px; font-weight: bold; margin: 10px 0; }}
                .filter-buttons {{ margin: 20px 0; }}
                .filter-btn {{ margin: 0 5px 5px 0; }}
                .timestamp {{ color: #666; font-size: 12px; }}
                .review-checklist {{ background: #e8f4fd; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Backdoor Detection Scan Report</h1>
                    <p class="timestamp">Scan ID: {data['scan_id']}</p>
                    <p class="timestamp">Target: {data['target']}</p>
                    <p class="timestamp">Scan started: {data['start_time']}</p>
                    <p class="timestamp">Scan completed: {data['end_time']}</p>
                    <p class="timestamp">Duration: {data['summary']['duration_seconds']:.2f} seconds</p>
                </div>
                
                <div class="summary">
                    <h2>📊 Summary</h2>
                    <div class="stats-grid">
        """
        
        # Add stats cards
        stats = data['summary']['stats']
        html += f"""
                        <div class="stat-card">
                            <div>Total Findings</div>
                            <div class="stat-number">{stats['total']}</div>
                        </div>
        """
        
        for severity, count in stats['by_severity'].items():
            color_class = f"severity-{severity.lower()}"
            html += f"""
                        <div class="stat-card">
                            <div><span class="severity-badge {color_class}">{severity}</span></div>
                            <div class="stat-number">{count}</div>
                        </div>
            """
        
        html += """
                    </div>
                </div>
                
                <div class="filter-buttons">
                    <h3>Filter Findings by Severity:</h3>
        """
        
        # Add filter buttons
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            color_class = f"severity-{severity.lower()}"
            count = stats['by_severity'].get(severity, 0)
            html += f"""
                    <button class="filter-btn severity-badge {color_class}" onclick="filterFindings('{severity}')">
                        {severity} ({count})
                    </button>
            """
        
        html += """
                    <button class="filter-btn" onclick="filterFindings('ALL')">Show All</button>
                </div>
                
                <div id="findings-section">
                    <h2>🔎 Findings</h2>
        """
        
        # Add findings
        if data['findings']:
            for i, finding in enumerate(data['findings']):
                severity = finding['severity']
                color_class = f"severity-{severity.lower()}"
                
                html += f"""
                    <div class="finding-card" data-severity="{severity}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <h3 style="margin: 0;">{finding['type'].replace('_', ' ').title()}</h3>
                            <span class="severity-badge {color_class}">{severity}</span>
                        </div>
                        <p><strong>File:</strong> {finding['file']}</p>
                        <p><strong>Description:</strong> {finding['description']}</p>
                """
                
                if finding.get('line_number'):
                    html += f"""<p><strong>Line:</strong> {finding['line_number']}</p>"""
                
                if finding.get('context'):
                    html += f"""<p><strong>Context:</strong> {finding['context']}</p>"""
                
                if finding.get('details'):
                    html += f"""
                        <div class="details">
                            <strong>Details:</strong><br>
                            <pre>{json.dumps(finding['details'], indent=2) if isinstance(finding['details'], dict) else str(finding['details'])}</pre>
                        </div>
                    """
                
                html += """
                    </div>
                """
        else:
            html += "<p>No findings detected.</p>"
        
        html += """
                </div>
                
                <div class="review-checklist">
                    <h2>📋 Manual Review Checklist</h2>
        """
        
        # Add manual review checklist
        for category in data.get('manual_review_items', []):
            html += f"""
                    <h3>{category['category']}</h3>
                    <ul>
            """
            for item in category['items']:
                html += f"""<li><input type="checkbox"> {item}</li>"""
            html += """
                    </ul>
            """
        
        html += """
                </div>
            </div>
            
            <script>
                function filterFindings(severity) {
                    const findings = document.querySelectorAll('.finding-card');
                    findings.forEach(finding => {
                        if (severity === 'ALL' || finding.dataset.severity === severity) {
                            finding.style.display = 'block';
                        } else {
                            finding.style.display = 'none';
                        }
                    });
                }
                
                // Initialize with all findings shown
                filterFindings('ALL');
            </script>
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html)
        
        return html_file

    def run_full_analysis(self, runtime_timeout: int = 30) -> ScanResult:
        """Run complete analysis pipeline."""
        logger.info(f"Starting backdoor analysis of: {self.target}")
        
        try:
            # Phase 1: YARA Scanning
            logger.info("Phase 1: YARA Rule Scanning")
            yara_results = self.scan_with_yara()
            logger.info(f"YARA scan found {len(yara_results)} matches")
            
            # Phase 2: Static Analysis
            logger.info("Phase 2: Static Analysis")
            secret_results = self.scan_hardcoded_secrets()
            logger.info(f"Secret scan found {len(secret_results)} hardcoded secrets")
            
            # Phase 3: Vulnerability Scanning
            logger.info("Phase 3: Vulnerability Scanning")
            vuln_results = self.scan_for_vulnerabilities()
            logger.info(f"Vulnerability scan found {len(vuln_results)} vulnerabilities")
            
            # Phase 4: Manual Review Checklist
            logger.info("Phase 4: Manual Review Checklist Generation")
            self.generate_manual_review_checklist()
            
            # Phase 5: Runtime Analysis (if applicable)
            logger.info("Phase 5: Runtime Analysis")
            if self._detect_run_command():
                runtime_results = self.analyze_network_behavior(timeout=runtime_timeout)
                logger.info(f"Runtime analysis found {len(runtime_results.get('findings', []))} network anomalies")
            else:
                logger.warning("Could not auto-detect run command. Skipping runtime analysis.")
            
            # Phase 6: Save Results
            logger.info("Phase 6: Report Generation")
            report_path = self.save_results()
            
            # Print summary
            stats = self.result.get_stats()
            logger.info("\n" + "="*60)
            logger.info("ANALYSIS COMPLETE")
            logger.info("="*60)
            logger.info(f"Total findings: {stats['total']}")
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = stats['by_severity'].get(severity, 0)
                if count > 0:
                    logger.info(f"  {severity}: {count}")
            
            logger.info("\nNEXT STEPS:")
            logger.info(f"1. Review the HTML report at: {report_path}")
            logger.info("2. Manually verify all HIGH/CRITICAL findings")
            logger.info("3. Check the manual review checklist")
            logger.info("4. Consider additional sandbox testing")
            logger.info("="*60)
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            logger.error(traceback.format_exc())
        
        return self.result

    def _is_binary(self, file_path: Path) -> bool:
        """Check if a file is binary."""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except:
            return False

    def _detect_run_command(self) -> Optional[str]:
        """Try to auto-detect how to run the software."""
        entry_points = [
            ("main.py", "python main.py"),
            ("app.py", "python app.py"),
            ("manage.py", "python manage.py"),
            ("run.py", "python run.py"),
            ("setup.py", "python setup.py develop"),
            ("index.js", "node index.js"),
            ("package.json", "npm start"),
            ("Makefile", "make"),
            ("run.sh", "bash run.sh"),
            ("start.sh", "bash start.sh"),
        ]
        
        for file_name, command in entry_points:
            if (self.target / file_name).exists():
                return command
        
        # Check for executable files
        for file_path in self.target.glob("*"):
            if file_path.is_file() and os.access(file_path, os.X_OK):
                return f"./{file_path.name}"
        
        return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges."""
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
        ]
        
        try:
            ip_parts = list(map(int, ip.split('.')))
            if len(ip_parts) != 4:
                return False
                
            for start_str, end_str in private_ranges:
                start = list(map(int, start_str.split('.')))
                end = list(map(int, end_str.split('.')))
                
                ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
                start_num = (start[0] << 24) + (start[1] << 16) + (start[2] << 8) + start[3]
                end_num = (end[0] << 24) + (end[1] << 16) + (end[2] << 8) + end[3]
                
                if start_num <= ip_num <= end_num:
                    return True
        except:
            pass
        
        return False


class BackdoorDetectorGUI:
    """Tkinter-based GUI for the Backdoor Detector."""
    
    def __init__(self):
        try:
            import tkinter as tk
            from tkinter import ttk, filedialog, messagebox, scrolledtext
            import threading
            
            self.tk = tk
            self.ttk = ttk
            self.filedialog = filedialog
            self.messagebox = messagebox
            self.scrolledtext = scrolledtext
            self.threading = threading
            
            self.root = tk.Tk()
            self.root.title("Backdoor Detector v2.0")
            self.root.geometry("1000x700")
            
            self.detector = None
            self.current_scan = None
            
            self._setup_ui()
            
        except ImportError as e:
            logger.error(f"Failed to import tkinter: {e}")
            raise
    
    def _setup_ui(self):
        """Setup the GUI interface."""
        # Create notebook for tabs
        notebook = self.ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scan Tab
        scan_frame = self.tk.Frame(notebook)
        notebook.add(scan_frame, text='Scan')
        self._setup_scan_tab(scan_frame)
        
        # Results Tab
        results_frame = self.tk.Frame(notebook)
        notebook.add(results_frame, text='Results')
        self._setup_results_tab(results_frame)
        
        # Settings Tab
        settings_frame = self.tk.Frame(notebook)
        notebook.add(settings_frame, text='Settings')
        self._setup_settings_tab(settings_frame)
        
        # About Tab
        about_frame = self.tk.Frame(notebook)
        notebook.add(about_frame, text='About')
        self._setup_about_tab(about_frame)
    
    def _setup_scan_tab(self, parent):
        """Setup the scan tab."""
        # Target selection
        target_frame = self.ttk.LabelFrame(parent, text="Target Selection", padding=10)
        target_frame.pack(fill='x', padx=10, pady=5)
        
        self.target_var = self.tk.StringVar()
        ttk.Entry(target_frame, textvariable=self.target_var, width=50).pack(side='left', padx=(0, 10))
        ttk.Button(target_frame, text="Browse...", command=self._browse_target).pack(side='left', padx=(0, 10))
        
        # Scan options
        options_frame = self.ttk.LabelFrame(parent, text="Scan Options", padding=10)
        options_frame.pack(fill='x', padx=10, pady=5)
        
        self.yara_var = self.tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable YARA scanning", variable=self.yara_var).grid(row=0, column=0, sticky='w')
        
        self.vuln_var = self.tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable vulnerability scanning", variable=self.vuln_var).grid(row=1, column=0, sticky='w')
        
        self.runtime_var = self.tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Enable runtime analysis", variable=self.runtime_var).grid(row=2, column=0, sticky='w')
        
        # Runtime timeout
        ttk.Label(options_frame, text="Runtime timeout (seconds):").grid(row=3, column=0, sticky='w', pady=(10, 0))
        self.timeout_var = self.tk.StringVar(value="30")
        ttk.Entry(options_frame, textvariable=self.timeout_var, width=10).grid(row=3, column=1, sticky='w', pady=(10, 0))
        
        # Scan controls
        control_frame = self.tk.Frame(parent)
        control_frame.pack(fill='x', padx=10, pady=20)
        
        self.scan_button = ttk.Button(control_frame, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side='left', padx=(0, 10))
        
        ttk.Button(control_frame, text="Stop Scan", command=self._stop_scan).pack(side='left', padx=(0, 10))
        ttk.Button(control_frame, text="Open Report", command=self._open_report).pack(side='left')
        
        # Progress
        progress_frame = self.ttk.LabelFrame(parent, text="Progress", padding=10)
        progress_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack(fill='x', pady=(0, 10))
        
        self.log_text = self.scrolledtext.ScrolledText(progress_frame, height=15)
        self.log_text.pack(fill='both', expand=True)
        
        # Redirect logging to text widget
        self.log_handler = TextHandler(self.log_text)
        logger.addHandler(self.log_handler)
    
    def _setup_results_tab(self, parent):
        """Setup the results tab."""
        # Results display
        results_frame = self.ttk.LabelFrame(parent, text="Scan Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview for findings
        columns = ('Severity', 'Type', 'File', 'Description')
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        self.tree.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Details frame
        details_frame = self.ttk.LabelFrame(parent, text="Finding Details", padding=10)
        details_frame.pack(fill='x', padx=10, pady=5)
        
        self.details_text = self.scrolledtext.ScrolledText(details_frame, height=10)
        self.details_text.pack(fill='both', expand=True)
        
        # Bind tree selection
        self.tree.bind('<<TreeviewSelect>>', self._on_tree_select)
    
    def _setup_settings_tab(self, parent):
        """Setup the settings tab."""
        settings_frame = self.ttk.LabelFrame(parent, text="Configuration", padding=10)
        settings_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # YARA rules path
        ttk.Label(settings_frame, text="YARA Rules Directory:").grid(row=0, column=0, sticky='w', pady=5)
        self.yara_dir_var = self.tk.StringVar(value="yara_rules")
        ttk.Entry(settings_frame, textvariable=self.yara_dir_var, width=50).grid(row=0, column=1, pady=5)
        ttk.Button(settings_frame, text="Browse...", command=self._browse_yara_dir).grid(row=0, column=2, padx=(5, 0))
        
        # Output directory
        ttk.Label(settings_frame, text="Output Directory:").grid(row=1, column=0, sticky='w', pady=5)
        self.output_dir_var = self.tk.StringVar(value="scan_results")
        ttk.Entry(settings_frame, textvariable=self.output_dir_var, width=50).grid(row=1, column=1, pady=5)
        ttk.Button(settings_frame, text="Browse...", command=self._browse_output_dir).grid(row=1, column=2, padx=(5, 0))
        
        # Save/Load buttons
        button_frame = self.tk.Frame(settings_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Save Settings", command=self._save_settings).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="Load Settings", command=self._load_settings).pack(side='left')
    
    def _setup_about_tab(self, parent):
        """Setup the about tab."""
        about_text = """
Backdoor Detector v2.0

A comprehensive tool for detecting potential backdoors and 
vulnerabilities in software projects.

Features:
- YARA rule-based signature detection
- Vulnerability scanning with multiple tools
- Static analysis for hardcoded secrets
- Runtime behavior monitoring
- HTML report generation
- GUI and Web interfaces

Requirements:
- Python 3.7+
- Optional: yara-python, safety, trivy, npm

Usage:
1. Select target directory
2. Configure scan options
3. Click Start Scan
4. Review results and HTML report

For more information, see the documentation.
"""
        
        text_widget = self.scrolledtext.ScrolledText(parent, height=20)
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        text_widget.insert('1.0', about_text)
        text_widget.config(state='disabled')
    
    def _browse_target(self):
        """Browse for target directory."""
        directory = self.filedialog.askdirectory(title="Select Target Directory")
        if directory:
            self.target_var.set(directory)
    
    def _browse_yara_dir(self):
        """Browse for YARA rules directory."""
        directory = self.filedialog.askdirectory(title="Select YARA Rules Directory")
        if directory:
            self.yara_dir_var.set(directory)
    
    def _browse_output_dir(self):
        """Browse for output directory."""
        directory = self.filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_dir_var.set(directory)
    
    def _start_scan(self):
        """Start the scan in a separate thread."""
        target = self.target_var.get()
        if not target or not Path(target).exists():
            self.messagebox.showerror("Error", "Please select a valid target directory")
            return
        
        # Disable scan button
        self.scan_button.config(state='disabled')
        self.progress_bar.start()
        
        # Clear log
        self.log_text.delete('1.0', self.tk.END)
        
        # Start scan in thread
        scan_thread = self.threading.Thread(target=self._run_scan_thread, daemon=True)
        scan_thread.start()
    
    def _run_scan_thread(self):
        """Run scan in background thread."""
        try:
            target = self.target_var.get()
            yara_dir = self.yara_dir_var.get()
            output_dir = self.output_dir_var.get()
            timeout = int(self.timeout_var.get())
            
            self.detector = BackdoorDetector(target, output_dir, yara_dir)
            self.current_scan = self.detector.run_full_analysis(runtime_timeout=timeout)
            
            # Update UI in main thread
            self.root.after(0, self._scan_completed)
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.root.after(0, lambda: self.messagebox.showerror("Error", f"Scan failed: {str(e)}"))
            self.root.after(0, self._scan_failed)
    
    def _scan_completed(self):
        """Handle scan completion."""
        self.progress_bar.stop()
        self.scan_button.config(state='normal')
        
        if self.current_scan:
            # Update results tree
            self._update_results_tree()
            
            # Show completion message
            stats = self.current_scan.get_stats()
            self.messagebox.showinfo("Scan Complete", 
                                   f"Scan completed successfully!\n"
                                   f"Total findings: {stats['total']}\n"
                                   f"HTML report has been generated.")
    
    def _scan_failed(self):
        """Handle scan failure."""
        self.progress_bar.stop()
        self.scan_button.config(state='normal')
    
    def _stop_scan(self):
        """Stop the current scan."""
        if self.detector:
            # Implement stop logic if needed
            pass
        
        self.progress_bar.stop()
        self.scan_button.config(state='normal')
        self.messagebox.showinfo("Scan Stopped", "Scan has been stopped.")
    
    def _open_report(self):
        """Open the latest HTML report."""
        if not self.detector or not self.detector.output_dir.exists():
            self.messagebox.showerror("Error", "No scan results available")
            return
        
        # Find latest HTML report
        html_files = list(self.detector.output_dir.glob("*.html"))
        if not html_files:
            self.messagebox.showerror("Error", "No HTML report found")
            return
        
        latest_report = max(html_files, key=lambda x: x.stat().st_mtime)
        
        # Open in default browser
        import webbrowser
        webbrowser.open(f"file://{latest_report.absolute()}")
    
    def _update_results_tree(self):
        """Update the results tree with scan findings."""
        if not self.current_scan:
            return
        
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add findings to tree
        for finding in self.current_scan.findings:
            self.tree.insert('', 'end', values=(
                finding.severity.value,
                finding.type,
                finding.file,
                finding.description[:100] + "..." if len(finding.description) > 100 else finding.description
            ))
    
    def _on_tree_select(self, event):
        """Handle tree item selection."""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        values = item['values']
        
        # Find corresponding finding
        if self.current_scan:
            for finding in self.current_scan.findings:
                if (finding.severity.value == values[0] and 
                    finding.type == values[1] and 
                    finding.file == values[2]):
                    
                    # Display details
                    details = f"""
Type: {finding.type}
Severity: {finding.severity.value}
File: {finding.file}
Description: {finding.description}

Details:
{json.dumps(finding.details, indent=2) if isinstance(finding.details, dict) else str(finding.details)}
"""
                    
                    self.details_text.delete('1.0', self.tk.END)
                    self.details_text.insert('1.0', details)
                    break
    
    def _save_settings(self):
        """Save settings to file."""
        settings = {
            'yara_dir': self.yara_dir_var.get(),
            'output_dir': self.output_dir_var.get(),
            'timeout': self.timeout_var.get()
        }
        
        try:
            file_path = self.filedialog.asksaveasfilename(
                title="Save Settings",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(settings, f, indent=2)
                
                self.messagebox.showinfo("Settings Saved", f"Settings saved to {file_path}")
                
        except Exception as e:
            self.messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def _load_settings(self):
        """Load settings from file."""
        try:
            file_path = self.filedialog.askopenfilename(
                title="Load Settings",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if file_path and Path(file_path).exists():
                with open(file_path, 'r') as f:
                    settings = json.load(f)
                
                self.yara_dir_var.set(settings.get('yara_dir', 'yara_rules'))
                self.output_dir_var.set(settings.get('output_dir', 'scan_results'))
                self.timeout_var.set(settings.get('timeout', '30'))
                
                self.messagebox.showinfo("Settings Loaded", f"Settings loaded from {file_path}")
                
        except Exception as e:
            self.messagebox.showerror("Error", f"Failed to load settings: {e}")
    
    def run(self):
        """Run the GUI application."""
        self.root.mainloop()


class TextHandler(logging.Handler):
    """Log handler that writes to a tkinter Text widget."""
    
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    def emit(self, record):
        msg = self.format(record)
        
        def append():
            self.text_widget.insert('end', msg + '\n')
            self.text_widget.see('end')
        
        # Schedule append in main thread
        self.text_widget.after(0, append)


def start_web_interface(host='127.0.0.1', port=5000):
    """Start Flask web interface."""
    try:
        from flask import Flask, render_template, request, jsonify, send_file
        import threading
        
        app = Flask(__name__)
        
        # Global scan state
        current_scans = {}
        
        @app.route('/')
        def index():
            return '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Backdoor Detector Web Interface</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; }
                    .header { background: #333; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
                    .card { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
                    .form-group { margin-bottom: 15px; }
                    label { display: block; margin-bottom: 5px; font-weight: bold; }
                    input[type="text"], input[type="number"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
                    button { background: #4CAF50; color: white; border: none; padding: 10px 20px; border-radius: 3px; cursor: pointer; }
                    button:hover { background: #45a049; }
                    .progress { height: 20px; background: #f0f0f0; border-radius: 10px; overflow: hidden; margin: 10px 0; }
                    .progress-bar { height: 100%; background: #4CAF50; transition: width 0.3s; }
                    .scan-item { border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 3px; }
                    .scan-status { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
                    .status-running { background: #ffc107; }
                    .status-completed { background: #28a745; color: white; }
                    .status-failed { background: #dc3545; color: white; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔍 Backdoor Detector Web Interface</h1>
                        <p>Scan for backdoors and vulnerabilities in software projects</p>
                    </div>
                    
                    <div class="card">
                        <h2>New Scan</h2>
                        <form id="scanForm">
                            <div class="form-group">
                                <label for="target">Target Directory:</label>
                                <input type="text" id="target" name="target" placeholder="/path/to/project" required>
                            </div>
                            <div class="form-group">
                                <label for="yara_rules">YARA Rules Directory:</label>
                                <input type="text" id="yara_rules" name="yara_rules" placeholder="yara_rules" value="yara_rules">
                            </div>
                            <div class="form-group">
                                <label for="timeout">Runtime Timeout (seconds):</label>
                                <input type="number" id="timeout" name="timeout" value="30" min="10" max="300">
                            </div>
                            <button type="submit">Start Scan</button>
                        </form>
                    </div>
                    
                    <div class="card">
                        <h2>Active Scans</h2>
                        <div id="scansList"></div>
                    </div>
                    
                    <div class="card">
                        <h2>Scan Results</h2>
                        <div id="results"></div>
                    </div>
                </div>
                
                <script>
                    let activeScans = {};
                    
                    document.getElementById('scanForm').addEventListener('submit', async (e) => {
                        e.preventDefault();
                        
                        const formData = {
                            target: document.getElementById('target').value,
                            yara_rules_dir: document.getElementById('yara_rules').value,
                            timeout: document.getElementById('timeout').value
                        };
                        
                        try {
                            const response = await fetch('/api/scan', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify(formData)
                            });
                            
                            const data = await response.json();
                            
                            if (data.scan_id) {
                                activeScans[data.scan_id] = { status: 'running' };
                                updateScansList();
                                pollScanStatus(data.scan_id);
                            } else if (data.error) {
                                alert('Error: ' + data.error);
                            }
                        } catch (error) {
                            console.error('Error starting scan:', error);
                            alert('Error starting scan: ' + error);
                        }
                    });
                    
                    async function pollScanStatus(scanId) {
                        try {
                            const response = await fetch(`/api/scan/${scanId}`);
                            const data = await response.json();
                            
                            if (data.error) {
                                activeScans[scanId] = { status: 'failed', error: data.error };
                            } else {
                                activeScans[scanId] = data;
                            }
                            
                            updateScansList();
                            
                            if (data.status === 'running') {
                                setTimeout(() => pollScanStatus(scanId), 2000);
                            } else if (data.status === 'completed') {
                                showResults(scanId, data);
                            }
                        } catch (error) {
                            console.error('Error polling scan status:', error);
                            activeScans[scanId] = { status: 'failed', error: error.toString() };
                            updateScansList();
                        }
                    }
                    
                    function updateScansList() {
                        const scansList = document.getElementById('scansList');
                        scansList.innerHTML = '';
                        
                        Object.entries(activeScans).forEach(([scanId, scanData]) => {
                            const div = document.createElement('div');
                            div.className = 'scan-item';
                            let statusHTML = `<span class="scan-status status-${scanData.status}">${scanData.status.toUpperCase()}</span>`;
                            
                            if (scanData.status === 'completed') {
                                statusHTML += ` <a href="/api/report/${scanId}" target="_blank">View Report</a>`;
                            } else if (scanData.status === 'failed' && scanData.error) {
                                statusHTML += ` <span style="color: #dc3545;">(${scanData.error})</span>`;
                            }
                            
                            div.innerHTML = `
                                <strong>${scanId}</strong>
                                ${statusHTML}
                            `;
                            scansList.appendChild(div);
                        });
                    }
                    
                    function showResults(scanId, scanData) {
                        const resultsDiv = document.getElementById('results');
                        resultsDiv.innerHTML = `
                            <h3>Scan ${scanId} Completed</h3>
                            <p>Total findings: ${scanData.stats?.total || 0}</p>
                            <p><a href="/api/report/${scanId}" target="_blank">Open Detailed Report</a></p>
                        `;
                    }
                    
                    // Load existing scans on page load
                    async function loadScans() {
                        try {
                            const response = await fetch('/api/scans');
                            const data = await response.json();
                            
                            if (data.scans) {
                                data.scans.forEach(scan => {
                                    activeScans[scan.id] = scan;
                                    if (scan.status === 'running') {
                                        pollScanStatus(scan.id);
                                    }
                                });
                                
                                updateScansList();
                            }
                        } catch (error) {
                            console.error('Error loading scans:', error);
                        }
                    }
                    
                    // Initialize
                    loadScans();
                </script>
            </body>
            </html>
            '''
        
        @app.route('/api/scan', methods=['POST'])
        def start_scan():
            data = request.json
            target = data.get('target')
            
            if not target:
                return jsonify({'error': 'Target path is required'}), 400
            
            target_path = Path(target)
            if not target_path.exists():
                return jsonify({'error': 'Target path does not exist'}), 400
            
            # Generate scan ID
            scan_id = f"web_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Start scan in background thread
            def run_scan():
                try:
                    # Create web_scans directory if it doesn't exist
                    web_scans_dir = Path("web_scans")
                    web_scans_dir.mkdir(parents=True, exist_ok=True)
                    
                    detector = BackdoorDetector(
                        str(target_path),
                        output_dir=f"web_scans/{scan_id}",
                        yara_rules_dir=data.get('yara_rules_dir', 'yara_rules')
                    )
                    
                    current_scans[scan_id] = {
                        'status': 'running',
                        'detector': detector,
                        'start_time': datetime.now()
                    }
                    
                    try:
                        result = detector.run_full_analysis(
                            runtime_timeout=int(data.get('timeout', 30))
                        )
                        
                        current_scans[scan_id]['status'] = 'completed'
                        current_scans[scan_id]['result'] = result
                        current_scans[scan_id]['end_time'] = datetime.now()
                        
                    except Exception as e:
                        current_scans[scan_id]['status'] = 'failed'
                        current_scans[scan_id]['error'] = str(e)
                        logger.error(f"Scan {scan_id} failed: {e}")
                        
                except Exception as e:
                    logger.error(f"Failed to initialize scan {scan_id}: {e}")
            
            thread = threading.Thread(target=run_scan, daemon=True)
            thread.start()
            
            return jsonify({'scan_id': scan_id, 'status': 'started'})
        
        @app.route('/api/scan/<scan_id>')
        def get_scan_status(scan_id):
            scan = current_scans.get(scan_id)
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            
            response = {'scan_id': scan_id, 'status': scan['status']}
            
            if scan['status'] == 'completed':
                result = scan.get('result')
                if result:
                    response['stats'] = result.get_stats()
                    response['report_path'] = f"/api/report/{scan_id}"
            
            elif scan['status'] == 'failed':
                response['error'] = scan.get('error', 'Unknown error')
            
            return jsonify(response)
        
        @app.route('/api/report/<scan_id>')
        def get_report(scan_id):
            scan = current_scans.get(scan_id)
            if not scan or scan['status'] != 'completed':
                return jsonify({'error': 'Report not available'}), 404
            
            # Find HTML report
            detector = scan['detector']
            html_files = list(detector.output_dir.glob("*.html"))
            
            if not html_files:
                return jsonify({'error': 'Report not found'}), 404
            
            latest_report = max(html_files, key=lambda x: x.stat().st_mtime)
            return send_file(str(latest_report.absolute()))
        
        @app.route('/api/scans')
        def list_scans():
            scans = []
            for scan_id, scan_data in current_scans.items():
                scans.append({
                    'id': scan_id,
                    'status': scan_data['status'],
                    'start_time': scan_data.get('start_time').isoformat() if scan_data.get('start_time') else None,
                    'target': str(scan_data.get('detector').target) if scan_data.get('detector') else None
                })
            
            return jsonify({'scans': scans})
        
        # Start Flask app
        logger.info(f"Starting web interface at http://{host}:{port}")
        app.run(host=host, port=port, debug=False, use_reloader=False)
        
    except ImportError as e:
        logger.error(f"Failed to import Flask: {e}")
        logger.error("Install Flask with: pip install flask")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Backdoor Detection Tool v2.0")
    parser.add_argument("target", nargs="?", help="Path to the software to analyze")
    parser.add_argument("--mode", choices=["cli", "gui", "web"], default="cli",
                       help="Interface mode (default: cli)")
    parser.add_argument("--runtime", type=int, default=30,
                       help="Runtime analysis duration in seconds")
    parser.add_argument("--output", default="scan_results",
                       help="Output directory for reports")
    parser.add_argument("--yara-rules", default="yara_rules",
                       help="Directory containing YARA rules")
    parser.add_argument("--host", default="127.0.0.1",
                       help="Web interface host (for web mode)")
    parser.add_argument("--port", type=int, default=5000,
                       help="Web interface port (for web mode)")
    
    args = parser.parse_args()
    
    if args.mode == "gui":
        try:
            gui = BackdoorDetectorGUI()
            gui.run()
        except Exception as e:
            logger.error(f"Failed to start GUI: {e}")
            logger.error("Make sure tkinter is installed (usually comes with Python)")
    
    elif args.mode == "web":
        start_web_interface(host=args.host, port=args.port)
    
    else:  # CLI mode
        if not args.target:
            parser.error("target is required for CLI mode")
        
        detector = BackdoorDetector(
            target_path=args.target,
            output_dir=args.output,
            yara_rules_dir=args.yara_rules
        )
        
        result = detector.run_full_analysis(runtime_timeout=args.runtime)
        
        # Print summary
        stats = result.get_stats()
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Target: {args.target}")
        print(f"Total findings: {stats['total']}")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats['by_severity'].get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        print(f"\nReport saved to: {detector.output_dir}")
        print("="*60)


if __name__ == "__main__":
    main()
