"""
ModelGuard - AI Model Security Scanner
A comprehensive security analysis tool for AI/ML models
"""

import os
import sys
import hashlib
import pickletools
import zipfile
import math
import io
import json
import struct
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum


class SeverityLevel(Enum):
    """Security issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class SecurityFinding:
    """Represents a single security finding"""
    severity: SeverityLevel
    category: str
    title: str
    description: str
    evidence: Optional[str] = None
    recommendation: str = ""
    cve_references: List[str] = None

    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []


@dataclass
class ScanResult:
    """Complete scan results for a model"""
    model_path: str
    model_name: str
    scan_timestamp: str
    file_format: str
    file_size: int
    file_hash_sha256: str
    findings: List[SecurityFinding]
    metadata: Dict[str, Any]
    risk_score: float
    trust_score: float

    def to_dict(self):
        result = asdict(self)
        result['findings'] = [
            {**asdict(f), 'severity': f.severity.value}
            for f in self.findings
        ]
        return result


class PickleExploitDetector:
    """Detects malicious patterns in pickle files"""

    DANGEROUS_OPCODES = {
        'GLOBAL', 'INST', 'OBJ', 'NEWOBJ', 'NEWOBJ_EX',
        'BUILD', 'REDUCE', 'STACK_GLOBAL'
    }

    SUSPICIOUS_MODULES = {
        'os', 'subprocess', 'socket', 'requests', 'urllib',
        'eval', 'exec', 'compile', '__builtin__', 'builtins',
        'pty', 'nt', 'posix', 'signal', 'ctypes', 'importlib'
    }

    SUSPICIOUS_FUNCTIONS = {
        'system', 'popen', 'exec', 'eval', 'compile',
        '__import__', 'open', 'input', 'raw_input',
        'execfile', 'reload', 'breakpoint'
    }

    def __init__(self):
        self.findings = []

    def analyze_pickle(self, file_path: str) -> List[SecurityFinding]:
        """Analyze pickle file for security issues"""
        self.findings = []

        try:
            for data in self._load_pickle_streams(file_path):
                # Analyze opcodes
                self._analyze_opcodes(data)

                # Check for embedded code
                self._check_embedded_code(data)

                # Analyze pickle structure
                self._analyze_structure(data)

        except Exception as e:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Analysis Error",
                title="Pickle Analysis Failed",
                description=f"Failed to analyze pickle file: {str(e)}",
                recommendation="Manual inspection required"
            ))

        return self.findings

    @staticmethod
    def _load_pickle_streams(file_path: str) -> List[bytes]:
        """Return the pickle byte streams contained in a file.

        PyTorch >= 1.6 saves models as ZIP archives with the pickle stored in
        ``<archive>/data.pkl``; older files and plain .pkl files are raw pickles.
        """
        if zipfile.is_zipfile(file_path):
            streams = []
            with zipfile.ZipFile(file_path) as zf:
                for name in zf.namelist():
                    if name.endswith('.pkl'):
                        streams.append(zf.read(name))
            return streams

        with open(file_path, 'rb') as f:
            return [f.read()]

    def _analyze_opcodes(self, data: bytes):
        """Analyze pickle opcodes for suspicious patterns"""
        try:
            # Recent string pushes, used to resolve STACK_GLOBAL (protocol 4+),
            # which takes module and name from the stack instead of an argument.
            recent_strings: List[str] = []

            for opcode, arg, pos in pickletools.genops(data):
                opname = opcode.name

                if opname in ('SHORT_BINUNICODE', 'BINUNICODE', 'BINUNICODE8',
                              'UNICODE', 'SHORT_BINSTRING', 'BINSTRING', 'STRING'):
                    recent_strings = (recent_strings + [str(arg)])[-2:]
                    continue

                if opname == 'STACK_GLOBAL':
                    if len(recent_strings) == 2:
                        arg = f"{recent_strings[0]} {recent_strings[1]}"
                        opname = 'GLOBAL'
                    else:
                        arg = None
                elif opname in ('MEMOIZE', 'BINPUT', 'LONG_BINPUT', 'PUT'):
                    continue  # memo ops sit between the strings and STACK_GLOBAL
                else:
                    recent_strings = []

                # Check for dangerous opcodes
                if opname in self.DANGEROUS_OPCODES:
                    self._check_dangerous_opcode(opname, arg, pos)

        except Exception as e:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Opcode Analysis",
                title="Opcode Analysis Error",
                description=f"Error analyzing opcodes: {str(e)}"
            ))

    def _check_dangerous_opcode(self, opname: str, arg: Any, pos: int):
        """Check if a dangerous opcode is being used maliciously"""
        if opname == 'GLOBAL' and arg:
            module, _, func = str(arg).partition(' ')
            root_module = module.split('.')[0]

            if module in self.SUSPICIOUS_MODULES or root_module in self.SUSPICIOUS_MODULES:
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.CRITICAL,
                    category="Pickle Exploit",
                    title=f"Suspicious Module Import: {module}",
                    description=f"Pickle contains import of suspicious module '{module}' at position {pos}",
                    evidence=f"GLOBAL opcode: {module}.{func}",
                    recommendation="This module can be used for code execution. Verify model source."
                ))

            if func in self.SUSPICIOUS_FUNCTIONS:
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.CRITICAL,
                    category="Pickle Exploit",
                    title=f"Dangerous Function Call: {func}",
                    description=f"Pickle attempts to call dangerous function '{func}' at position {pos}",
                    evidence=f"Function: {module}.{func}",
                    recommendation="This function can execute arbitrary code. DO NOT load this model."
                ))

        elif opname in ['REDUCE', 'BUILD']:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="Pickle Exploit",
                title=f"Object Construction Opcode: {opname}",
                description=f"Pickle uses {opname} opcode which can trigger arbitrary code",
                evidence=f"Position: {pos}",
                recommendation="Review the full pickle structure for malicious patterns"
            ))

    def _check_embedded_code(self, data: bytes):
        """Check for embedded shell commands or suspicious strings"""
        suspicious_patterns = [
            b'/bin/sh', b'/bin/bash', b'cmd.exe', b'powershell',
            b'wget', b'curl', b'http://', b'https://',
            b'eval(', b'exec(', b'__import__',
            b'reverse_shell', b'backdoor'
        ]

        for pattern in suspicious_patterns:
            if pattern in data:
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.CRITICAL,
                    category="Embedded Payload",
                    title=f"Suspicious String Found: {pattern.decode('utf-8', errors='ignore')}",
                    description="Model file contains suspicious strings that may indicate malicious code",
                    evidence=f"Pattern: {pattern.decode('utf-8', errors='ignore')}",
                    recommendation="This is a strong indicator of malicious intent. DO NOT load this model."
                ))

    def _analyze_structure(self, data: bytes):
        """Analyze overall pickle structure"""
        try:
            # Check pickle protocol version
            if len(data) > 1 and data[0] == 0x80:  # PROTO opcode
                protocol = data[1]
                if protocol > 5:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.LOW,
                        category="Protocol Version",
                        title=f"Unknown Pickle Protocol: {protocol}",
                        description="Model uses unknown pickle protocol version",
                        recommendation="Verify compatibility and security of protocol version"
                    ))
        except Exception:
            pass


class BinaryAnalyzer:
    """Analyzes binary patterns in model files"""

    def __init__(self):
        self.findings = []

    def analyze(self, file_path: str, file_format: str) -> List[SecurityFinding]:
        """Analyze binary file for anomalies"""
        self.findings = []

        try:
            with open(file_path, 'rb') as f:
                # Read in chunks for large files
                chunk_size = 1024 * 1024  # 1MB

                # Check file header
                header = f.read(1024)
                self._check_header(header, file_format)

                # Sample scanning (first 10MB)
                f.seek(0)
                sample_data = f.read(10 * 1024 * 1024)

                # Check for embedded executables
                self._check_embedded_executables(sample_data)

                # Check for network indicators
                self._check_network_indicators(sample_data)

                # Entropy analysis
                self._analyze_entropy(sample_data)

        except Exception as e:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Binary Analysis",
                title="Binary Analysis Error",
                description=f"Error during binary analysis: {str(e)}"
            ))

        return self.findings

    def _check_header(self, header: bytes, expected_format: str):
        """Verify file header matches expected format"""
        magic_numbers = {
            # Raw pickle (protocol 2-5) or ZIP archive (PyTorch >= 1.6)
            'pytorch': [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05', b'PK\x03\x04'],
            'gguf': [b'GGUF'],
        }

        if expected_format == 'safetensors':
            # 8-byte little-endian header length followed by a JSON object
            valid = len(header) > 8 and header[8:9] == b'{'
        elif expected_format in magic_numbers:
            valid = any(header.startswith(magic) for magic in magic_numbers[expected_format])
        else:
            return

        if not valid:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="File Format",
                title="Invalid File Header",
                description=f"File header doesn't match expected {expected_format} format",
                recommendation="File may be corrupted or mislabeled"
            ))

    def _check_embedded_executables(self, data: bytes):
        """Check for embedded executable code.

        Short signatures such as ``MZ`` occur by chance in any large binary, so a
        match is only reported as CRITICAL when a valid header structure follows.
        Unverified matches are reported as INFO.
        """
        verified = []
        unverified = []

        # Windows PE: "MZ" + e_lfanew offset pointing at "PE\0\0"
        for m in re.finditer(rb'MZ', data):
            off = m.start()
            if off + 0x40 <= len(data):
                e_lfanew = struct.unpack_from('<I', data, off + 0x3C)[0]
                pe = off + e_lfanew
                if 0 < e_lfanew < 0x1000 and data[pe:pe + 4] == b'PE\x00\x00':
                    verified.append(("Windows PE executable", off))
                    break
        else:
            if b'MZ' in data:
                unverified.append("Windows PE (MZ)")

        # Linux ELF: magic + valid class (1/2), data encoding (1/2) and version (1)
        for m in re.finditer(rb'\x7fELF', data):
            ei = data[m.start() + 4:m.start() + 7]
            if len(ei) == 3 and ei[0] in (1, 2) and ei[1] in (1, 2) and ei[2] == 1:
                verified.append(("Linux ELF executable", m.start()))
                break
        else:
            if b'\x7fELF' in data:
                unverified.append("Linux ELF")

        # macOS Mach-O: full 4-byte magic (32/64-bit, both byte orders)
        for magic in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                      b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
            idx = data.find(magic)
            if idx >= 0:
                verified.append(("macOS Mach-O executable", idx))
                break

        # Shell script: shebang followed by an interpreter path
        m = re.search(rb'#!\s*/(?:usr/)?(?:local/)?bin/(?:env\s+)?(?:ba|z|da|k)?sh\b|#!\s*/(?:usr/)?bin/(?:env\s+)?(?:python|perl|ruby)', data)
        if m:
            verified.append(("Shell/interpreter script", m.start()))

        for desc, offset in verified:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.CRITICAL,
                category="Embedded Executable",
                title=f"Embedded Executable Detected: {desc}",
                description="Model file contains embedded executable code with a valid header",
                evidence=f"Offset: {offset}",
                recommendation="Highly suspicious. This model should not be loaded."
            ))

        if unverified:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.INFO,
                category="Embedded Executable",
                title="Executable Signature Bytes (Unverified)",
                description="Executable signature bytes were found, but no valid header structure follows them. "
                            "This is common in random binary weight data.",
                evidence=f"Signatures: {', '.join(unverified)}",
                recommendation="Likely a coincidental byte match; no action needed unless other findings exist."
            ))

    def _check_network_indicators(self, data: bytes):
        """Check for network-related indicators"""
        # Look for URLs, IPs, domain patterns
        url_pattern = rb'https?://[^\s<>"{}|\\^`\[\]]+'
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

        urls = re.findall(url_pattern, data)
        ips = re.findall(ip_pattern, data)

        if urls:
            unique_urls = set(urls[:10])  # Limit to first 10 unique
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Network Indicators",
                title=f"URLs Found in Model: {len(unique_urls)} unique",
                description="Model contains embedded URLs",
                evidence=f"Examples: {', '.join(u.decode('utf-8', errors='ignore') for u in list(unique_urls)[:3])}",
                recommendation="Verify if URLs are legitimate model metadata or malicious"
            ))

        if ips:
            unique_ips = set(ips[:10])
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Network Indicators",
                title=f"IP Addresses Found: {len(unique_ips)} unique",
                description="Model contains embedded IP addresses",
                evidence=f"Examples: {', '.join(ip.decode('utf-8', errors='ignore') for ip in list(unique_ips)[:3])}",
                recommendation="Verify these IPs are not command and control servers"
            ))

    def _analyze_entropy(self, data: bytes):
        """Analyze data entropy (simplified)"""
        if len(data) < 1000:
            return

        # Calculate byte frequency
        freq = [0] * 256
        for byte in data[:100000]:  # Sample first 100KB
            freq[byte] += 1

        # Calculate entropy
        total = sum(freq)
        entropy = 0
        for count in freq:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        # High entropy might indicate encryption or compression
        if entropy > 7.8:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.INFO,
                category="Entropy Analysis",
                title=f"High Entropy Detected: {entropy:.2f}/8.0",
                description="File has high entropy which may indicate encryption or compression",
                recommendation="Verify if encryption is expected for this model format"
            ))


class FileFormatHandler:
    """Handles different model file formats"""

    @staticmethod
    def identify_format(file_path: str) -> str:
        """Identify the model file format"""
        ext = Path(file_path).suffix.lower()

        format_map = {
            '.pt': 'pytorch',
            '.pth': 'pytorch',
            '.bin': 'pytorch',
            '.ckpt': 'pytorch',
            '.pkl': 'pickle',
            '.gguf': 'gguf',
            '.safetensors': 'safetensors',
            '.onnx': 'onnx',
            '.pb': 'tensorflow',
            '.h5': 'keras'
        }

        detected = format_map.get(ext, 'unknown')

        # Verify with magic numbers if possible
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

            if header.startswith(b'GGUF'):
                return 'gguf'
            elif header[8:9] == b'{':
                # safetensors: 8-byte header length followed by JSON
                return 'safetensors'
            elif header.startswith(b'PK\x03\x04'):
                # ZIP archive: PyTorch >= 1.6 checkpoints (other zips keep their extension)
                if detected in ('pytorch', 'pickle', 'unknown'):
                    return 'pytorch'
            elif header[:1] == b'\x80' and detected != 'pickle':
                return 'pytorch'

        except Exception:
            pass

        return detected

    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        stat = os.stat(file_path)

        # Hash in chunks so multi-GB models are not loaded into memory
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()

        return {
            'size': stat.st_size,
            'size_mb': round(stat.st_size / (1024 * 1024), 2),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'sha256': file_hash
        }


class ModelScanner:
    """Main scanner orchestrator"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.pickle_detector = PickleExploitDetector()
        self.binary_analyzer = BinaryAnalyzer()

    def scan(self, file_path: str) -> ScanResult:
        """Perform complete security scan on a model file"""

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Model file not found: {file_path}")

        self._log(f"Starting scan: {file_path}")

        # Identify format
        file_format = FileFormatHandler.identify_format(file_path)
        self._log(f"Detected format: {file_format}")

        # Get file info
        file_info = FileFormatHandler.get_file_info(file_path)
        self._log(f"File size: {file_info['size_mb']} MB")

        # Collect all findings
        all_findings = []

        # Run pickle analysis if applicable
        if file_format in ['pytorch', 'pickle']:
            self._log("Running pickle exploit detection...")
            all_findings.extend(self.pickle_detector.analyze_pickle(file_path))

        # Run binary analysis
        self._log("Running binary analysis...")
        all_findings.extend(self.binary_analyzer.analyze(file_path, file_format))

        # Calculate risk score
        risk_score = self._calculate_risk_score(all_findings)

        # Create scan result
        result = ScanResult(
            model_path=file_path,
            model_name=Path(file_path).name,
            scan_timestamp=datetime.now().isoformat(),
            file_format=file_format,
            file_size=file_info['size'],
            file_hash_sha256=file_info['sha256'],
            findings=all_findings,
            metadata=file_info,
            risk_score=risk_score,
            trust_score=100 - risk_score
        )

        self._log(f"Scan complete. Risk score: {risk_score}/100")

        return result

    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall risk score (0-100)"""
        if not findings:
            return 0.0

        severity_weights = {
            SeverityLevel.CRITICAL: 40,
            SeverityLevel.HIGH: 20,
            SeverityLevel.MEDIUM: 10,
            SeverityLevel.LOW: 5,
            SeverityLevel.INFO: 1
        }

        total_score = sum(severity_weights.get(f.severity, 0) for f in findings)

        # Cap at 100
        return min(100.0, total_score)

    def _log(self, message: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[ModelGuard] {message}")


if __name__ == "__main__":
    # Basic test
    if len(sys.argv) > 1:
        scanner = ModelScanner(verbose=True)
        result = scanner.scan(sys.argv[1])

        print(f"\n{'=' * 60}")
        print(f"SCAN RESULTS: {result.model_name}")
        print(f"{'=' * 60}")
        print(f"Risk Score: {result.risk_score}/100")
        print(f"Trust Score: {result.trust_score}/100")
        print(f"Findings: {len(result.findings)}")

        for finding in result.findings:
            print(f"\n[{finding.severity.value}] {finding.title}")
            print(f"  {finding.description}")
    else:
        print("Usage: python modelguard_core.py <model_file>")