"""
ModelGuard - Advanced Analyzers (FIXED)
GGUF, Metadata, Source Trust, and Weight Analysis
"""

import json
import struct
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta


class GGUFAnalyzer:
    """Analyzes GGUF format models"""

    GGUF_MAGIC = 0x46554747  # 'GGUF' in little endian

    # Smart technique: Use ENTROPY-BASED DETECTION
    # Real metadata has LOW entropy (structured, predictable)
    # Malicious code has HIGH entropy (obfuscated, random-looking)

    # Whitelist: Standard GGUF metadata prefixes
    SAFE_METADATA_PREFIXES = {
        'general.', 'tokenizer.', 'llama.', 'mistral.', 'phi.', 'gpt.',
        'qwen.', 'gemma.', 'mpt.', 'falcon.', 'bloom.', 'opt.',
        'gptneox.', 'stablelm.', 'persimmon.', 'refact.', 'bert.',
        'nomic.', 'jina.', 'command-r.', 'dbrx.', 'olmo.', 'arctic.'
    }

    # Dangerous patterns: Only flag EXECUTABLE code patterns
    DANGEROUS_PATTERNS = [
        # Code execution functions with parentheses (actual calls)
        (r'eval\s*\([\'"].*?[\'"].*?\)', 'eval() function call'),
        (r'exec\s*\([\'"].*?[\'"].*?\)', 'exec() function call'),
        (r'__import__\s*\([\'"]os[\'"]|[\'"]subprocess[\'"]', 'dangerous module import'),
        (r'compile\s*\([\'"].*?[\'"].*?[\'"]exec[\'"]', 'compile() with exec mode'),

        # System commands
        (r'os\.system\s*\(', 'os.system() call'),
        (r'subprocess\.(run|Popen|call)\s*\(', 'subprocess execution'),
        (r'shell\s*=\s*True', 'shell command execution'),

        # Network operations with suspicious context
        (r'socket\.socket\s*\(.*?SOCK_STREAM', 'raw socket creation'),
        (r'requests\.(post|get)\s*\([\'"]http', 'HTTP request in metadata'),

        # Base64 decode + exec pattern (common in malware)
        (r'base64\.b64decode.*?exec', 'base64 decode with exec'),
        (r'zlib\.decompress.*?exec', 'compressed code execution'),
    ]

    def __init__(self):
        self.findings = []

    def analyze(self, file_path: str) -> Tuple[List[Any], Dict[str, Any]]:
        """Analyze GGUF file structure and metadata"""
        from modelguard_core import SecurityFinding, SeverityLevel

        self.findings = []
        metadata = {}

        try:
            with open(file_path, 'rb') as f:
                # Read header
                magic = struct.unpack('<I', f.read(4))[0]

                if magic != self.GGUF_MAGIC:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="GGUF Format",
                        title="Invalid GGUF Magic Number",
                        description=f"Expected 0x{self.GGUF_MAGIC:X}, got 0x{magic:X}",
                        recommendation="File may be corrupted or not a valid GGUF file"
                    ))
                    return self.findings, metadata

                # Read version
                version = struct.unpack('<I', f.read(4))[0]
                metadata['gguf_version'] = version

                if version > 3:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.LOW,  # Changed from MEDIUM - newer versions aren't dangerous
                        category="GGUF Format",
                        title=f"Newer GGUF Version: {version}",
                        description="Model uses newer GGUF version than commonly seen",
                        recommendation="Ensure your GGUF loader supports this version"
                    ))

                # Read tensor count and metadata count
                tensor_count = struct.unpack('<Q', f.read(8))[0]
                metadata_count = struct.unpack('<Q', f.read(8))[0]

                metadata['tensor_count'] = tensor_count
                metadata['metadata_entries'] = metadata_count

                # Sanity checks - increased threshold for modern large models
                if tensor_count > 50000:  # Increased from 10000
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.INFO,  # Changed from MEDIUM
                        category="GGUF Structure",
                        title=f"Large Tensor Count: {tensor_count}",
                        description="Model has a very large number of tensors (typical for large models)",
                        recommendation="This is normal for 70B+ parameter models"
                    ))

                # Read metadata entries (simplified)
                gguf_metadata = self._read_metadata(f, metadata_count)
                metadata['gguf_metadata'] = gguf_metadata

                # Check for suspicious metadata
                self._check_metadata_security(gguf_metadata)

        except Exception as e:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="GGUF Analysis",
                title="GGUF Analysis Error",
                description=f"Error analyzing GGUF file: {str(e)}"
            ))

        return self.findings, metadata

    def _read_metadata(self, f, count: int) -> Dict[str, Any]:
        """Read GGUF metadata entries (simplified)"""
        metadata = {}

        try:
            for _ in range(min(count, 100)):  # Limit to first 100 entries
                # Read key length and key
                key_len = struct.unpack('<Q', f.read(8))[0]
                if key_len > 1024:  # Sanity check
                    break
                key = f.read(key_len).decode('utf-8', errors='ignore')

                # Read value type
                value_type = struct.unpack('<I', f.read(4))[0]

                # Read value based on type (simplified)
                if value_type == 8:  # String
                    val_len = struct.unpack('<Q', f.read(8))[0]
                    if val_len > 10240:  # Limit string size
                        value = f"<large_string:{val_len}>"
                        f.seek(val_len, 1)
                    else:
                        value = f.read(val_len).decode('utf-8', errors='ignore')
                    metadata[key] = value
                else:
                    # Skip other types for simplicity
                    pass

        except Exception:
            pass

        return metadata

    def _check_metadata_security(self, metadata: Dict[str, Any]):
        """Check GGUF metadata for security issues using smart detection"""
        from modelguard_core import SecurityFinding, SeverityLevel
        import math

        for key, value in metadata.items():
            # Smart Technique #1: Whitelist standard metadata prefixes
            is_standard_metadata = any(key.startswith(prefix) for prefix in self.SAFE_METADATA_PREFIXES)

            if is_standard_metadata and isinstance(value, str) and len(value) < 1000:
                # Standard metadata with reasonable length - skip detailed checks
                continue

            value_str = str(value)

            # Smart Technique #2: Entropy Analysis for obfuscation detection
            entropy = self._calculate_entropy(value_str)
            if entropy > 6.5 and len(value_str) > 50:  # High entropy = possible obfuscation
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="GGUF Metadata",
                    title=f"High Entropy Data in Metadata: {key}",
                    description=f"Metadata contains high-entropy data (entropy: {entropy:.2f}) which may indicate obfuscation",
                    evidence=f"{key}: {value_str[:100]}...",
                    recommendation="High entropy in metadata may indicate encoded/obfuscated malicious code"
                ))

            # Smart Technique #3: Pattern-based detection with regex
            for pattern, description in self.DANGEROUS_PATTERNS:
                if re.search(pattern, value_str, re.IGNORECASE):
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="GGUF Metadata",
                        title=f"Malicious Code Pattern Detected: {key}",
                        description=f"Metadata contains {description}",
                        evidence=f"{key}: {value_str[:200]}",
                        recommendation="This metadata contains executable code patterns. DO NOT load this model."
                    ))

            # Smart Technique #4: Context-aware URL checking
            if not is_standard_metadata and isinstance(value, str):
                self._check_suspicious_urls(key, value)

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string data"""
        if not data:
            return 0.0

        import math
        from collections import Counter

        # Count character frequencies
        frequencies = Counter(data)
        total = len(data)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in frequencies.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def _check_suspicious_urls(self, key: str, value: str):
        """Smart URL checking - only flag truly suspicious ones"""
        from modelguard_core import SecurityFinding, SeverityLevel

        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', value)
        if not urls:
            return

        # Trusted domains (academic, major tech companies, model hosting)
        TRUSTED_DOMAINS = [
            'huggingface.co', 'github.com', 'arxiv.org', 'papers.nips.cc',
            'openai.com', 'meta.com', 'google.com', 'microsoft.com',
            'kaggle.com', 'paperswithcode.com', 'tensorflow.org',
            'pytorch.org', 'nvidia.com', 'anthropic.com', 'cohere.com',
            'together.ai', 'replicate.com', 'modal.com', 'anyscale.com'
        ]

        suspicious_urls = []
        for url in urls:
            url_lower = url.lower()

            # Check if URL is from trusted domain
            is_trusted = any(domain in url_lower for domain in TRUSTED_DOMAINS)

            # Check for suspicious URL patterns
            has_ip = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)
            has_suspicious_tld = any(tld in url_lower for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
            has_port = re.search(r':\d{2,5}/', url)  # Non-standard ports

            if not is_trusted and (has_ip or has_suspicious_tld or has_port):
                suspicious_urls.append(url)

        if suspicious_urls:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.HIGH,
                category="GGUF Metadata",
                title=f"Suspicious URLs in Metadata: {key}",
                description="Metadata contains URLs with suspicious characteristics (IP addresses, suspicious TLDs, or non-standard ports)",
                evidence=f"URLs: {', '.join(suspicious_urls[:3])}",
                recommendation="Verify these URLs before loading the model. They may be command-and-control servers."
            ))


class MetadataValidator:
    """Validates model metadata and configuration files"""

    def __init__(self):
        self.findings = []

    def validate(self, model_dir: str) -> Tuple[List[Any], Dict[str, Any]]:
        """Validate all metadata files in model directory"""
        from modelguard_core import SecurityFinding, SeverityLevel

        self.findings = []
        metadata = {}

        model_path = Path(model_dir)

        # Check for common metadata files
        config_files = [
            'config.json',
            'model_index.json',
            'generation_config.json',
            'preprocessor_config.json',
            'tokenizer_config.json',
            'README.md',
            'model_card.json'
        ]

        for config_file in config_files:
            config_path = model_path / config_file if model_path.is_dir() else model_path.parent / config_file

            if config_path.exists():
                self._validate_config_file(config_path, metadata)

        return self.findings, metadata

    def _validate_config_file(self, file_path: Path, metadata: Dict):
        """Validate individual config file"""
        from modelguard_core import SecurityFinding, SeverityLevel

        try:
            content = file_path.read_text(encoding='utf-8')

            # Try to parse as JSON if applicable
            if file_path.suffix == '.json':
                try:
                    config = json.loads(content)
                    metadata[file_path.name] = config

                    # Check for suspicious configurations
                    self._check_config_security(config, file_path.name)

                except json.JSONDecodeError as e:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.MEDIUM,
                        category="Metadata Validation",
                        title=f"Invalid JSON: {file_path.name}",
                        description=f"Config file is not valid JSON: {str(e)}",
                        recommendation="Verify file integrity"
                    ))

            # Check for suspicious content in any metadata
            self._check_content_security(content, file_path.name)

        except Exception as e:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.LOW,
                category="Metadata Validation",
                title=f"Error Reading {file_path.name}",
                description=f"Could not read metadata file: {str(e)}"
            ))

    def _check_config_security(self, config: Dict, filename: str):
        """Check configuration for security issues"""
        from modelguard_core import SecurityFinding, SeverityLevel

        for key, value in self._flatten_dict(config).items():
            key_lower = str(key).lower()

            # Check for trust_remote_code - this is the REAL security issue
            if 'trust_remote_code' in key_lower:
                if value is True:
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.CRITICAL,
                        category="Remote Code Execution",
                        title="trust_remote_code Enabled",
                        description=f"Config file {filename} has trust_remote_code=true",
                        evidence=f"{key}: {value}",
                        recommendation="This allows arbitrary code execution. Only use with trusted models from known sources."
                    ))

            # Check for actual dangerous patterns (not common config keys)
            dangerous_patterns = ['__import__', 'eval(', 'exec(', 'compile(',
                                  'subprocess', 'os.system', 'shell=True']

            if any(dangerous in str(value).lower() for dangerous in dangerous_patterns):
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="Config Security",
                    title=f"Dangerous Code in Config: {key}",
                    description=f"Configuration contains code execution patterns in {filename}",
                    evidence=f"{key}: {str(value)[:100]}",
                    recommendation="This config contains code execution patterns. Review carefully."
                ))

    def _check_content_security(self, content: str, filename: str):
        """Check file content for security issues"""
        from modelguard_core import SecurityFinding, SeverityLevel

        # Check for embedded scripts with actual dangerous code
        dangerous_patterns = [
            (r'<script[^>]*>.*?</script>', 'Executable HTML script tag'),
            (r'javascript:\s*eval\s*\(', 'JavaScript eval URI'),
            (r'eval\s*\(\s*["\']', 'eval() with string literal'),
            (r'exec\s*\(\s*["\']', 'exec() with string literal'),
            (r'__import__\s*\(\s*["\']os["\']', 'Dynamic OS import'),
        ]

        for pattern, desc in dangerous_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.HIGH,
                    category="Embedded Code",
                    title=f"Dangerous Code Pattern in {filename}",
                    description=f"File contains {desc}",
                    recommendation="Review file for malicious code"
                ))

    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)


class SourceTrustAnalyzer:
    """Analyzes model source trustworthiness"""

    TRUSTED_ORGS = {
        'openai', 'google', 'meta', 'microsoft', 'anthropic',
        'huggingface', 'stabilityai', 'eleutherai', 'bigscience',
        'facebook', 'nvidia', 'mistralai', 'cohere', 'databricks',
        'apple', 'deepmind', 'together', 'allenai'
    }

    VERIFIED_PUBLISHERS = {
        'TheBloke', 'stabilityai', 'runwayml', 'CompVis',
        'bartowski', 'NousResearch', 'teknium', 'Phind',
        'WizardLM', 'lmsys', 'mosaicml'
    }

    def __init__(self):
        self.findings = []

    def analyze(self, model_info: Dict[str, Any]) -> Tuple[List[Any], float]:
        """Analyze model source and calculate trust score"""
        from modelguard_core import SecurityFinding, SeverityLevel

        self.findings = []
        trust_score = 50.0  # Start neutral

        # Check author/organization
        author = model_info.get('author', '').lower()
        org = model_info.get('organization', '').lower()

        if author in self.TRUSTED_ORGS or org in self.TRUSTED_ORGS:
            trust_score += 30
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.INFO,
                category="Source Trust",
                title="Trusted Organization",
                description=f"Model from recognized organization: {author or org}",
                recommendation="Generally trustworthy source"
            ))
        elif author in self.VERIFIED_PUBLISHERS:
            trust_score += 20
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.INFO,
                category="Source Trust",
                title="Verified Publisher",
                description=f"Model from verified publisher: {author}",
                recommendation="Known community contributor"
            ))
        else:
            trust_score -= 10
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Source Trust",
                title="Unknown Publisher",
                description=f"Model from unverified source: {author or 'unknown'}",
                recommendation="Exercise caution with unknown sources"
            ))

        # Check download count
        downloads = model_info.get('downloads', 0)
        if downloads > 100000:
            trust_score += 15
        elif downloads > 10000:
            trust_score += 10
        elif downloads < 100:
            trust_score -= 15
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.MEDIUM,
                category="Source Trust",
                title=f"Low Download Count: {downloads}",
                description="Model has very few downloads",
                recommendation="Less vetted by community"
            ))

        # Check model age
        created = model_info.get('created_at')
        if created:
            try:
                created_date = datetime.fromisoformat(created.replace('Z', '+00:00'))
                age_days = (datetime.now(created_date.tzinfo) - created_date).days

                if age_days < 7:
                    trust_score -= 20
                    self.findings.append(SecurityFinding(
                        severity=SeverityLevel.HIGH,
                        category="Source Trust",
                        title=f"Very New Model: {age_days} days old",
                        description="Model was created very recently",
                        recommendation="Newly created models have less community vetting"
                    ))
                elif age_days > 365:
                    trust_score += 10
            except Exception:
                pass

        # Check for license
        license_info = model_info.get('license', '')
        if license_info and license_info != 'unknown':
            trust_score += 5
        else:
            self.findings.append(SecurityFinding(
                severity=SeverityLevel.LOW,
                category="Source Trust",
                title="No License Information",
                description="Model has no clear license",
                recommendation="Verify usage rights before deployment"
            ))

        # Ensure trust score is in valid range
        trust_score = max(0.0, min(100.0, trust_score))

        return self.findings, trust_score

    def check_huggingface_repo(self, repo_id: str) -> Dict[str, Any]:
        """Fetch HuggingFace repository information (if online)"""
        try:
            import requests

            api_url = f"https://huggingface.co/api/models/{repo_id}"
            response = requests.get(api_url, timeout=10)

            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'HTTP {response.status_code}'}

        except ImportError:
            return {'error': 'requests library not available'}
        except Exception as e:
            return {'error': str(e)}


class WeightAnomalyDetector:
    """Detects anomalies in model weights (statistical analysis)"""

    def __init__(self):
        self.findings = []

    def analyze(self, weights_info: Dict[str, Any]) -> List[Any]:
        """Analyze weight statistics for anomalies"""
        from modelguard_core import SecurityFinding, SeverityLevel

        self.findings = []

        # This is a placeholder for advanced weight analysis
        # Would require actually loading weights which may be memory intensive

        # Check for unusual weight patterns (basic checks)
        if 'shapes' in weights_info:
            shapes = weights_info['shapes']

            # Check for suspiciously small models
            total_params = sum(self._calculate_params(shape) for shape in shapes.values())

            if total_params < 1000:
                self.findings.append(SecurityFinding(
                    severity=SeverityLevel.MEDIUM,
                    category="Weight Analysis",
                    title=f"Unusually Small Model: {total_params} parameters",
                    description="Model has very few parameters",
                    recommendation="Verify this is the intended model"
                ))

        return self.findings

    def _calculate_params(self, shape) -> int:
        """Calculate number of parameters from shape"""
        if isinstance(shape, (list, tuple)):
            result = 1
            for dim in shape:
                result *= dim
            return result
        return 0


if __name__ == "__main__":
    print("ModelGuard Advanced Analyzers Module (Fixed)")
    print("Use with modelguard_core.py")