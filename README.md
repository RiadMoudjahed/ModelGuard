# 🛡️ ModelGuard - AI Model Security Scanner

<div align="center">

**Professional-grade security scanning for AI/ML models with AI-powered threat analysis**
  
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: ModelGuard](https://img.shields.io/badge/security-ModelGuard-green.svg)](https://github.com/RiadMoudjahed/modelguard)

</div>

ModelGuard is a comprehensive security analysis tool that scans AI/ML models for malicious code, backdoors, and security vulnerabilities. It uses advanced detection techniques including entropy analysis, pattern matching, and optional AI-powered deep analysis via local Ollama.

---

## 🎯 Key Features

### Core Security Scanning
- ✅ **Pickle Exploit Detection** - Detects malicious code in PyTorch .pt/.pth files
- ✅ **Binary Analysis** - Smart executable detection with false-positive reduction
- ✅ **GGUF Format Support** - Specialized analysis for GGUF quantized models
- ✅ **Entropy Analysis** - Identifies obfuscated/encoded malicious payloads
- ✅ **Network Indicators** - Detects suspicious URLs, IPs, and C2 servers
- ✅ **Metadata Validation** - Checks config files for `trust_remote_code` and other risks

### AI-Powered Analysis (Optional)
- 🤖 **Local AI Analysis** - Uses Ollama for deep threat assessment
- 🎯 **Context-Aware Detection** - Reduces false positives with intelligent pattern recognition
- 📊 **Confidence Scoring** - AI provides confidence levels for its assessments
- 💡 **Actionable Recommendations** - Get specific security advice for each finding

### Multiple Output Formats
- 📄 Text reports (human-readable)
- 📊 JSON (for automation/CI/CD)
- 📝 Markdown (for documentation)
- 🌐 HTML (for viewing in browser)

### Source Trust Analysis
- 🏢 **Publisher Verification** - Checks against known trusted organizations
- 📈 **Download Statistics** - Validates community vetting through download counts
- 📅 **Model Age Analysis** - Flags newly created models with less vetting
- 🔗 **HuggingFace Integration** - Fetches repository metadata for validation

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/RiadMoudjahed/ModelGuard.git
cd ModelGuard

# Install Python dependencies
pip install requests

# (Optional) Install Ollama for AI-powered analysis
# Visit: https://ollama.ai
# Then: ollama pull qwen2.5
```

### Basic Usage

```bash
# Scan a single model
python modelguard_cli.py scan model.gguf

# Scan with AI-powered analysis
python modelguard_cli.py scan model.pt --ai-analysis

# Scan with verbose output
python modelguard_cli.py scan model.gguf --ai-analysis --verbose

# Generate HTML report
python modelguard_cli.py scan model.safetensors --format html -o report.html

# Batch scan directory
python modelguard_cli.py scan ./models/ --ai-analysis
```

---

## 📋 Supported Model Formats

| Format | Extensions | Features |
|--------|-----------|----------|
| **PyTorch** | `.pt`, `.pth`, `.bin`, `.ckpt` | Pickle exploit detection, binary analysis |
| **GGUF** | `.gguf` | Specialized GGUF parser, metadata validation |
| **SafeTensors** | `.safetensors` | Safe format validation, metadata checks |
| **ONNX** | `.onnx` | Binary analysis, format verification |
| **TensorFlow** | `.pb`, `.h5` | SavedModel analysis, Keras validation |
| **Generic Pickle** | `.pkl` | Full pickle opcode analysis |

---

## 🔍 Detection Capabilities

### Smart Detection Techniques

ModelGuard uses advanced techniques to minimize false positives:

#### 1. **Entropy-Based Detection**
```
High entropy (>6.5) = Likely obfuscated/compressed malicious code
Low entropy (<5.0) = Normal structured data
```

#### 2. **Context-Aware Pattern Matching**
```python
# ❌ Won't flag: "evaluation_mode": true
# ✅ Will flag: eval("malicious_code")
```

#### 3. **Executable Header Verification**
```
Checks if MZ/ELF signatures have valid header structures
Random binary data containing these bytes is marked as INFO, not CRITICAL
```

#### 4. **Trusted Domain Whitelisting**
```
HuggingFace, GitHub, ArXiv URLs = Legitimate metadata
Unknown domains with IPs/suspicious TLDs = Flagged as suspicious
```

---

## 📊 Risk Scoring System

ModelGuard provides clear risk scores to guide your decisions:

| Score | Level | Description | Action |
|-------|-------|-------------|--------|
| **0-10** | ✅ SAFE | No significant security concerns | Safe to use |
| **10-30** | ⚠️ LOW | Minor concerns (unknown publisher, etc.) | Review but likely safe |
| **30-50** | ⚠️ MEDIUM | Exercise caution (unknown URLs, unusual patterns) | Verify source |
| **50-70** | 🚨 HIGH | Serious issues (suspicious URLs, obfuscation) | Use only if trusted |
| **70-100** | 🔴 CRITICAL | Severe threats (real executables, malicious code) | DO NOT USE |

---

## 🤖 AI-Powered Analysis

### Setup Ollama (Optional but Recommended)

```bash
# 1. Install Ollama
# Visit: https://ollama.ai

# 2. Pull a model (choose one)
ollama pull qwen2.5:0.5b      # Fast & lightweight (< 1GB)
ollama pull llama3.2          # Balanced (3GB)
ollama pull mistral           # High quality (7GB)

# 3. Start Ollama (if not auto-started)
ollama serve

# 4. Run ModelGuard with AI analysis
python modelguard_cli.py scan model.gguf --ai-analysis
```

### AI Analysis Features

- **Deep Threat Assessment** - AI analyzes patterns and context
- **Risk Explanation** - Clear reasoning for risk levels
- **Prioritized Recommendations** - Actionable steps to mitigate risks
- **False Positive Reduction** - AI distinguishes legitimate vs malicious patterns

### Auto-Detection

ModelGuard automatically detects available Ollama models:

```bash
# No need to specify model - it auto-detects!
python modelguard_cli.py scan model.gguf --ai-analysis

# Or specify a specific model
python modelguard_cli.py scan model.gguf --ai-analysis --ollama-model "mistral"
```

---

## 🎨 Output Examples

### Text Report (Default)
```
================================================================================
                        MODELGUARD SECURITY SCAN REPORT
================================================================================

RISK ASSESSMENT
--------------------------------------------------------------------------------
Overall Risk Score: 5.0/100
Trust Score: 95.0/100
Risk Level: SAFE

FINDINGS SUMMARY
--------------------------------------------------------------------------------
Total Findings: 2
  INFO: 2

AI ANALYSIS SUMMARY
--------------------------------------------------------------------------------
This model appears to be a legitimate GGUF quantized model from a trusted
source. No malicious patterns detected. The URLs found are legitimate model
metadata from HuggingFace.

Confidence: 90%
```

### JSON Output (For Automation)
```json
{
  "model_name": "Llama-3-8B-Q4_K_M.gguf",
  "risk_score": 5.0,
  "trust_score": 95.0,
  "risk_level": "SAFE",
  "findings": [
    {
      "severity": "INFO",
      "category": "Model Metadata",
      "title": "Trusted URLs Found",
      "description": "Model contains URLs from trusted sources"
    }
  ],
  "ai_analysis": {
    "summary": "Legitimate model from trusted source",
    "confidence": 0.9
  }
}
```

---

## ⚙️ Advanced Usage

### Command-Line Options

```bash
# Core options
python modelguard_cli.py scan <model_file>
  -v, --verbose              # Detailed logging
  -o, --output FILE          # Save report to file
  -f, --format FORMAT        # Report format: text|json|markdown|html

# AI analysis
  --ai-analysis              # Enable AI-powered analysis
  --ollama-model MODEL       # Specify Ollama model (default: auto)
  --ollama-url URL           # Ollama server URL (default: localhost:11434)

# Source verification
  --check-source             # Verify model source/publisher
  --repo-id REPO_ID          # HuggingFace repo (e.g., "meta-llama/Llama-3-8B")

# Advanced options
  --no-metadata              # Skip metadata validation
  --version                  # Show version
```

### Batch Scanning

```bash
# Scan entire directory
python modelguard_cli.py scan ~/models/ --ai-analysis

# Scan with pattern matching
python modelguard_cli.py scan ~/Downloads/*.gguf --ai-analysis --format json

# Output summary
python modelguard_cli.py scan ./models/ --ai-analysis -o batch-report.json
```

### CI/CD Integration

```yaml
# .github/workflows/model-security.yml
name: Model Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install requests
      
      - name: Scan models
        run: |
          python modelguard_cli.py scan models/ --format json -o scan-results.json
      
      - name: Check risk score
        run: |
          python -c "
          import json
          with open('scan-results.json') as f:
              data = json.load(f)
              if data['risk_score'] > 50:
                  exit(1)
          "
```

---

## 🧪 Testing & Validation

### Run Diagnostics

```bash
# Test Ollama connection
python ollama_connection_diagnostics.py

# Test with verbose output
python modelguard_cli.py scan test-model.gguf --verbose

# Validate specific model
python modelguard_cli.py scan known-good-model.gguf --ai-analysis
```

### Example Test Cases

**Test 1: Clean Model**
```bash
python modelguard_cli.py scan Llama-3-8B-Q4.gguf --ai-analysis
# Expected: Risk Score < 10 (SAFE)
```

**Test 2: Unknown Source**
```bash
python modelguard_cli.py scan random-model.pt --check-source
# Expected: Risk Score 30-50 (MEDIUM) - Unknown publisher
```

**Test 3: Malicious Pattern Detection**
```bash
# Create test file with malicious patterns
python -c "import pickle; pickle.dump(__import__('os').system, open('bad.pkl', 'wb'))"
python modelguard_cli.py scan bad.pkl
# Expected: Risk Score > 70 (CRITICAL)
```

---

## 📖 Understanding Findings

### Severity Levels Explained

#### 🔴 CRITICAL
- **Real executable code** embedded in model
- **Actual malicious patterns** (os.system(), eval() with code)
- **Command & control URLs** with IPs/ports
- **Action**: DO NOT USE - Delete immediately

#### 🚨 HIGH
- **Suspicious code patterns** (subprocess calls, network operations)
- **Unknown URLs** with suspicious characteristics
- **Obfuscated code** (high entropy)
- **Action**: Only use if from verified trusted source

#### ⚠️ MEDIUM
- **Unknown publisher** or low download count
- **URLs from unknown domains** (but not suspicious)
- **Unusual metadata** or configuration
- **Action**: Verify source before deployment

#### ℹ️ LOW/INFO
- **Binary patterns** that coincidentally match signatures
- **Trusted URLs** (HuggingFace, GitHub, etc.)
- **Standard metadata** and structure
- **Action**: Safe - just informational

---

## 🔧 Troubleshooting

### "Ollama not available" Error

```bash
# 1. Check if Ollama is installed
ollama --version

# 2. Check if Ollama is running
curl http://localhost:11434/api/tags

# 3. Start Ollama
ollama serve

# 4. Pull a model
ollama pull qwen2.5

# 5. Test connection
python ollama_connection_diagnostics.py
```

### False Positives

If you get false positives (legitimate models flagged as CRITICAL):

1. **Update to latest version** - We continuously improve detection
2. **Use AI analysis** - Helps reduce false positives
3. **Check verbose output** - See why it was flagged
4. **Report the issue** - Help us improve the tool

### High Risk Score on Known Good Models

```bash
# Check specific findings
python modelguard_cli.py scan model.gguf --verbose

# Verify with AI analysis
python modelguard_cli.py scan model.gguf --ai-analysis

# Check source trust
python modelguard_cli.py scan model.gguf --check-source --repo-id "publisher/model"
```

---

## 🏗️ Architecture

```
modelguard/
├── modelguard_cli.py          # Main CLI interface
├── modelguard_core.py         # Core scanning engine
├── modelguard_advanced.py     # GGUF, metadata, source analysis
├── modelguard_ollama.py       # AI-powered analysis via Ollama
├── modelguard_reports.py      # Multi-format report generation
├── requirements.txt           # Requirements file
└── ollama_connection_diagnostics.py  # Diagnostic tool
```

### Key Components

- **PickleExploitDetector** - Analyzes pickle opcodes for malicious patterns
- **BinaryAnalyzer** - Smart binary file analysis with context awareness
- **GGUFAnalyzer** - Specialized parser for GGUF format
- **MetadataValidator** - Validates config files and metadata
- **SourceTrustAnalyzer** - Evaluates model source trustworthiness
- **OllamaAnalyzer** - AI-powered deep threat analysis
- **ReportGenerator** - Multi-format report generation

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Report Issues
- False positives/negatives
- Unsupported model formats
- Feature requests

### Submit Pull Requests
- New detection techniques
- Additional model format support
- Performance improvements
- Documentation updates

### Development Setup

```bash
# Clone repository
git clone https://github.com/RiadMoudjahed/ModelGuard.git
cd modelguard

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Format code
black modelguard*.py

# Type checking
mypy modelguard*.py
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 🙏 Acknowledgments

- **Pickle Security Research** - Based on documented pickle exploits and CVEs
- **Ollama Project** - For making local AI inference accessible
- **HuggingFace** - For the model hub and community
- **Security Community** - For ongoing research into AI model security

---

## 📚 Additional Resources

### External Resources
- [Pickle Security (CVE-2022-45061)](https://nvd.nist.gov/vuln/detail/CVE-2022-45061)
- [AI Model Security Best Practices](https://arxiv.org/abs/2302.04237)
- [GGUF Format Specification](https://github.com/ggerganov/ggml/blob/master/docs/gguf.md)
- [Ollama Documentation](https://github.com/ollama/ollama)

---

## 🔒 Security Notice

ModelGuard is a security tool designed to help identify threats in AI models. While it uses advanced techniques and AI-powered analysis, **no security tool is 100% accurate**. Always:

- ✅ Download models from trusted sources (HuggingFace verified publishers, official repos)
- ✅ Verify checksums when available
- ✅ Review ModelGuard findings carefully
- ✅ Use sandboxed environments for testing suspicious models
- ✅ Keep ModelGuard updated for latest detection techniques
- ❌ Don't rely solely on automated scanning
- ❌ Don't load models with CRITICAL findings

**Use at your own risk. The authors are not responsible for any damage caused by malicious models.**

---

<div align="center">

**⭐ Star us on GitHub if ModelGuard helps secure your AI models!**

Made with ❤️ by Riad


</div>
