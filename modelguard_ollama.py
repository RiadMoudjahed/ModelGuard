"""
ModelGuard - AI-Powered Analysis Engine (FIXED v2)
Uses local Ollama for deep security analysis
Enhanced diagnostics and connection handling
"""

import json
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class AIAnalysisResult:
    """Result from AI analysis"""
    summary: str
    risk_assessment: str
    recommendations: List[str]
    confidence: float
    reasoning: str


class OllamaAnalyzer:
    """Uses local Ollama for AI-powered security analysis"""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "auto", verbose: bool = False):
        self.base_url = base_url.rstrip('/')  # Remove trailing slash
        self.model = model
        self.verbose = verbose
        self.available = False
        self.error_message = None
        self._check_availability()

    def _log(self, message: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[Ollama] {message}")

    def _check_availability(self) -> bool:
        """Check if Ollama is available and model exists - with multiple fallback methods"""

        # Method 1: Try /api/version endpoint (newer Ollama versions)
        self._log(f"Checking Ollama at {self.base_url}...")

        try:
            self._log("Method 1: Trying /api/version endpoint...")
            response = requests.get(f"{self.base_url}/api/version", timeout=5)

            if response.status_code == 200:
                self._log(f"✓ Ollama server is running (version endpoint)")
                # Continue to check models
            else:
                self._log(f"Version endpoint returned {response.status_code}, trying alternatives...")
        except requests.exceptions.ConnectionError:
            self.error_message = (
                "Cannot connect to Ollama server at {self.base_url}\n"
                "Is Ollama running? Start with: ollama serve\n"
                "Or check if it's running on a different port."
            )
            self._log(f"✗ Connection failed: {self.error_message}")
            self.available = False
            return False
        except Exception as e:
            self._log(f"Version check failed: {e}, trying alternatives...")

        # Method 2: Try /api/tags endpoint (most reliable)
        try:
            self._log("Method 2: Trying /api/tags endpoint...")
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)

            if response.status_code != 200:
                self.error_message = f"Ollama server returned status {response.status_code} for /api/tags"
                self._log(f"✗ Tags endpoint failed: {response.status_code}")

                # Try one more method before giving up
                return self._try_direct_generation()

            # Parse available models
            try:
                data = response.json()
                models = data.get('models', [])

                if not models:
                    self.error_message = (
                        f"No models installed in Ollama.\n"
                        f"Install a model with: ollama pull {self.model}"
                    )
                    self._log(f"✗ No models found")
                    self.available = False
                    return False

                # Log available models
                model_names = [m.get('name', '') for m in models]
                self._log(f"Found {len(models)} model(s): {', '.join(model_names[:5])}")

                # Auto-detect model if set to "auto"
                if self.model == "auto":
                    # Prefer smaller models for speed
                    # Priority: small instruction models > general models > code models
                    preferred_order = [
                        'qwen', 'phi', 'gemma', 'llama3.2', 'llama3.1',
                        'mistral', 'llama', 'deepseek', 'codellama'
                    ]

                    for preferred in preferred_order:
                        for m in models:  # Fixed: iterate over model objects, not names
                            m_name = m.get('name', '')
                            if preferred in m_name.lower():
                                self.model = m_name
                                self._log(f"✓ Auto-selected model: {self.model}")
                                self.available = True
                                return True

                    # If no preferred model, just use the first one
                    if models:
                        self.model = models[0].get('name', '')  # Fixed: get name from dict
                        self._log(f"✓ Auto-selected first available model: {self.model}")
                        self.available = True
                        return True
                    else:
                        self.error_message = "No models installed in Ollama"
                        self._log(f"✗ No models found")
                        self.available = False
                        return False

                # Check if requested model is available (flexible matching)
                model_base = self.model.split(':')[0]
                model_found = False

                for m in models:
                    m_name = m.get('name', '')
                    if (self.model in m_name or
                        model_base in m_name or
                        m_name.startswith(model_base)):
                        model_found = True
                        self.model = m_name  # Use exact name
                        self._log(f"✓ Model found: {self.model}")
                        break

                if not model_found:
                    self.error_message = (
                        f"Model '{self.model}' not found.\n"
                        f"Available models: {', '.join(model_names)}\n"
                        f"Install with: ollama pull {self.model}"
                    )
                    self._log(f"✗ Model '{self.model}' not found")
                    self._log(f"Available: {model_names}")
                    self.available = False
                    return False

                self.available = True
                self._log("✓ Ollama is ready!")
                return True

            except json.JSONDecodeError:
                self.error_message = "Failed to parse Ollama response"
                self._log(f"✗ JSON parse error")
                return self._try_direct_generation()

        except requests.exceptions.ConnectionError:
            self.error_message = (
                f"Cannot connect to Ollama at {self.base_url}\n\n"
                "Troubleshooting:\n"
                "1. Check if Ollama is running: ps aux | grep ollama\n"
                "2. Start Ollama: ollama serve\n"
                "3. Check if running on different port: ollama serve --port 11435\n"
                "4. Test manually: curl http://localhost:11434/api/tags"
            )
            self._log(f"✗ Connection error")
            self.available = False
            return False

        except requests.exceptions.Timeout:
            self.error_message = "Ollama server connection timeout (5s)"
            self._log(f"✗ Timeout")
            self.available = False
            return False

        except Exception as e:
            self.error_message = f"Unexpected error checking Ollama: {str(e)}"
            self._log(f"✗ Unexpected error: {e}")
            return self._try_direct_generation()

    def _try_direct_generation(self) -> bool:
        """Last resort: Try to generate directly to see if Ollama works"""
        self._log("Method 3: Trying direct generation test...")

        try:
            payload = {
                "model": self.model,
                "prompt": "test",
                "stream": False,
                "options": {"num_predict": 1}
            }

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                self._log("✓ Direct generation successful!")
                self.available = True
                return True
            elif response.status_code == 404:
                try:
                    error_data = response.json()
                    self.error_message = (
                        f"Model '{self.model}' not found.\n"
                        f"Error: {error_data.get('error', 'Model not found')}\n"
                        f"Install with: ollama pull {self.model}"
                    )
                except:
                    self.error_message = f"Model '{self.model}' not found (404)"
                self._log(f"✗ Model not found (404)")
                self.available = False
                return False
            else:
                self.error_message = f"Ollama returned status {response.status_code}"
                self._log(f"✗ Status {response.status_code}")
                self.available = False
                return False

        except Exception as e:
            self.error_message = f"Direct generation test failed: {str(e)}"
            self._log(f"✗ Direct generation failed: {e}")
            self.available = False
            return False

    def analyze_findings(self, findings: List[Any], metadata: Dict[str, Any]) -> Optional[AIAnalysisResult]:
        """Use AI to analyze security findings and provide insights"""

        if not self.available:
            if self.verbose:
                print(f"\n{'='*70}")
                print("AI Analysis Unavailable")
                print(f"{'='*70}")
                print(f"Reason: {self.error_message}")
                print(f"{'='*70}\n")
            return None

        # Prepare context for AI
        context = self._prepare_context(findings, metadata)

        # Create analysis prompt
        prompt = self._create_analysis_prompt(context)

        # Query Ollama
        try:
            if self.verbose:
                print("\n[Ollama] Sending analysis request...")
                print(f"[Ollama] Context length: {len(context)} chars")

            response = self._query_ollama(prompt)

            if self.verbose:
                print(f"[Ollama] Response length: {len(response)} chars")

            return self._parse_response(response)
        except Exception as e:
            if self.verbose:
                print(f"[Ollama] Analysis failed: {e}")
            return None

    def _prepare_context(self, findings: List[Any], metadata: Dict[str, Any]) -> str:
        """Prepare context string for AI analysis"""
        context_parts = []

        # Add metadata summary
        context_parts.append("MODEL INFORMATION:")
        context_parts.append(f"- File: {metadata.get('model_name', 'unknown')}")
        context_parts.append(f"- Format: {metadata.get('file_format', 'unknown')}")
        context_parts.append(f"- Size: {metadata.get('size_mb', 0)} MB")
        context_parts.append("")

        # Add findings summary
        context_parts.append(f"SECURITY FINDINGS ({len(findings)} total):")

        severity_counts = {}
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for severity, count in sorted(severity_counts.items()):
            context_parts.append(f"- {severity}: {count}")

        context_parts.append("")
        context_parts.append("DETAILED FINDINGS:")

        # Add detailed findings (limit to top 10 most severe)
        sorted_findings = sorted(
            findings,
            key=lambda f: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(
                f.severity.value if hasattr(f.severity, 'value') else 'INFO'
            )
        )

        for i, finding in enumerate(sorted_findings[:10], 1):
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            context_parts.append(f"{i}. [{sev}] {finding.title}")
            context_parts.append(f"   {finding.description}")
            if finding.evidence:
                context_parts.append(f"   Evidence: {finding.evidence[:100]}")
            context_parts.append("")

        return "\n".join(context_parts)

    def _create_analysis_prompt(self, context: str) -> str:
        """Create prompt for AI analysis"""
        return f"""You are a cybersecurity expert specializing in AI/ML model security. Analyze the following security scan results and provide a comprehensive security assessment.

{context}

Provide your analysis in the following JSON format:
{{
    "summary": "Brief 2-3 sentence summary of overall security posture",
    "risk_assessment": "Detailed risk assessment explaining the main security concerns",
    "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"],
    "confidence": 0.85,
    "reasoning": "Explain your reasoning for the risk level and recommendations"
}}

Focus on:
1. Whether this model is safe to load and use
2. The most critical security issues
3. Practical recommendations for mitigation
4. Any patterns that suggest intentional backdoors vs accidental issues

Respond ONLY with the JSON object, no additional text."""

    def _query_ollama(self, prompt: str) -> str:
        """Query Ollama API with proper error handling"""
        url = f"{self.base_url}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "num_predict": 1000
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=120)

            if response.status_code == 404:
                raise Exception(
                    f"Model '{self.model}' not found. "
                    f"Pull it with: ollama pull {self.model}"
                )

            response.raise_for_status()
            result = response.json()
            return result.get('response', '')

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise Exception(
                    f"Ollama API error (404). Check your Ollama version and model availability.\n"
                    f"Tried: {url}"
                )
            else:
                raise Exception(f"HTTP {e.response.status_code}: {str(e)}")
        except requests.exceptions.ConnectionError:
            raise Exception("Cannot connect to Ollama during generation")
        except requests.exceptions.Timeout:
            raise Exception("Ollama request timed out (120s)")

    def _parse_response(self, response: str) -> AIAnalysisResult:
        """Parse AI response into structured result"""
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)

                return AIAnalysisResult(
                    summary=data.get('summary', ''),
                    risk_assessment=data.get('risk_assessment', ''),
                    recommendations=data.get('recommendations', []),
                    confidence=float(data.get('confidence', 0.5)),
                    reasoning=data.get('reasoning', '')
                )
            else:
                raise ValueError("No JSON found in response")

        except Exception as e:
            # Fallback: treat entire response as summary
            return AIAnalysisResult(
                summary=response[:200],
                risk_assessment=response,
                recommendations=["Manual review recommended"],
                confidence=0.3,
                reasoning="Failed to parse structured response"
            )

    def analyze_suspicious_code(self, code_snippet: str, context: str) -> Optional[str]:
        """Analyze specific suspicious code snippets"""
        if not self.available:
            return None

        prompt = f"""You are a malware analyst. Analyze this suspicious code found in an AI model file:

Context: {context}

Code:
```
{code_snippet}
```

Explain:
1. What this code does
2. Whether it's malicious or benign
3. Risk level (LOW/MEDIUM/HIGH/CRITICAL)
4. Recommended action

Be concise and technical."""

        try:
            response = self._query_ollama(prompt)
            return response
        except Exception:
            return None

    def compare_with_known_exploits(self, finding_description: str) -> Optional[str]:
        """Check if finding matches known exploit patterns"""
        if not self.available:
            return None

        prompt = f"""You are a security researcher with knowledge of known AI model exploits and CVEs.

Compare this security finding with known exploits:

Finding: {finding_description}

Does this match any known CVE or documented exploit pattern for AI models? If so, which ones and what are the implications?

Be specific about CVE numbers if applicable."""

        try:
            response = self._query_ollama(prompt)
            return response
        except Exception:
            return None


class ThreatIntelligence:
    """Local threat intelligence without external APIs"""

    KNOWN_MALICIOUS_PATTERNS = {
        'backdoor_indicators': [
            'reverse_shell', 'bind_shell', 'nc -e', 'bash -i',
            '/dev/tcp', 'socket.socket', 'subprocess.Popen'
        ],
        'data_exfiltration': [
            'requests.post', 'urllib.request.urlopen', 'socket.send',
            'http.client', 'base64.b64encode'
        ],
        'persistence': [
            'crontab', 'systemd', 'LaunchAgent', 'startup',
            'registry', 'autorun'
        ],
        'obfuscation': [
            'eval(', 'exec(', 'compile(', '__import__',
            'base64.b64decode', 'zlib.decompress'
        ]
    }

    KNOWN_CVES = {
        'pickle': [
            'CVE-2022-45061: Pickle module arbitrary code execution',
            'CVE-2023-XXXX: PyTorch model poisoning vulnerability'
        ],
        'tensorflow': [
            'CVE-2021-37678: TensorFlow SavedModel arbitrary code execution',
            'CVE-2022-23578: TensorFlow Grappler vulnerability'
        ]
    }

    @staticmethod
    def check_pattern(content: str) -> Dict[str, List[str]]:
        """Check content against known malicious patterns"""
        matches = {}
        content_lower = content.lower()

        for category, patterns in ThreatIntelligence.KNOWN_MALICIOUS_PATTERNS.items():
            found = []
            for pattern in patterns:
                if pattern.lower() in content_lower:
                    found.append(pattern)
            if found:
                matches[category] = found

        return matches

    @staticmethod
    def get_relevant_cves(file_format: str) -> List[str]:
        """Get relevant CVEs for file format"""
        return ThreatIntelligence.KNOWN_CVES.get(file_format, [])


if __name__ == "__main__":
    # Test Ollama connection with detailed diagnostics
    print("Testing Ollama connection...\n")

    analyzer = OllamaAnalyzer(verbose=True)

    if analyzer.available:
        print("\n" + "="*70)
        print("✓ SUCCESS - Ollama is available and ready!")
        print("="*70)
        print(f"Model: {analyzer.model}")
        print(f"URL: {analyzer.base_url}")
    else:
        print("\n" + "="*70)
        print("✗ FAILED - Ollama is not available")
        print("="*70)
        print(f"\nError Details:")
        print(analyzer.error_message)
        print(f"\nTried URL: {analyzer.base_url}")
        print(f"Tried Model: {analyzer.model}")