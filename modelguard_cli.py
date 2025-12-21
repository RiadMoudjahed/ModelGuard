#!/usr/bin/env python3
"""
ModelGuard - AI Model Security Scanner
Complete CLI interface (FIXED - Auto-detects Ollama models)
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Import all modules
try:
    from modelguard_core import ModelScanner, ScanResult
    from modelguard_advanced import (
        GGUFAnalyzer, MetadataValidator,
        SourceTrustAnalyzer, WeightAnomalyDetector
    )
    from modelguard_ollama import OllamaAnalyzer, ThreatIntelligence
    from modelguard_reports import ReportGenerator
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all ModelGuard modules are in the same directory")
    sys.exit(1)


class ModelGuardCLI:
    """Main CLI application"""

    def __init__(self):
        self.version = "1.0.0"
        self.scanner = None
        self.report_gen = ReportGenerator()
        self.ollama = None

    def run(self):
        """Main entry point"""
        parser = self.create_parser()
        args = parser.parse_args()

        if args.version:
            print(f"ModelGuard v{self.version}")
            return 0

        if not args.model:
            parser.print_help()
            return 1

        return self.scan_model(args)

    def create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description="ModelGuard - AI Model Security Scanner",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  modelguard scan model.pt
  modelguard scan model.gguf --verbose --ai-analysis
  modelguard scan model.bin --output report.txt --format text
  modelguard scan model.safetensors --format json -o report.json

Supported Formats:
  PyTorch: .pt, .pth, .bin, .ckpt
  GGUF: .gguf
  SafeTensors: .safetensors
  ONNX: .onnx
  Others: .pkl, .pb, .h5
            """
        )

        parser.add_argument(
            'command',
            choices=['scan'],
            help='Command to execute'
        )

        parser.add_argument(
            'model',
            nargs='?',
            help='Path to model file or directory'
        )

        parser.add_argument(
            '-o', '--output',
            help='Output file path for report (default: stdout)'
        )

        parser.add_argument(
            '-f', '--format',
            choices=['text', 'json', 'markdown', 'html'],
            default='text',
            help='Report format (default: text)'
        )

        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

        parser.add_argument(
            '--ai-analysis',
            action='store_true',
            help='Enable AI-powered deep analysis (requires Ollama)'
        )

        parser.add_argument(
            '--ollama-model',
            default='auto',
            help='Ollama model to use for AI analysis (default: auto - uses first available model)'
        )

        parser.add_argument(
            '--ollama-url',
            default='http://localhost:11434',
            help='Ollama API URL (default: http://localhost:11434)'
        )

        parser.add_argument(
            '--no-metadata',
            action='store_true',
            help='Skip metadata validation'
        )

        parser.add_argument(
            '--check-source',
            action='store_true',
            help='Check model source trustworthiness (requires internet)'
        )

        parser.add_argument(
            '--repo-id',
            help='HuggingFace repository ID (e.g., username/model-name)'
        )

        parser.add_argument(
            '--version',
            action='store_true',
            help='Show version and exit'
        )

        return parser

    def scan_model(self, args):
        """Scan a model file"""
        model_path = Path(args.model)

        # Validate path
        if not model_path.exists():
            print(f"Error: Model file not found: {args.model}")
            return 1

        # Initialize scanner
        self.scanner = ModelScanner(verbose=args.verbose)

        # Initialize Ollama if requested
        if args.ai_analysis:
            self.ollama = OllamaAnalyzer(
                base_url=args.ollama_url,
                model=args.ollama_model,
                verbose=args.verbose  # Pass verbose flag!
            )

            if not self.ollama.available:
                print("\n" + "="*70)
                print("⚠️  AI Analysis Unavailable")
                print("="*70)
                print(self.ollama.error_message or "Unknown error")
                print("="*70)
                print("\nContinuing with standard security scan...\n")
                self.ollama = None

        # Print header
        self.print_header()

        # Handle directory vs file
        if model_path.is_dir():
            return self.scan_directory(model_path, args)
        else:
            return self.scan_single_file(model_path, args)

    def scan_single_file(self, file_path: Path, args):
        """Scan a single model file"""
        try:
            print(f"\nScanning: {file_path.name}")
            print("=" * 70)

            # Run core scan
            result = self.scanner.scan(str(file_path))

            # Run GGUF analysis if applicable
            if result.file_format == 'gguf':
                if args.verbose:
                    print("\nRunning GGUF analysis...")
                gguf_analyzer = GGUFAnalyzer()
                gguf_findings, gguf_metadata = gguf_analyzer.analyze(str(file_path))
                result.findings.extend(gguf_findings)
                result.metadata.update(gguf_metadata)

            # Run metadata validation
            if not args.no_metadata:
                if args.verbose:
                    print("Validating metadata...")
                metadata_validator = MetadataValidator()
                meta_findings, meta_data = metadata_validator.validate(str(file_path))
                result.findings.extend(meta_findings)
                result.metadata.update(meta_data)

            # Check source trust
            if args.check_source:
                if args.verbose:
                    print("Checking source trustworthiness...")
                source_analyzer = SourceTrustAnalyzer()

                model_info = {}
                if args.repo_id:
                    model_info = source_analyzer.check_huggingface_repo(args.repo_id)
                    model_info['author'] = args.repo_id.split('/')[0] if '/' in args.repo_id else ''

                source_findings, trust_score = source_analyzer.analyze(model_info)
                result.findings.extend(source_findings)
                result.trust_score = trust_score

            # Recalculate risk score
            result.risk_score = self.scanner._calculate_risk_score(result.findings)

            # Run AI analysis
            ai_analysis = None
            if self.ollama:
                if args.verbose:
                    print("\nRunning AI-powered deep analysis...")
                    print("This may take a minute...")

                ai_analysis = self.ollama.analyze_findings(
                    result.findings,
                    {
                        'model_name': result.model_name,
                        'file_format': result.file_format,
                        'size_mb': result.file_size / (1024 * 1024)
                    }
                )

                if ai_analysis and args.verbose:
                    print(f"AI Analysis complete (confidence: {ai_analysis.confidence * 100:.0f}%)")

            # Generate report
            if args.verbose:
                print("\nGenerating report...")

            report = self.generate_report(result, ai_analysis, args.format)

            # Output report
            if args.output:
                self.report_gen.save_report(report, args.output)
                print(f"\nReport saved to: {args.output}")
            else:
                print("\n")
                print(report)

            # Print summary
            print("\n" + "=" * 70)
            self.print_summary(result)

            return 0 if result.risk_score < 50 else 1

        except Exception as e:
            print(f"\nError scanning model: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1

    def scan_directory(self, dir_path: Path, args):
        """Scan all model files in a directory"""
        model_extensions = {'.pt', '.pth', '.bin', '.ckpt', '.gguf',
                            '.safetensors', '.onnx', '.pkl', '.pb', '.h5'}

        model_files = []
        for ext in model_extensions:
            model_files.extend(dir_path.rglob(f'*{ext}'))

        if not model_files:
            print(f"No model files found in {dir_path}")
            return 1

        print(f"\nFound {len(model_files)} model file(s)")
        print("=" * 70)

        results = []
        for i, file_path in enumerate(model_files, 1):
            print(f"\n[{i}/{len(model_files)}] Scanning: {file_path.name}")

            try:
                result = self.scanner.scan(str(file_path))
                results.append((file_path, result))

                print(f"  Risk Score: {result.risk_score:.1f}/100")
                print(f"  Findings: {len(result.findings)}")

            except Exception as e:
                print(f"  Error: {e}")

        # Generate summary report
        if results:
            self.print_batch_summary(results)

        return 0

    def generate_report(self, result: ScanResult, ai_analysis, format: str) -> str:
        """Generate report in specified format"""
        if format == 'text':
            return self.report_gen.generate_text_report(result, ai_analysis)
        elif format == 'json':
            return self.report_gen.generate_json_report(result, ai_analysis)
        elif format == 'markdown':
            return self.report_gen.generate_markdown_report(result, ai_analysis)
        elif format == 'html':
            return self.report_gen.generate_html_report(result, ai_analysis)
        else:
            return self.report_gen.generate_text_report(result, ai_analysis)

    def print_header(self):
        """Print CLI header"""
        print("\n")
        print("=" * 70)
        print("ModelGuard - AI Model Security Scanner".center(70))
        print(f"Version {self.version}".center(70))
        print("=" * 70)

    def print_summary(self, result: ScanResult):
        """Print scan summary"""
        risk_level = self.report_gen._get_risk_level(result.risk_score)

        print(f"Model: {result.model_name}")
        print(f"Risk Score: {result.risk_score:.1f}/100 ({risk_level})")
        print(f"Trust Score: {result.trust_score:.1f}/100")
        print(f"Total Findings: {len(result.findings)}")

        # Count by severity
        severity_counts = {}
        for finding in result.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts.get('CRITICAL', 0) > 0:
            print(f"CRITICAL Issues: {severity_counts['CRITICAL']}")
        if severity_counts.get('HIGH', 0) > 0:
            print(f"HIGH Issues: {severity_counts['HIGH']}")
        if severity_counts.get('MEDIUM', 0) > 0:
            print(f"MEDIUM Issues: {severity_counts['MEDIUM']}")

        print(f"\nRecommendation: {self.report_gen._get_risk_recommendation(risk_level)}")

    def print_batch_summary(self, results):
        """Print summary for batch scan"""
        print("\n" + "=" * 70)
        print("BATCH SCAN SUMMARY")
        print("=" * 70)

        total = len(results)
        critical = sum(1 for _, r in results if r.risk_score >= 70)
        high = sum(1 for _, r in results if 50 <= r.risk_score < 70)
        medium = sum(1 for _, r in results if 30 <= r.risk_score < 50)
        safe = sum(1 for _, r in results if r.risk_score < 30)

        print(f"\nTotal Models Scanned: {total}")
        print(f"  CRITICAL Risk: {critical}")
        print(f"  HIGH Risk: {high}")
        print(f"  MEDIUM Risk: {medium}")
        print(f"  LOW/SAFE: {safe}")

        # List high-risk models
        if critical > 0 or high > 0:
            print("\nHIGH RISK MODELS:")
            for path, result in results:
                if result.risk_score >= 50:
                    print(f"  - {path.name}: {result.risk_score:.1f}/100")


def main():
    """Entry point"""
    try:
        cli = ModelGuardCLI()
        return cli.run()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        return 130
    except Exception as e:
        print(f"\nFatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())