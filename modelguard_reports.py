"""
ModelGuard - Report Generator
Professional security reports in multiple formats
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class ReportGenerator:
    """Generates security reports in multiple formats"""

    def __init__(self):
        self.template_width = 80

    def generate_text_report(self, scan_result, ai_analysis: Optional[Any] = None) -> str:
        """Generate detailed text report"""

        lines = []

        # Header
        lines.append("=" * self.template_width)
        lines.append("MODELGUARD SECURITY SCAN REPORT".center(self.template_width))
        lines.append("=" * self.template_width)
        lines.append("")

        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * self.template_width)
        lines.append(f"Model: {scan_result.model_name}")
        lines.append(f"Scanned: {scan_result.scan_timestamp}")
        lines.append(f"Format: {scan_result.file_format.upper()}")
        lines.append(f"Size: {scan_result.file_size / (1024 * 1024):.2f} MB")
        lines.append("")

        # Risk Scoring
        lines.append("RISK ASSESSMENT")
        lines.append("-" * self.template_width)
        lines.append(f"Overall Risk Score: {scan_result.risk_score:.1f}/100")
        lines.append(f"Trust Score: {scan_result.trust_score:.1f}/100")
        lines.append("")

        risk_level = self._get_risk_level(scan_result.risk_score)
        lines.append(f"Risk Level: {risk_level}")
        lines.append(f"Recommendation: {self._get_risk_recommendation(risk_level)}")
        lines.append("")

        # AI Analysis Summary (if available)
        if ai_analysis:
            lines.append("AI ANALYSIS SUMMARY")
            lines.append("-" * self.template_width)
            # Handle both string and dictionary formats for summary
            if isinstance(ai_analysis.summary, dict):
                lines.append(self._wrap_text(str(ai_analysis.summary)))
            else:
                lines.append(self._wrap_text(ai_analysis.summary))
            lines.append("")
            lines.append(f"Confidence: {ai_analysis.confidence * 100:.0f}%")
            lines.append("")

        # Findings Summary
        lines.append("FINDINGS SUMMARY")
        lines.append("-" * self.template_width)

        severity_counts = {}
        for finding in scan_result.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"Total Findings: {len(scan_result.findings)}")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"  {severity}: {count}")
        lines.append("")

        # Detailed Findings
        if scan_result.findings:
            lines.append("DETAILED FINDINGS")
            lines.append("=" * self.template_width)
            lines.append("")

            # Group by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                severity_findings = [f for f in scan_result.findings if f.severity.value == severity]

                if severity_findings:
                    lines.append(f"{severity} SEVERITY ({len(severity_findings)})")
                    lines.append("-" * self.template_width)

                    for i, finding in enumerate(severity_findings, 1):
                        lines.append(f"\n[{severity}-{i}] {finding.title}")
                        lines.append("")
                        lines.append(f"Category: {finding.category}")
                        lines.append("")

                        lines.append("Description:")
                        lines.append(self._wrap_text(finding.description, indent=2))
                        lines.append("")

                        if finding.evidence:
                            lines.append("Evidence:")
                            lines.append(self._wrap_text(finding.evidence, indent=2))
                            lines.append("")

                        if finding.recommendation:
                            lines.append("Recommendation:")
                            lines.append(self._wrap_text(finding.recommendation, indent=2))
                            lines.append("")

                        if finding.cve_references:
                            lines.append("Related CVEs:")
                            for cve in finding.cve_references:
                                lines.append(f"  - {cve}")
                            lines.append("")

                        lines.append("-" * self.template_width)

                    lines.append("")

        # AI Deep Analysis (if available)
        if ai_analysis and ai_analysis.risk_assessment:
            lines.append("AI DEEP ANALYSIS")
            lines.append("=" * self.template_width)
            lines.append("")
            lines.append("Risk Assessment:")
            # Handle both string and dictionary formats for risk_assessment
            if isinstance(ai_analysis.risk_assessment, dict):
                lines.append(self._wrap_text(str(ai_analysis.risk_assessment), indent=2))
            else:
                lines.append(self._wrap_text(ai_analysis.risk_assessment, indent=2))
            lines.append("")

            if ai_analysis.recommendations:
                lines.append("AI Recommendations:")
                for i, rec in enumerate(ai_analysis.recommendations, 1):
                    lines.append(f"  {i}. {rec}")
                lines.append("")

            if ai_analysis.reasoning:
                lines.append("Reasoning:")
                # Handle both string and dictionary formats for reasoning
                if isinstance(ai_analysis.reasoning, dict):
                    lines.append(self._wrap_text(str(ai_analysis.reasoning), indent=2))
                else:
                    lines.append(self._wrap_text(ai_analysis.reasoning, indent=2))
                lines.append("")

        # Metadata
        lines.append("TECHNICAL DETAILS")
        lines.append("=" * self.template_width)
        lines.append(f"SHA256: {scan_result.file_hash_sha256}")
        lines.append(f"File Path: {scan_result.model_path}")
        lines.append("")

        if scan_result.metadata:
            lines.append("Metadata:")
            for key, value in scan_result.metadata.items():
                if not isinstance(value, (dict, list)):
                    lines.append(f"  {key}: {value}")
            lines.append("")

        # Footer
        lines.append("=" * self.template_width)
        lines.append("Report generated by ModelGuard".center(self.template_width))
        lines.append(f"Timestamp: {datetime.now().isoformat()}".center(self.template_width))
        lines.append("=" * self.template_width)

        return "\n".join(lines)

    def generate_json_report(self, scan_result, ai_analysis: Optional[Any] = None) -> str:
        """Generate JSON report for programmatic access"""

        report = scan_result.to_dict()

        if ai_analysis:
            report['ai_analysis'] = {
                'summary': ai_analysis.summary,
                'risk_assessment': ai_analysis.risk_assessment,
                'recommendations': ai_analysis.recommendations,
                'confidence': ai_analysis.confidence,
                'reasoning': ai_analysis.reasoning
            }

        report['risk_level'] = self._get_risk_level(scan_result.risk_score)
        report['report_generated'] = datetime.now().isoformat()

        return json.dumps(report, indent=2)

    def generate_markdown_report(self, scan_result, ai_analysis: Optional[Any] = None) -> str:
        """Generate Markdown report"""

        lines = []

        # Header
        lines.append("# ModelGuard Security Scan Report")
        lines.append("")
        lines.append(f"**Generated:** {scan_result.scan_timestamp}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Model:** {scan_result.model_name}")
        lines.append(f"- **Format:** {scan_result.file_format.upper()}")
        lines.append(f"- **Size:** {scan_result.file_size / (1024 * 1024):.2f} MB")
        lines.append(f"- **SHA256:** `{scan_result.file_hash_sha256}`")
        lines.append("")

        # Risk Assessment
        lines.append("## Risk Assessment")
        lines.append("")
        risk_level = self._get_risk_level(scan_result.risk_score)
        lines.append(f"- **Risk Score:** {scan_result.risk_score:.1f}/100")
        lines.append(f"- **Trust Score:** {scan_result.trust_score:.1f}/100")
        lines.append(f"- **Risk Level:** `{risk_level}`")
        lines.append("")
        lines.append(f"> {self._get_risk_recommendation(risk_level)}")
        lines.append("")

        # AI Analysis
        if ai_analysis:
            lines.append("## AI Analysis")
            lines.append("")
            # Handle both string and dictionary formats for summary
            if isinstance(ai_analysis.summary, dict):
                lines.append(str(ai_analysis.summary))
            else:
                lines.append(ai_analysis.summary)
            lines.append("")

            if ai_analysis.recommendations:
                lines.append("### Recommendations")
                lines.append("")
                for rec in ai_analysis.recommendations:
                    lines.append(f"- {rec}")
                lines.append("")

        # Findings
        lines.append("## Security Findings")
        lines.append("")

        severity_counts = {}
        for finding in scan_result.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append(f"**Total:** {len(scan_result.findings)}")
        lines.append("")

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"- {severity}: {count}")

        lines.append("")

        # Detailed findings
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in scan_result.findings if f.severity.value == severity]

            if severity_findings:
                lines.append(f"### {severity} Severity")
                lines.append("")

                for finding in severity_findings:
                    lines.append(f"#### {finding.title}")
                    lines.append("")
                    lines.append(f"**Category:** {finding.category}")
                    lines.append("")
                    lines.append(finding.description)
                    lines.append("")

                    if finding.evidence:
                        lines.append(f"**Evidence:** `{finding.evidence}`")
                        lines.append("")

                    if finding.recommendation:
                        lines.append(f"**Recommendation:** {finding.recommendation}")
                        lines.append("")

        return "\n".join(lines)

    def generate_html_report(self, scan_result, ai_analysis: Optional[Any] = None) -> str:
        """Generate HTML report"""

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ModelGuard Security Report - {scan_result.model_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .risk-score {{
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            margin: 20px 0;
        }}
        .risk-CRITICAL {{ color: #dc3545; }}
        .risk-HIGH {{ color: #fd7e14; }}
        .risk-MEDIUM {{ color: #ffc107; }}
        .risk-LOW {{ color: #28a745; }}
        .risk-SAFE {{ color: #20c997; }}
        .finding {{
            border-left: 4px solid #ddd;
            padding: 15px;
            margin: 15px 0;
            background: #f8f9fa;
        }}
        .finding.CRITICAL {{ border-left-color: #dc3545; }}
        .finding.HIGH {{ border-left-color: #fd7e14; }}
        .finding.MEDIUM {{ border-left-color: #ffc107; }}
        .finding.LOW {{ border-left-color: #28a745; }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .badge.CRITICAL {{ background: #dc3545; }}
        .badge.HIGH {{ background: #fd7e14; }}
        .badge.MEDIUM {{ background: #ffc107; color: #000; }}
        .badge.LOW {{ background: #28a745; }}
        .badge.INFO {{ background: #17a2b8; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        td, th {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ModelGuard Security Report</h1>
        <p>{scan_result.model_name}</p>
        <p>Scanned: {scan_result.scan_timestamp}</p>
    </div>

    <div class="section">
        <h2>Risk Assessment</h2>
        <div class="risk-score risk-{self._get_risk_level(scan_result.risk_score)}">
            {scan_result.risk_score:.1f}/100
        </div>
        <p style="text-align: center; font-size: 18px;">
            <strong>Risk Level: {self._get_risk_level(scan_result.risk_score)}</strong>
        </p>
        <p style="text-align: center;">
            {self._get_risk_recommendation(self._get_risk_level(scan_result.risk_score))}
        </p>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Risk Score</td>
                <td>{scan_result.risk_score:.1f}/100</td>
            </tr>
            <tr>
                <td>Trust Score</td>
                <td>{scan_result.trust_score:.1f}/100</td>
            </tr>
            <tr>
                <td>Total Findings</td>
                <td>{len(scan_result.findings)}</td>
            </tr>
        </table>
    </div>
"""

        # AI Analysis section
        if ai_analysis:
            html += f"""
    <div class="section">
        <h2>AI Analysis</h2>
        <p>{" ".join(str(ai_analysis.summary).split()[:100])}...</p>
        <h3>Recommendations</h3>
        <ul>
"""
            for rec in ai_analysis.recommendations:
                html += f"            <li>{rec}</li>\n"

            html += """        </ul>
    </div>
"""

        # Findings section
        html += """
    <div class="section">
        <h2>Security Findings</h2>
"""

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in scan_result.findings if f.severity.value == severity]

            if severity_findings:
                html += f"""
        <h3><span class="badge {severity}">{severity}</span> {len(severity_findings)} Finding(s)</h3>
"""
                for finding in severity_findings:
                    html += f"""
        <div class="finding {severity}">
            <h4>{finding.title}</h4>
            <p><strong>Category:</strong> {finding.category}</p>
            <p>{finding.description}</p>
"""
                    if finding.evidence:
                        html += f"            <p><strong>Evidence:</strong> <code>{finding.evidence[:200]}</code></p>\n"

                    if finding.recommendation:
                        html += f"            <p><strong>Recommendation:</strong> {finding.recommendation}</p>\n"

                    html += "        </div>\n"

        html += """
    </div>

    <div class="section">
        <h2>Technical Details</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>File Path</td><td><code>{}</code></td></tr>
            <tr><td>Format</td><td>{}</td></tr>
            <tr><td>Size</td><td>{:.2f} MB</td></tr>
            <tr><td>SHA256</td><td><code>{}</code></td></tr>
        </table>
    </div>

    <div class="section" style="text-align: center; color: #666;">
        <p>Report generated by ModelGuard</p>
        <p>{}</p>
    </div>
</body>
</html>
""".format(
            scan_result.model_path,
            scan_result.file_format.upper(),
            scan_result.file_size / (1024 * 1024),
            scan_result.file_hash_sha256,
            datetime.now().isoformat()
        )

        return html

    def save_report(self, content: str, output_path: str):
        """Save report to file"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to level"""
        if risk_score >= 70:
            return "CRITICAL"
        elif risk_score >= 50:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "SAFE"

    def _get_risk_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level"""
        recommendations = {
            "CRITICAL": "DO NOT USE THIS MODEL. Contains severe security issues that could compromise your system.",
            "HIGH": "Use with extreme caution. Multiple serious security concerns identified.",
            "MEDIUM": "Exercise caution. Review findings before deployment.",
            "LOW": "Generally safe but review minor findings.",
            "SAFE": "No significant security concerns detected. Model appears safe to use."
        }
        return recommendations.get(risk_level, "Review findings carefully.")

    def _wrap_text(self, text: str, width: int = 76, indent: int = 0) -> str:
        """Wrap text to specified width"""
        # Ensure text is string
        if not isinstance(text, str):
            text = str(text)

        words = text.split()
        lines = []
        current_line = " " * indent

        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                if current_line.strip():
                    current_line += " " + word
                else:
                    current_line = " " * indent + word
            else:
                if current_line.strip():
                    lines.append(current_line)
                current_line = " " * indent + word

        if current_line.strip():
            lines.append(current_line)

        return "\n".join(lines)


if __name__ == "__main__":
    print("ModelGuard Report Generator Module")