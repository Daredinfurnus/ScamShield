
from typing import Any


class DeterministicFallback:
    """Evidence-based responses when the AI provider is unavailable."""

    def _get_risk_classification(self, risk_score: float, risk_band: str) -> str:
        """Return a descriptive risk classification."""
        band = (risk_band or '').lower()
        if band == 'critical' or risk_score >= 75:
            return "CRITICAL RISK - Immediate action required. This evidence exhibits characteristics of sophisticated social engineering or financial fraud that warrants urgent protective action."
        elif band == 'high' or risk_score >= 50:
            return "HIGH RISK - Review recommended. Multiple deception indicators present suggestive of targeted fraud attempts."
        elif band == 'medium' or risk_score >= 25:
            return "MEDIUM RISK - Monitor and verify. Some suspicious patterns detected requiring further scrutiny."
        else:
            return "LOW RISK - Standard verification advised. Evidence does not trigger primary fraud detectors but normal caution is warranted."

    def _get_attack_pattern(self, findings: list) -> str:
        """Infer potential attack pattern from findings."""
        if not findings:
            return "UNKNOWN - No attack patterns identified from analysis."

        finding_types = [f.get('finding_type', '').lower() for f in findings]
        titles = [f.get('title', '').lower() for f in findings]
        all_text = ' '.join(finding_types + titles)

        if 'phishing' in all_text or 'credential' in all_text:
            return "CREDENTIAL THEFT - Likely attempting to harvest login credentials through deceptive authentication requests."
        elif 'financial' in all_text or 'payment' in all_text or 'upi' in all_text:
            return "FINANCIAL FRAUD - Attempting to redirect or intercept monetary transactions, often via social engineering."
        elif 'sms' in all_text or 'otp' in all_text:
            return "ONE-TIME PASSWORD ABUSE - Likely phishing for OTPs to bypass two-factor authentication."
        elif 'delivery' in all_text or 'parcel' in all_text:
            return "DELIVERY SCHEME DECEPTION - Using fake delivery notices to lure victims into fraudulent interactions."
        elif 'customs' in all_text or 'duty' in all_text:
            return "CUSTOMS/BUSINESS IMPOSTER - Impersonating authority figures to extract fees or sensitive information."
        else:
            return "COMBINED INDICATORS - Multiple deception techniques present suggesting an orchestrated social engineering campaign."

    def _format_evidence(self, observations: list) -> str:
        """Format observations as a narrative."""
        if not observations:
            return "No specific evidence fragments were extracted that could be attributed to particular detection signals."

        lines = []
        for obs in observations:
            evidence = obs.get('evidence_snippet', '')
            if evidence:
                lines.append(f"  Evidence: \"{evidence}\"")
            lines.append(f"    Type: {obs.get('title', obs.get('finding_id', 'Unknown'))}")
            source = obs.get('evidence_source', '')
            if source:
                lines.append(f"    Source: {source}")
        return '\n'.join(lines)

    def explain(
        self,
        findings: list[dict[str, Any]],
        risk_score: float,
        risk_band: str,
    ) -> dict[str, Any]:
        observations = []

        for finding in findings:
            title = finding.get("title") or finding.get("finding_type")
            description = finding.get("description")

            if title or description:
                observations.append({
                    "finding_id": finding.get("id"),
                    "title": title or "Detected finding",
                    "description": description or "",
                    "evidence_snippet": finding.get("evidence_snippet", ""),
                    "evidence_source": finding.get("evidence_source", ""),
                })

        # Build detailed narrative
        risk_classification = self._get_risk_classification(risk_score, risk_band)
        attack_pattern = self._get_attack_pattern(findings)
        evidence_breakdown = self._format_evidence(observations)

        if observations:
            summary = f"""INCIDENT OVERVIEW

{attack_pattern}

{self._get_risk_classification(risk_score, risk_band)}

EVIDENCE BREAKDOWN

{evidence_breakdown}

RISK ASSESSMENT

The deterministic engine assigned a risk score of {risk_score} (scaled 0-100), placing this investigation in the '{risk_band or 'Unknown'}' band. This assessment reflects the cumulative contribution of detected fraud indicators."""

            limitation = (
                "LIMITATION: These findings are automated detection signals based on pattern matching, "
                "not definitive proof of criminal intent or actual financial loss. "
                "Investigators should corroborate with additional intelligence sources."
            )

            recommendations = [
                "Do not respond to any requests contained in the submitted evidence.",
                "Report identified phishing domains, phone numbers, and financial accounts to appropriate authorities.",
                "Share indicators of compromise through institutional threat intelligence channels.",
                "Document all communications related to this case for future reference.",
                "Monitor for related phishing attempts using similar tactics or infrastructure.",
            ]
        else:
            summary = f"""INCIDENT OVERVIEW

{self._get_risk_classification(risk_score, risk_band)}

The submitted evidence did not trigger any of the 10 deterministic fraud detection patterns. This does not establish safety - many scam techniques operate without triggering known signatures.

RISK ASSESSMENT

Risk score: {risk_score} (band: {risk_band or 'Unknown'})

LIMITATION

The absence of detection signals should not be interpreted as evidence of benign intent. Suspicious actors frequently adapt techniques to evade pattern-based detection."""

            limitation = (
                "LIMITATION: Insufficient detection signals for pattern identification. "
                "Manual review by investigators is strongly recommended."
            )

            recommendations = [
                "Exercise caution with all unsolicited communications.",
                "Verify sender identity through out-of-band channels.",
                "Report any suspicious activity to institutional security teams.",
                "Consider additional technical analysis of the communication vector.",
            ]

        return {
            "summary": summary,
            "observations": observations,
            "recommendations": recommendations,
            "limitations": [limitation],
            "risk_score": risk_score,
            "risk_band": risk_band,
            "provider": "deterministic",
            "fallback_used": True,
        }

    def draft_report(
        self,
        investigation_data: dict[str, Any],
    ) -> dict[str, Any]:
        findings = investigation_data.get("findings", [])
        risk_score = investigation_data.get("risk_score")
        risk_band = investigation_data.get("risk_band")
        input_type = investigation_data.get("input_type", "unknown").upper()
        input_content = investigation_data.get("input_content", "")
        title = investigation_data.get("title", "Investigation Report")
        created_at = investigation_data.get("created_at", "")

        explanation = self.explain(
            findings=findings,
            risk_score=risk_score,
            risk_band=risk_band,
        )

        # Build executive summary from findings
        total_findings = len(findings)
        if findings:
            finding_summary = " & ".join([f.get('title', f.get('finding_type', 'Unknown')) for f in findings[:3]])
            if len(findings) > 3:
                finding_summary += f" and {len(findings) - 3} other signal(s)"
            executive_summary = (
                f"Risk Assessment: {risk_band} (Score: {risk_score}). "
                f"Detected {total_findings} fraud indicator(s): {finding_summary}."
            )
        else:
            executive_summary = (
                f"Risk Assessment: {risk_band} (Score: {risk_score}). "
                f"No fraud detection signals were triggered by this {input_type.lower()} input."
            )

        # Build detailed findings section
        detailed_findings = ""
        if findings:
            for i, f in enumerate(findings, 1):
                ftitle = f.get('title', f.get('finding_type', 'Unknown'))
                fdesc = f.get('description', '')
                esnippet = f.get('evidence_snippet', '')
                esource = f.get('evidence_source', '')
                fscore = f.get('score', 0)

                detailed_findings += f"{i}. **{ftitle}** (Signal: +{fscore})\n"
                if fdesc:
                    detailed_findings += f"   {fdesc}\n"
                if esnippet:
                    detailed_findings += f"   Evidence: \"{esnippet}\"\n"
                if esource:
                    detailed_findings += f"   Source: {esource}\n"
                detailed_findings += "\n"
        else:
            detailed_findings = "*No detection signals were triggered*\n\n"
            detailed_findings += "This investigation did not match any of the 10 deterministic fraud detection patterns. "
            detailed_findings += "However, absence of signals does not prove benign intent.\n\n"

        # Build supporting evidence section
        evidence_items = []
        for f in findings:
            if f.get('evidence_snippet'):
                evidence_items.append(f.get('evidence_snippet'))

        supporting_evidence = '\n'.join(evidence_items) if evidence_items else "No evidence fragments extracted."

        # Build formal report
        report_content = f"""# {title}

## Executive Summary

{executive_summary}

## Details

### Input Type
{input_type}

### Submitted Evidence
```
{input_content[:500]}{'...' if len(input_content) > 500 else ''}
```

### Detection Findings
{detailed_findings}

### Risk Assessment

**Risk Score:** {risk_score}/100
**Risk Band:** {risk_band or 'Unknown'}
**Attack Pattern:** {self._get_attack_pattern(findings)}

### Recommended Protective Actions
"""
        for rec in explanation['recommendations']:
            report_content += f"- {rec}\n"

        report_content += f"""
### Limitations
{chr(10).join(explanation['limitations'])}

### Source
Deterministic Baseline (Fallback)

### Generated Fields
- risk_score_from_scorer: {risk_score}
- risk_band_from_scorer: {risk_band or 'Unknown'}
- findings_count: {total_findings}
"""

        return {
            "investigation_id": investigation_data.get("id"),
            "title": title,
            "executive_summary": executive_summary,
            "detailed_findings": detailed_findings,
            "supporting_evidence": evidence_items if evidence_items else ["No evidence fragments"],
            "recommendations": explanation["recommendations"],
            "limitations": explanation["limitations"],
            "report_markdown": report_content,
            "risk_score": risk_score,
            "risk_band": risk_band,
            "provider": "deterministic",
            "fallback_used": True,
            "findings": [
                {
                    "id": f.get('id'),
                    "finding_type": f.get('finding_type'),
                    "title": f.get('title', f.get('finding_type', 'Unknown')),
                    "description": f.get('description', ''),
                    "evidence_snippet": f.get('evidence_snippet', ''),
                    "evidence_source": f.get('evidence_source', ''),
                    "score": f.get('score', 0),
                }
                for f in findings
            ],
        }
