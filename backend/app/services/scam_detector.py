"""Deterministic scam detection engine.

Provides rule-based detection across multiple scam categories. Every signal
references actual evidence extracted from the submitted message. Keyword matches
are never treated as proof of fraud — confidence reflects signal strength.

Detectors:
  - Phishing and credential theft
  - Fake recruitment
  - UPI / payment fraud
  - OTP scams
  - Impersonation
  - Investment fraud
  - Lottery / prize scams
  - Advance-fee fraud
  - Urgency and intimidation

The engine deduplicates overlapping signals so that multiple detectors firing on
the same text span do not artificially inflate the risk score.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from app.services.detection_signal import DetectionSignal
from app.services.evidence_service import EvidenceService


def _find_all(text: str, pattern: str) -> List[Tuple[int, int, str]]:
    """Return [(start, end, matched_text)] for all case-insensitive matches."""
    matches: List[Tuple[int, int, str]] = []
    for m in re.finditer(pattern, text, re.IGNORECASE):
        matches.append((m.start(), m.end(), m.group(0)))
    return matches


def _overlaps(a: Tuple[int, int], b: Tuple[int, int]) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])


class BaseDetector:
    """Base class for all scam detectors."""

    category: str = "unknown"

    def detect(self, text: str) -> List[DetectionSignal]:
        """Return a list of DetectionSignal objects found in the text."""
        raise NotImplementedError


class PhishingDetector(BaseDetector):
    """Detects phishing and credential-theft attempts."""

    category = "phishing"

    HIGH_PATTERNS = [
        r"verify your (?:account|identity|password|credentials)",
        r"confirm your (?:account|password|bank|credit card)",
        r"enter your (?:password|pin|otp|ssn|social security)",
        r"reset your (?:password|account|login)",
        r"update your (?:payment|billing|bank) details",
    ]

    MEDIUM_PATTERNS = [
        r"click here to (?:verify|confirm|update|reset|activate|claim)",
        r"your account (?:has been|will be) (?:suspended|locked|closed|deactivated)",
        r"unauthorized (?:access|login|transaction|activity)",
        r"sign in to (?:avoid|prevent|stop)",
    ]

    LOW_KEYWORDS = ["phishing", "credential", "login", "password", "account"]

    # KYC-specific patterns — only flagged when combined with urgency/threat.
    # Consolidated into one pattern to avoid double-counting overlapping matches
    # (e.g. "incomplete KYC verification" would match both "incomplete KYC" and
    # "KYC verification").
    KYC_PATTERNS = [
        r"(?:incomplete|pending|outdated|expired) kyc",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="phishing_credential_request",
                        description=(
                            "Message requests verification or entry of account "
                            "credentials, a strong phishing indicator."
                        ),
                        score=55.0,
                        weight=1.0,
                        confidence=0.85,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="phishing_suspicious_action",
                        description=(
                            "Message urges a suspicious action tied to an account, "
                            "consistent with phishing."
                        ),
                        score=35.0,
                        weight=1.0,
                        confidence=0.65,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        # KYC-specific detection: only flag when combined with urgency/threat,
        # never on a bare "KYC" mention alone (legitimate banks do send KYC reminders).
        text_lower = text.lower()
        has_urgency = bool(re.search(
            r"(?:urgent|immediately|within \d+ (?:hour|hours)|blocked|suspended|failure to comply)",
            text, re.IGNORECASE,
        ))
        if has_urgency:
            for pattern in self.KYC_PATTERNS:
                for start, end, match in _find_all(text, pattern):
                    signals.append(
                        DetectionSignal(
                            signal_type="text",
                            name="phishing_kyc_pressure",
                            description=(
                                "Message combines KYC verification pressure with "
                                "urgency or account-threat language, a common "
                                "phishing tactic."
                            ),
                            score=25.0,
                            weight=1.0,
                            confidence=0.60,
                            evidence_snippet=text[start:end],
                            evidence_source="message_body",
                            metadata={"category": self.category, "pattern": "kyc"},
                        )
                    )

        for kw in self.LOW_KEYWORDS:
            for start, end, match in _find_all(text, r"\b" + re.escape(kw) + r"\b"):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="phishing_keyword",
                        description=(
                            f"Message contains the keyword '{match}', which may "
                            "indicate phishing but requires corroboration."
                        ),
                        score=10.0,
                        weight=1.0,
                        confidence=0.30,
                        evidence_snippet=match,
                        evidence_source="message_body",
                        metadata={"category": self.category, "keyword": kw},
                    )
                )

        return signals


class FakeRecruitmentDetector(BaseDetector):
    """Detects fake job / recruitment scams."""

    category = "fake_recruitment"

    HIGH_PATTERNS = [
        r"(?:work from home|remote job) (?:no experience|no interview|immediate)",
        r"earn (?:\\$|₹|rs|rupees|dollars)?\\s*\d+ (?:per|a) (?:day|hour|week)",
        r"job (?:offer|confirmation) (?:via|through) (?:whatsapp|telegram|text)",
        r"pay (?:a|registration|processing|training) fee to (?:start|join|begin)",
    ]

    MEDIUM_PATTERNS = [
        r"(?:urgent|immediate) hiring",
        r"(?:no interview|without interview)",
        r"(?:data entry|typing) job",
        r"whatsapp (?:recruiter|hr|manager)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="fake_recruitment_high",
                        description=(
                            "Message exhibits classic fake-recruitment indicators: "
                            "unsolicited job offer with upfront payment or no interview."
                        ),
                        score=50.0,
                        weight=1.0,
                        confidence=0.80,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="fake_recruitment_medium",
                        description=(
                            "Message contains recruitment-scam language that "
                            "warrants caution but is not conclusive alone."
                        ),
                        score=25.0,
                        weight=1.0,
                        confidence=0.55,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class UPIIntentDetector(BaseDetector):
    """Detects UPI / payment fraud indicators."""

    category = "upi_payment_fraud"

    HIGH_PATTERNS = [
        r"(?:send|transfer|pay) (?:money|₹|rs|rupees|\$\d+|\d+) (?:to|via) (?:upi|phonepe|gpay|paytm)",
        r"(?:upi|upi id|vpa) (?:is|:)\s*[\w.]+@[\w]+",
        r"scan (?:this|the) qr (?:code|to pay|to receive)",
        r"money (?:will be|has been) (?:credited|transferred|refunded)",
    ]

    MEDIUM_PATTERNS = [
        r"(?:upi|payment|transfer) (?:request|link)",
        r"click (?:to|for) (?:receive|claim|get) (?:money|₹|rs|cash)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        # Contextual UPI Freeze + Demand to unlock/restore:
        # Require BOTH a freeze/suspension/block threat AND a demand to transfer/send/pay to unlock/release
        has_freeze_threat = bool(re.search(
            r"(?:account|upi|access|service) (?:has been|is) (?:frozen|blocked|suspended|locked)",
            text,
            re.IGNORECASE,
        ))
        unlock_payment_match = re.search(
            r"(?:transfer|send|pay) (?:₹\s*\d+|rs\.?\s*\d+|rupees\s*\d+|\$\s*\d+|\d+|money)?\s*(?:to unlock|to release|to unblock|to restore)",
            text,
            re.IGNORECASE,
        )
        if has_freeze_threat and unlock_payment_match:
            signals.append(
                DetectionSignal(
                    signal_type="text",
                    name="upi_freeze_extortion",
                    description=(
                        "Message claims account/UPI has been frozen and demands a monetary transfer to unlock or restore access."
                    ),
                    score=55.0,
                    weight=1.0,
                    confidence=0.85,
                    evidence_snippet=unlock_payment_match.group(0),
                    evidence_source="message_body",
                    metadata={"category": self.category, "pattern": "freeze_unlock_extortion"},
                )
            )

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="upi_payment_fraud_high",
                        description=(
                            "Message contains UPI payment instructions or a UPI ID, "
                            "a common vector for payment fraud."
                        ),
                        score=45.0,
                        weight=1.0,
                        confidence=0.75,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="upi_payment_fraud_medium",
                        description=(
                            "Message references a UPI payment request, which may be "
                            "legitimate or fraudulent depending on context."
                        ),
                        score=20.0,
                        weight=1.0,
                        confidence=0.50,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class OTPScamDetector(BaseDetector):
    """Detects OTP / one-time password scams."""

    category = "otp_scam"

    HIGH_PATTERNS = [
        r"share your (?:otp|one.time.password|verification code)",
        r"(?:otp|code) (?:is|was) (?:sent|delivered) to your",
        r"enter your (?:atm )?pin",
        r"provide your (?:atm )?pin",
        r"(?:atm )?pin.{0,30}?otp|otp.{0,30}?(?:atm )?pin",
        # Contextual OTP solicitation: requesting code / verification code
        r"send (?:me\s+)?(?:the\s+)?(?:verification code|code|otp)(?:.*?(?:to complete|immediately|for login|to login|to|via))?",
    ]

    # MEDIUM patterns specifically target scammy OTP requests, not legitimate OTP notifications
    MEDIUM_PATTERNS = [
        r"otp (?:required|needed|verification)",
        r"(?:verification|otp) code (?:request|sent) (?:by|via|to you)",
        r"(?:enter|provide|input) (?:your )?otp (?:to|for)",
        # Legitimate OTP notifications should not be flagged
        r"your otp (?:is|expires|has been sent)",
        r"otp code (?:for|to) (?:login|verification)",
        # NEW: Legitimate OTP expiration notifications
        r"your session (?:expires|expired) (?:soon|now)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="otp_scam_high",
                        description=(
                            "Message requests or references sharing an OTP, a "
                            "direct social-engineering indicator."
                        ),
                        score=50.0,
                        weight=1.0,
                        confidence=0.80,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                # Additional check: only flag if OTP is being requested/shared
                # not merely mentioned in a legitimate context
                snippet = text[start:end].lower()
                # Skip if it's just mentioning OTP expiration/information
                if "your otp" in snippet and "expires" in snippet:
                    continue  # legitimate OTP notification
                if "share your" in snippet or "send me" in snippet:
                    signals.append(
                        DetectionSignal(
                            signal_type="text",
                            name="otp_scam_medium",
                            description=(
                                "Message references an OTP or verification code in a "
                                "way that could be legitimate or part of a scam."
                            ),
                            score=20.0,
                            weight=1.0,
                            confidence=0.50,
                            evidence_snippet=text[start:end],
                            evidence_source="message_body",
                            metadata={"category": self.category, "pattern": "medium"},
                        )
                    )

        return signals


class ImpersonationDetector(BaseDetector):
    """Detects impersonation of authority figures or organizations."""

    category = "impersonation"

    # Common bank / financial institution names that may be impersonated.
    # A bare mention of a bank name is NOT fraud — it must appear in a
    # suspicious context (urgency, verification request, threat).
    BANK_NAMES = [
        "sbi", "hdfc", "icici", "axis", "kotak", "bank of baroda",
        "canara bank", "punjab national bank", "pnb", "indusind",
        "federal bank", "idbi", "rbi", "reserve bank",
    ]

    HIGH_PATTERNS = [
        r"(?:this is|i am|we are) (?:from|at|representing) (?:the )?(?:bank|police|irb|cbi|rbi|customs)",
        r"(?:your|our) (?:account|card|aadhaar|pan) (?:has been|will be) (?:blocked|suspended|cancelled)",
        r"legal (?:action|case|notice) (?:will be|has been) (?:taken|filed|issued)",
        r"arrest (?:warrant|notice)",
    ]

    MEDIUM_PATTERNS = [
        r"(?:official|government|authorized) (?:representative|agent|department)",
        r"(?:immediately|urgently) (?:contact|call|reply)",
        r"failure to (?:respond|comply|pay) (?:will|may) result in",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="impersonation_high",
                        description=(
                            "Message impersonates an authority figure or "
                            "organization to create fear or urgency."
                        ),
                        score=45.0,
                        weight=1.0,
                        confidence=0.75,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="impersonation_medium",
                        description=(
                            "Message uses authority-like language that could be "
                            "legitimate or part of an impersonation scam."
                        ),
                        score=20.0,
                        weight=1.0,
                        confidence=0.50,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        # Bank-name impersonation: only flag when a bank name appears in a
        # suspicious context (urgency + verification/threat), never on a bare
        # mention alone.
        text_lower = text.lower()
        has_urgency = bool(re.search(
            r"(?:urgent|immediately|within \d+ (?:hour|hours)|blocked|suspended|failure to comply)",
            text, re.IGNORECASE,
        ))
        has_verification_or_threat = bool(re.search(
            r"(?:verify|confirm|kyc|atm pin|otp|suspended|blocked|failure to comply)",
            text, re.IGNORECASE,
        ))
        if has_urgency and has_verification_or_threat:
            for bank in self.BANK_NAMES:
                if bank in text_lower:
                    start = text_lower.find(bank)
                    end = start + len(bank)
                    signals.append(
                        DetectionSignal(
                            signal_type="text",
                            name="bank_impersonation",
                            description=(
                                f"Message references '{bank}' in a high-pressure "
                                "verification or account-threat context, consistent "
                                "with bank impersonation fraud."
                            ),
                            score=35.0,
                            weight=1.0,
                            confidence=0.70,
                            evidence_snippet=text[start:end],
                            evidence_source="message_body",
                            metadata={
                                "category": self.category,
                                "bank": bank,
                                "pattern": "bank_impersonation",
                            },
                        )
                    )
                    break  # only one bank-impersonation signal per message

        return signals


class InvestmentFraudDetector(BaseDetector):
    """Detects investment fraud indicators."""

    category = "investment_fraud"

    HIGH_PATTERNS = [
        # Guaranteed returns with percentage - e.g. "guaranteed 50% return"
        r"guaranteed (?:\d+%|assured|fixed|high) (?:return|profit|earnings|income|yield)",
        r"(?:assured|fixed) (?:\d+%|guaranteed) (?:return|profit|earnings|income|yield)",
        # Guaranteed returns - plain phrase
        r"guaranteed (?:returns?|profits?|earnings?|income)",
        r"(?:assured|fixed) (?:returns?|profits?|earnings?|income)",
        # Unrealistic money multiplication
        r"(?:double|triple|10x|20x|50x) (?:your )?money (?:in| within) (?:\d+ )?weeks?",
        r"(?:double|triple|10x|20x|50x) (?:your )?investment (?:in| within) (?:\d+ )?weeks?",
        r"(?:double|triple|10x|20x|50x) (?:your )?money in (?:\d+ )?days?",
        # Earnings with time period
        r"(?:earn|make) (?:\d+ )?(?:per )?(?:day|week|month|year) (?:guaranteed)?",
        r"returns? (?:of| '? s)? (?:\d+ )?(?:per )?(?:day|week|month|year) (?:guaranteed|assured)?",
        # Risk-free investment claims - HIGH category
        r"no (?:risk-free|no )risk (?:investment|opportunity|plan)",
        r"risk-free (?:investment|opportunity|plan) (?:with)? (?:guaranteed|no )?risk",
        r"guaranteed (?:returns?|profit|earnings?) with (?:no )?risk",
        r"unsecured (?:investment|trading|profits)",
        r"risk-free earnings",
        r"earn \$\d+ (?:per )?(?:day|week|month|year)",
        r"assured (?:safe|guaranteed|high) (?:return|profit|earnings|income)",
        r"no risk (?:involved|of )?",
        r"unlimited (?:profits|returns|earnings)",
        r"double your (?:money|investment)",
        r"double (?:your )?(?:money|investment) in \\d+ days?",
        # Crypto investment fraud
        # Crypto investment fraud
        r"crypto (?:investment|trading|opportunity) (?:guaranteed|assured|safe|high[- ]return)",
        r"crypto (?:ico|token) (?:with)? (?:guaranteed|assured)? (?:unrealistic|high )?returns?",
        r"crypto (?:ico|token) (?:with)? (?:guaranteed|assured)? (?:unrealistic|high )?returns?",
        r"crypto (?:ico|token) (?:with)? (?:guaranteed|assured)? (?:unrealistic|high )?returns?",
        r"crypto (?:investment|trading) with (?:guaranteed|assured|hidden|unsafe) returns?",
        r"crypto (?:investment|trading|opportunity)",
        r"token (?:sale|launch|offering) (?:guaranteed|assured|high[- ]return)",
        r"unrealistic (?:returns|earnings|profits|income)",
        r"no[- ]risk (?:claims?|guarantees?)",
    ]

    MEDIUM_PATTERNS = [
        # Guaranteed returns with no percentage - e.g. "guaranteed returns"
        r"(?:guaranteed|assured|fixed) (?:returns?|profits?|earnings?) (?:with|and)? (?:no )?risk",
        # Limited time/exclusive offers
        r"(?:limited time|exclusive) (?:investment|trading) (?:opportunity|offer|plan|deal)",
        r"special (?:investment|trading) (?:plan|program|deal)",
        # High return + low risk combined
        r"high (?:return|yield|profit) (?:with| and) (?:low|reduced|minimal) risk",
        r"high (?:return|yield|profit) with guaranteed (?:no )?risk",
        # Join our investment group
        r"join our (?:investment|trading) (?:group|team|community|network)",
        # Risk-free claims
        r"(?:no |zero )risk (?:investment|opportunity|plan)",
        r"(?:no |zero )risk of (?:losing|loss)",
        r"guaranteed (?:profit|return) with (?:no )?risk",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="investment_fraud_high",
                        description=(
                            "Message promises guaranteed or unusually high "
                            "investment returns, a classic fraud indicator."
                        ),
                        score=45.0,
                        weight=1.0,
                        confidence=0.75,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="investment_fraud_medium",
                        description=(
                            "Message promotes an investment opportunity that "
                            "warrants caution."
                        ),
                        score=20.0,
                        weight=1.0,
                        confidence=0.50,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class LotteryPrizeDetector(BaseDetector):
    """Detects lottery / prize scam indicators."""

    category = "lottery_prize_scam"

    HIGH_PATTERNS = [
        r"(?:congratulations|you have).{0,30}?(?:won|been selected).{0,30}?(?:lottery|prize|jackpot|reward)",
        r"claim your (?:prize|reward|winnings|lottery)",
        r"(?:click|call|reply) (?:to|now) (?:claim|collect|receive) (?:your )?(?:prize|reward)",
        r"lucky (?:draw|winner) (?:you|has|is)",
    ]

    MEDIUM_PATTERNS = [
        r"(?:free|cash) (?:prize|reward|gift|voucher)",
        r"you (?:are|were) (?:selected|chosen) for",
        r"no (?:purchase|payment) required to (?:claim|win)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="lottery_prize_scam_high",
                        description=(
                            "Message claims the recipient won a lottery or prize "
                            "they did not enter, a classic advance-fee scam."
                        ),
                        score=45.0,
                        weight=1.0,
                        confidence=0.75,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="lottery_prize_scam_medium",
                        description=(
                            "Message references a prize or reward that may be "
                            "part of a scam."
                        ),
                        score=15.0,
                        weight=1.0,
                        confidence=0.45,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class AdvanceFeeDetector(BaseDetector):
    """Detects advance-fee fraud indicators."""

    category = "advance_fee_fraud"

    HIGH_PATTERNS = [
        r"pay (?:a|the|processing|registration|transfer) fee (?:to|before|for)",
        r"(?:wire|transfer|send) (?:money|₹|rs|\\$) (?:to|via) (?:unlock|release|claim)",
        r"(?:inheritance|fund|estate|million) (?:is|was) (?:held|frozen|stuck)",
        r"assist (?:with|in) (?:transferring|moving) (?:\d+|money|funds)",
    ]

    MEDIUM_PATTERNS = [
        r"(?:processing|administrative|legal) fee",
        r"reward of (?:\d+|\d+%|a share)",
        r"trusted (?:partner|associate|representative)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="advance_fee_fraud_high",
                        description=(
                            "Message requests an upfront payment to release or "
                            "claim funds, the hallmark of advance-fee fraud."
                        ),
                        score=50.0,
                        weight=1.0,
                        confidence=0.80,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="advance_fee_fraud_medium",
                        description=(
                            "Message references a fee or reward that may be "
                            "part of an advance-fee scam."
                        ),
                        score=20.0,
                        weight=1.0,
                        confidence=0.50,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class UrgencyIntimidationDetector(BaseDetector):
    """Detects urgency and intimidation tactics."""

    category = "urgency_intimidation"

    HIGH_PATTERNS = [
        r"(?:act|respond|reply) (?:now|immediately|within \d+ (?:hour|hours|minute|minutes))",
        r"(?:account|service|access) (?:will be|is) (?:suspended|closed|terminated|deleted)",
        r"failure to (?:respond|comply|act) (?:will|may) (?:result in|lead to)",
        r"(?:urgent|immediate) (?:action|attention|response) required",
    ]

    MEDIUM_PATTERNS = [
        r"(?:limited time|time sensitive|expires soon)",
        r"act (?:now|fast|quick)",
        r"don't (?:miss|delay|wait)",
    ]

    def detect(self, text: str) -> List[DetectionSignal]:
        signals: List[DetectionSignal] = []

        for pattern in self.HIGH_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="urgency_intimidation_high",
                        description=(
                            "Message uses urgent or intimidating language to "
                            "pressure the recipient into immediate action."
                        ),
                        score=30.0,
                        weight=1.0,
                        confidence=0.70,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "high"},
                    )
                )

        for pattern in self.MEDIUM_PATTERNS:
            for start, end, match in _find_all(text, pattern):
                signals.append(
                    DetectionSignal(
                        signal_type="text",
                        name="urgency_intimidation_medium",
                        description=(
                            "Message contains urgency language that may be "
                            "legitimate or part of a scam."
                        ),
                        score=10.0,
                        weight=1.0,
                        confidence=0.40,
                        evidence_snippet=text[start:end],
                        evidence_source="message_body",
                        metadata={"category": self.category, "pattern": "medium"},
                    )
                )

        return signals


class ScamDetector:
    """Central deterministic scam detection engine.

    Orchestrates all category-specific detectors, deduplicates overlapping
    signals, and returns a unified list of DetectionSignal objects.
    """

    def __init__(self):
        self.detectors: List[BaseDetector] = [
            PhishingDetector(),
            FakeRecruitmentDetector(),
            UPIIntentDetector(),
            OTPScamDetector(),
            ImpersonationDetector(),
            InvestmentFraudDetector(),
            LotteryPrizeDetector(),
            AdvanceFeeDetector(),
            UrgencyIntimidationDetector(),
        ]

    def detect(self, text: str) -> List[DetectionSignal]:
        """Run all detectors on the text and return deduplicated signals."""
        all_signals: List[DetectionSignal] = []

        for detector in self.detectors:
            try:
                detector_signals = detector.detect(text)
                all_signals.extend(detector_signals)
            except Exception:
                # A single detector failure must not disable the whole engine
                continue

        return self._deduplicate(all_signals)

    def _deduplicate(self, signals: List[DetectionSignal]) -> List[DetectionSignal]:
        """Remove duplicate signals with identical evidence snippets.

        Keeps the highest-confidence signal when multiple detectors produce
        the same evidence, preventing artificial score inflation.
        """
        sorted_signals = sorted(signals, key=lambda s: s.confidence, reverse=True)
        seen_snippets: set[str] = set()
        result: List[DetectionSignal] = []

        for signal in sorted_signals:
            snippet = (signal.evidence_snippet or "").strip().lower()
            if snippet and snippet in seen_snippets:
                continue
            if snippet:
                seen_snippets.add(snippet)
            result.append(signal)

        return result


# Module-level instance for convenience
scam_detector = ScamDetector()