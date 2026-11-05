"""Comprehensive tests for the ScamDetector deterministic engine.

Covers 50+ synthetic test messages across scam, legitimate, and ambiguous
categories. Evaluates precision, recall, F1, confusion matrix, and
false-positive analysis.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.services.scam_detector import ScamDetector
from app.services.risk_scoring import RiskScorer


SCAM_MESSAGES: List[Tuple[str, str]] = [
    ("URGENT: Your account has been suspended. Click here to verify your password now!", "scam", "phishing"),
    ("Verify your identity by entering your SSN and credit card details at the link below.", "scam", "phishing"),
    ("Reset your account login credentials immediately to avoid deactivation.", "scam", "phishing"),
    ("Your bank account will be closed unless you confirm your password within 24 hours.", "scam", "phishing"),
    ("Update your payment details by clicking here to reactivate your account.", "scam", "phishing"),
    ("Work from home, no interview required. Pay a registration fee to start.", "scam", "fake_recruitment"),
    ("Earn $500 per day with our remote data entry job. No experience needed.", "scam", "fake_recruitment"),
    ("Job offer via WhatsApp. Immediate hiring, no interview, training fee applies.", "scam", "fake_recruitment"),
    ("Remote job confirmation via text. Pay processing fee to join.", "scam", "fake_recruitment"),
    ("Send money via UPI to this phonepe ID: user@upi to claim your reward.", "scam", "upi_payment_fraud"),
    ("Scan this QR code to receive ₹5000 instantly.", "scam", "upi_payment_fraud"),
    ("Your UPI account has been frozen. Transfer money to unlock it.", "scam", "upi_payment_fraud"),
    ("Money will be credited to your account after you pay the transfer fee.", "scam", "upi_payment_fraud"),
    ("Share your OTP code with our agent to verify your identity.", "scam", "otp_scam"),
    ("Send me the verification code to complete your login.", "scam", "otp_scam"),
    ("Your OTP is 123456. Share it with us to confirm the transaction.", "scam", "otp_scam"),
    ("Enter the OTP below to verify your account immediately.", "scam", "otp_scam"),
    ("This is the IRS. Your account has been blocked. Call us immediately.", "scam", "impersonation"),
    ("Legal action will be taken against you. Failure to comply will result in arrest.", "scam", "impersonation"),
    ("We are from the bank. Your card has been suspended. Respond now.", "scam", "impersonation"),
    ("Government official here. You have an unpaid tax warrant.", "scam", "impersonation"),
    ("Guaranteed 50% return on investment in just 30 days. Double your money!", "scam", "investment_fraud"),
    ("Crypto investment opportunity with assured safe returns. Join now.", "scam", "investment_fraud"),
    ("High yield profit with low risk. Limited time investment offer.", "scam", "investment_fraud"),
    ("Invest $1000 and earn $5000 per week. Guaranteed returns.", "scam", "investment_fraud"),
    ("Congratulations! You have won a $10000 lottery prize. Click here to claim.", "scam", "lottery_prize_scam"),
    ("You have been selected for a lucky draw. Claim your reward now.", "scam", "lottery_prize_scam"),
    ("No purchase required to win this cash prize. Call now to collect.", "scam", "lottery_prize_scam"),
    ("Free gift voucher! You were chosen for our exclusive reward.", "scam", "lottery_prize_scam"),
    ("Pay a processing fee to unlock your inheritance funds.", "scam", "advance_fee_fraud"),
    ("Transfer money to release your stuck estate funds. Trusted partner.", "scam", "advance_fee_fraud"),
    ("Assist with transferring million dollar funds. Reward of 20%.", "scam", "advance_fee_fraud"),
    ("Wire money to claim your reward. Administrative fee required.", "scam", "advance_fee_fraud"),
    ("Act now or your account will be terminated within 2 hours!", "scam", "urgency_intimidation"),
    ("Immediate response required. Failure to act will lead to service closure.", "scam", "urgency_intimidation"),
    ("Urgent action needed. Your access will be deleted if you don't reply now.", "scam", "urgency_intimidation"),
]

LEGITIMATE_MESSAGES: List[Tuple[str, str]] = [
    ("Hello, this is a reminder about our team meeting tomorrow at 2pm in conference room B.", "legit", "meeting"),
    ("Your monthly statement is available for download in your online banking portal.", "legit", "banking"),
    ("Please review the Q3 budget report attached to this email and send feedback by Friday.", "legit", "work"),
    ("Your password was successfully changed. If you did not make this change, contact support.", "legit", "security_notice"),
    ("Thank you for your payment of $49.99. Your subscription is active until next month.", "legit", "payment_confirmation"),
    ("Your OTP for login is 789012. This code expires in 10 minutes.", "legit", "otp_legitimate"),
    ("Your account has been verified. Welcome to our platform!", "legit", "account_verification"),
    ("The urgent delivery of your package is scheduled for today between 2-4pm.", "legit", "delivery"),
    ("Free shipping on all orders over $50. Shop now at our store.", "legit", "promo"),
    ("Your payment of $100 was received. Thank you for your business.", "legit", "payment_received"),
]

AMBIGUOUS_MESSAGES: List[Tuple[str, str]] = [
    ("Your account needs attention. Please log in to review recent activity.", "ambiguous", "account_review"),
    ("Click here to verify your email address for the newsletter you subscribed to.", "ambiguous", "email_verification"),
    ("Urgent: Your subscription expires tomorrow. Renew to continue service.", "ambiguous", "subscription_renewal"),
    ("Free trial ends today. Upgrade to premium to keep access.", "ambiguous", "free_trial"),
    ("Payment failed. Update your payment method to avoid service interruption.", "ambiguous", "payment_failed"),
]


def _classify(signals) -> bool:
    """A message is classified as scam if RiskScorer gives score >= 25 (medium+)."""
    scorer = RiskScorer()
    result = scorer.score([{"score": s.score, "weight": s.weight} for s in signals])
    return result["risk_score"] >= 25.0


def test_all_detectors_produce_structured_signals():
    """Every detector returns DetectionSignal-compatible objects with evidence."""
    detector = ScamDetector()
    text = "URGENT: Your account has been suspended. Click here to verify your password now!"
    signals = detector.detect(text)
    assert len(signals) > 0
    for s in signals:
        assert s.signal_type == "text"
        assert s.name
        assert 0.0 <= s.score <= 100.0
        assert 0.0 <= s.confidence <= 1.0
        assert s.evidence_snippet
        assert s.evidence_snippet in text
        assert s.evidence_source == "message_body"
        assert s.confidence < 1.0


def test_no_keyword_is_proof_of_fraud():
    """A single keyword match should never produce max confidence."""
    detector = ScamDetector()
    signals = detector.detect("Hello, please check your account statement.")
    for s in signals:
        assert s.confidence < 1.0, f"Signal {s.name} has confidence 1.0 for keyword-only match"


def test_legitimate_messages_not_auto_scam():
    """Legitimate messages containing 'urgent', 'free', 'account', 'payment' should not be auto-scams."""
    detector = ScamDetector()
    scorer = RiskScorer()

    for text, expected, _ in LEGITIMATE_MESSAGES:
        signals = detector.detect(text)
        result = scorer.score([{"score": s.score, "weight": s.weight} for s in signals])
        assert result["risk_score"] < 25.0, (
            f"Legitimate message classified as scam: '{text}' (score={result['risk_score']})"
        )


def test_ambiguous_messages_handled_conservatively():
    """Ambiguous messages should not produce high-confidence scam verdicts."""
    detector = ScamDetector()
    scorer = RiskScorer()

    for text, expected, _ in AMBIGUOUS_MESSAGES:
        signals = detector.detect(text)
        result = scorer.score([{"score": s.score, "weight": s.weight} for s in signals])
        assert result["risk_score"] < 50.0, (
            f"Ambiguous message classified too high: '{text}' (score={result['risk_score']})"
        )


def test_duplicate_signal_prevention():
    """Duplicate signals with identical evidence should be deduplicated."""
    detector = ScamDetector()
    text = "Your account password needs to be verified. Verify your account password now."
    signals = detector.detect(text)
    snippets = [s.evidence_snippet.strip().lower() for s in signals if s.evidence_snippet]
    assert len(snippets) == len(set(snippets)), "Duplicate evidence snippets found"


def test_empty_signals_not_verified_safe():
    """Empty signal collection should not be treated as verified safe."""
    detector = ScamDetector()
    scorer = RiskScorer()

    text = "Hello, how are you today?"
    signals = detector.detect(text)
    result = scorer.score([{"score": s.score, "weight": s.weight} for s in signals])

    assert result["risk_score"] == 0.0
    assert result["risk_band"] == "low"
    assert len(signals) == 0


def test_scam_detection_precision_recall():
    """Evaluate precision, recall, F1 on the full dataset."""
    detector = ScamDetector()
    scorer = RiskScorer()

    all_messages = SCAM_MESSAGES + LEGITIMATE_MESSAGES + AMBIGUOUS_MESSAGES

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    scam_true_positives = 0
    scam_false_negatives = 0

    for text, expected, category in all_messages:
        signals = detector.detect(text)
        result = scorer.score([{"score": s.score, "weight": s.weight} for s in signals])
        predicted_scam = result["risk_score"] >= 25.0

        if expected == "scam":
            if predicted_scam:
                true_positives += 1
                scam_true_positives += 1
            else:
                false_negatives += 1
                scam_false_negatives += 1
        elif expected == "legit":
            if predicted_scam:
                false_positives += 1
            else:
                true_negatives += 1
        else:
            if predicted_scam:
                false_positives += 1
            else:
                true_negatives += 1

    total = len(all_messages)
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\n{'='*60}")
    print(f"SCAM DETECTOR EVALUATION RESULTS")
    print(f"{'='*60}")
    print(f"Total messages: {total}")
    print(f"  Scam messages: {len(SCAM_MESSAGES)}")
    print(f"  Legitimate messages: {len(LEGITIMATE_MESSAGES)}")
    print(f"  Ambiguous messages: {len(AMBIGUOUS_MESSAGES)}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives (scam detected): {true_positives}")
    print(f"  False Positives (legit/ambiguous flagged): {false_positives}")
    print(f"  True Negatives (correctly not flagged): {true_negatives}")
    print(f"  False Negatives (scam missed): {false_negatives}")
    print(f"\nMetrics:")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall: {recall:.3f}")
    print(f"  F1 Score: {f1:.3f}")
    print(f"\nScam detection: {scam_true_positives}/{len(SCAM_MESSAGES)} scams caught, {scam_false_negatives} missed")
    print(f"{'='*60}\n")

    assert precision >= 0.70, f"Precision too low: {precision:.3f}"
    assert recall >= 0.70, f"Recall too low: {recall:.3f}"
    assert f1 >= 0.70, f"F1 too low: {f1:.3f}"
    assert false_positives <= 3, f"Too many false positives: {false_positives}"