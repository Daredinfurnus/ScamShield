# ScamShield Detection Benchmark Report

## Summary

- Total cases: 50
- Accuracy: 1.0
- Precision: 1.0
- Recall: 1.0
- F1 Score: 1.0
- Specificity: 1.0
- False Positive Rate: 0.0
- False Negative Rate: 0.0

### Confusion Matrix

| Metric | Count |
|--------|-------|
| True Positives | 24 |
| True Negatives | 26 |
| False Positives | 0 |
| False Negatives | 0 |

## Risk Band Confusion Matrix

| Expected \ Predicted | low | medium | high | critical | Total |
|---|---|---|---|---|---|
| low | 26 | 0 | 0 | 0 | 26 |
| medium | 0 | 3 | 1 | 1 | 5 |
| high | 0 | 1 | 7 | 8 | 16 |
| critical | 0 | 0 | 0 | 3 | 3 |

## Category-wise Performance

| Category | Total | Accuracy | Precision | Recall | FP | FN |
|----------|-------|----------|-----------|--------|----|----|
| ambiguous_messages | 6 | 1.0 | 0.0 | 0.0 | 0 | 0 |
| banking_phishing | 8 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| delivery_parcel_refund | 5 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| fake_recruitment | 6 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| investment_financial_fraud | 4 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| legitimate_messages | 8 | 1.0 | 0.0 | 0.0 | 0 | 0 |
| otp_upi_payment_fraud | 7 | 1.0 | 1.0 | 1.0 | 0 | 0 |
| suspicious_url_credential_harvesting | 6 | 1.0 | 1.0 | 1.0 | 0 | 0 |

## False Positives (Legitimate flagged as scam)

- None

## False Negatives (Scam flagged as legitimate)

- None

## Risk Band Errors

- **Case B002** (banking_phishing): Expected high, Got critical (Score: 100.0)
- **Case B003** (banking_phishing): Expected high, Got critical (Score: 100.0)
- **Case B004** (banking_phishing): Expected high, Got critical (Score: 100.0)
- **Case B013** (otp_upi_payment_fraud): Expected medium, Got high (Score: 55.0)
- **Case B016** (fake_recruitment): Expected high, Got medium (Score: 25.0)
- **Case B018** (fake_recruitment): Expected high, Got critical (Score: 100.0)
- **Case B021** (fake_recruitment): Expected high, Got critical (Score: 100.0)
- **Case B022** (suspicious_url_credential_harvesting): Expected high, Got critical (Score: 75.0)
- **Case B023** (suspicious_url_credential_harvesting): Expected medium, Got critical (Score: 80.0)
- **Case B024** (suspicious_url_credential_harvesting): Expected high, Got critical (Score: 100.0)
- **Case B033** (investment_financial_fraud): Expected high, Got critical (Score: 90.0)

## Recommendations

1. Review false positives to adjust detector thresholds or add context rules.
2. Review false negatives to add missing detection patterns.
3. RiskScorer remains authoritative - do not artificially inflate scores.
4. Add regression tests for any production detection changes.