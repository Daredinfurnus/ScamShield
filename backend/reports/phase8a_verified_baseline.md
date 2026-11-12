# Phase 8a: Verified Baseline Analysis

## Overview

Comparative analysis of all 50 benchmark cases from `detection_benchmark.json` against actual predictions stored in `backend/reports/detection_benchmark.json`.

**Total cases**: 50
**Benchmark source**: `backend/tests/fixtures/detection_benchmark.json`
**Report source**: `backend/reports/detection_benchmark.json`

---

## Summary Metrics Verification

| Metric | Value | Match |
|--------|-------|-------|
| True Positives (TP) | 18 | ✅ |
| True Negatives (TN) | 24 | ✅ |
| False Positives (FP) | 2 | ✅ |
| False Negatives (FN) | 6 | ✅ |
| Accuracy | 0.84 | ✅ |
| Precision | 0.9 | ✅ |
| Recall | 0.75 | ✅ |
| F1 Score | 0.8182 | ✅ |
| Specificity | 0.9231 | ✅ |
| False Positive Rate | 0.0769 | ✅ |
| False Negative Rate | 0.25 | ✅ |

## False Positives (2 cases)

*False Positive: Expected "legitimate" but predicted as "scam"*

| Case ID | Category | Expected | Predicted | Risk Score | Expected Band | Predicted Band | Explanation |
|---------|----------|----------|-----------|------------|---------------|----------------|-------------|
| **B008** | banking_phishing | legitimate | scam | 50.0 | low | high | RBI consumer advisory warning about scams |
## False Negatives (6 cases)

*False Negative: Expected "scam" but predicted as "legitimate"*

| Case ID | Category | Expected | Predicted | Risk Score | Expected Band | Predicted Band | Explanation |
|---------|----------|----------|-----------|------------|---------------|----------------|-------------|
| **B010** | otp_upi_payment_fraud | scam | legitimate | 20.0 | high | low | OTP code request + session expiry urgency |
| **B011** | otp_upi_payment_fraud | scam | legitimate | 10.0 | high | low | UPI freeze threat + money transfer request + UPI ID |
| **B028** | delivery_parcel_refund | scam | legitimate | 0.0 | medium | low | Failed delivery + redelivery fee request + suspicious URL |
| **B031** | delivery_parcel_refund | scam | legitimate | 0.0 | medium | low | Customs duty fee + pay now to avoid return |
## Risk Band Discrepancy Analysis

The risk band confusion matrix reveals 19 cases where the predicted risk band differs from the expected risk band:

| Expected Band | Low | Medium | High | Critical | Total |
|-------------|-----|--------|------|----------|-------|
| **Low** | 24 | 1 | 1 | 0 | 26 |
| **Medium** | 2 | 1 | 1 | 1 | 5 |
| **High** | 3 | 2 | 4 | 7 | 16 |
| **Critical** | 1 | 0 | 0 | 2 | 3 |
| **Total** | 30 | 4 | 6 | 10 | 50 |

**Key observations**:
- All 6 false negatives (B010, B011, B028, B031, B033, B036) have risk scores of 0.0 or very low (<25), causing them to be classified as "low" risk band even though their expected bands are high/critical.
- All 2 false positives (B008, B046) have moderate risk scores (35.0-50.0) that correctly exceed the threshold, but the underlying messages are legitimate.
- B002, B003, B004 (banking_phishing) have risk scores of 100.0 but are predicted as "critical" band, which is correct.
## Per-Category Performance

| Category | Total | TP | TN | FP | FN | Accuracy | Precision | Recall |
|----------|-------|----|----|----|----|----------|-----------|--------|
| ambiguous_messages | 6 | 0 | 5 | 1 | 0 | 0.8333 | 0.0 | 0.0 |
| banking_phishing | 8 | 5 | 2 | 1 | 0 | 0.875 | 0.8333 | 1.0 |
| delivery_parcel_refund | 5 | 1 | 2 | 0 | 2 | 0.6 | 1.0 | 0.3333 |
| fake_recruitment | 6 | 4 | 2 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| investment_financial_fraud | 4 | 1 | 1 | 0 | 2 | 0.5 | 1.0 | 0.3333 |
| legitimate_messages | 8 | 0 | 8 | 0 | 0 | 1.0 | 0.0 | 0.0 |
| otp_upi_payment_fraud | 7 | 3 | 2 | 0 | 2 | 0.7143 | 1.0 | 0.6 |
## Resolved Discrepancy

**Previous audit error counts**: The existing summary already correctly reports TP=18, TN=24, FP=2, FN=6. This verification confirms those counts are accurate.

**Key findings**:
1. The summary metrics are **correct** and verified against all 50 cases.
2. There are **8 individual case mismatches** between expected and predicted classifications, which account for the FP=2 and FN=6 counts.
3. **Risk band predictions** are widely inconsistent, especially for categories where the risk scorer assigns 0.0 to clearly fraudulent messages (delivery_parcel_refund, investment_financial_fraud).
4. The classification threshold (risk_score >= 25 => scam; risk_score < 25 => legitimate) is consistently applied, but the risk scorer itself has patterns of under-detection in certain fraud categories.

**8 mismatch cases detailed**:
- **B008**: expected=legitimate, predicted=scam, risk_score=50.0, expected_band=low, predicted_band=high, category=banking_phishing
- **B046**: expected=legitimate, predicted=scam, risk_score=35.0, expected_band=low, predicted_band=medium, category=ambiguous_messages
- **B010**: expected=scam, predicted=legitimate, risk_score=20.0, expected_band=high, predicted_band=low, category=otp_upi_payment_fraud
- **B011**: expected=scam, predicted=legitimate, risk_score=10.0, expected_band=high, predicted_band=low, category=otp_upi_payment_fraud
- **B028**: expected=scam, predicted=legitimate, risk_score=0.0, expected_band=medium, predicted_band=low, category=delivery_parcel_refund
- **B031**: expected=scam, predicted=legitimate, risk_score=0.0, expected_band=medium, predicted_band=low, category=delivery_parcel_refund
- **B033**: expected=scam, predicted=legitimate, risk_score=0.0, expected_band=high, predicted_band=low, category=investment_financial_fraud
## Recommendations (Read-Only Observations)

- **Risk scorer improvements needed for**: delivery_parcel_refund advance-fee fraud patterns, investment_financial_fraud guaranteed-return patterns, otp_upi_payment_fraud urgency/threat language weighting.
- **False positives (B008, B046)** are expected given the current threshold; B008 is a consumer advisory that legitimately resembles a scam pattern, and B046 is a common legitimate newsletter pattern.
- **False negatives (B010, B011, B028, B031, B033, B036)** represent categories where the risk scorer fails to capture fraud-indicative patterns, not classification threshold issues.
- No code, tests, benchmark labels, or databases were modified during this analysis (read-only).