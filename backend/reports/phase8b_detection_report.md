# SCAMSHIELD PHASE 8B â€” VERIFIED BASELINE IMPLEMENTATION

## Verified Baseline (from phase8a_verified_baseline.md)

| Metric | Value |
|--------|-------|
| True Positives (TP) | 18 |
| True Negatives (TN) | 24 |
| False Positives (FP) | 2 |
| False Negatives (FN) | 6 |
| Accuracy | 84% |
| Precision | 90% |
| Recall | 75% |
### Confirmed Error Cases

**False Positives (2 cases)** â€” Expected legitimate, predicted as scam:

| Case ID | Category | Issue |
|---------|----------|-------|
| B008 | banking_phishing | Legitimate RBI consumer advisory warning about scams |
| B046 | ambiguous_messages | Legitimate newsletter email verification |

**False Negatives (6 cases)** â€” Expected scam, predicted as legitimate:

| Case ID | Category | Issue |
|---------|----------|-------|
| B010 | otp_upi_payment_fraud | OTP code request and session expiry urgency |
| B011 | otp_upi_payment_fraud | UPI freeze threat and money transfer request |
| B028 | delivery_parcel_refund | Failed delivery and redelivery fee |
| B031 | delivery_parcel_refund | Customs duty and payment urgency |
| B033 | investment_financial_fraud | Guaranteed investment returns and double-money claim |## Stage 2: Implement targeted detection

### Prioritized detection improvements

#### Priority 1: Investment fraud detection
**Missing patterns identified from B033, B036**:
- Guaranteed/assured returns language ("double your money", "assured returns")
- "No risk" claims
- Cryptocurrency investment references
- Unrealistic earning projections ("monthly returns of 20%", "guaranteed profit")
- Ponzi/pyramid scheme language

**Evidence requirements**:
- Presence of guaranteed return claims
- "No risk" or "risk-free" assertions
- Cryptocurrency/token investment mentions
- Unrealistic projected returns (>100% annualized)
- Referral/recruitment language

#### Priority 2: OTP and UPI contextual detection
**Missing patterns identified from B010, B011**:
- OTP/code request combined with urgency/expiry language ("within 2 hours", "session expires")
- UPI freeze/threat language combined with money transfer requests
- Session expiry or account lockout threats
- Money transfer or payment requests via UPI/OTP channels

**Evidence requirements**:
- OTP/code request keyword + urgency/expiry time marker
- UPI/freeze/threat keyword + money transfer/request keyword
- Time-bound pressure ("expires today", "within hours")
- Payment method specification (UPI ID, bank transfer)

#### Priority 3: Delivery fee and customs duty fraud detection
**Missing patterns identified from B028, B031**:
- "Redelivery fee" or "re-delivery charge"
- "Customs duty" or "import tax" demands
- "Pay now to avoid" return/cancellation/threat language
- International parcel/package context
- Suspicious URL + payment demand combination

**Evidence requirements**:
- Redelivery fee / customs duty keyword + amount specification
- "Pay now to avoid" threat phrase
- International/parcel/package context keyword
- Suspicious URL or tracking link presence

#### Priority 4: Legitimate advisory and newsletter de-weighting
**Missing de-weighting from B008, B046**:
- Consumer advisories/warnings from government/regulatory bodies
- Newsletter subscription verification patterns
- Legitimate communication markers that resemble scam patterns

**Evidence requirements for legitimate de-weighting**:
- Government/regulatory agency naming (RBI, SEC, consumer protection)
- "Advisory," "warning," "information" intent markers
- Newsletter subscription context ("you subscribed to", "confirm your email")
- Absence of urgency/threat language ("urgent", "immediate action required", "penalty")

### Implementation guidance (do not simply increase scores)

1. **Add new signal patterns** for each prioritized category above, rather than modifying existing score calculations
2. **Maintain evidence traceability** — each new detection should produce actual_signal_names and indicators_correctly_detected/indicators_missed
3. **Preserve RiskScorer authority** — the RiskScorer remains the single authoritative scoring engine; new signals feed into it but do not bypass it
4. **Avoid artificial score inflation** — new patterns should only trigger on genuine fraud indicators, not on legitimate communications that happen to share surface similarities
5. **Do not change risk thresholds merely to hide inconsistencies** — the 25-point threshold remains; investigations into the 19 risk-band mismatches proceed separately (per Stage 4)


---
## Stage 3: Add regression coverage

### 3.1 Scam counterexamples for every improvement
For each new detection pattern implemented, add test cases covering:
- **Positive examples** (scam messages containing the new pattern)
- **Negative examples** (legitimate messages that should NOT trigger the pattern)

Example format for investment fraud pattern:
```json
{
  "case_id": "INVEST-001",
  "category": "investment_financial_fraud",
  "message": "Guaranteed 50% monthly returns on crypto investment. Double your money in 30 days. No risk involved.",
  "expected_classification": "scam",
  "expected_risk_band": "critical"
}
```

Example format for legitimate counterexample:
```json
{
  "case_id": "LEGIT-001",
  "category": "legitimate_messages",
  "message": "Investment advice: diversify your portfolio with these options.",
  "expected_classification": "legitimate",
  "expected_risk_band": "low"
}
```

### 3.2 Legitimate counterexamples for every improvement
For each new detection pattern, ensure legitimate messages that could superficially resemble scams are captured as true negatives:
- B008-type RBI advisories
- B046-type newsletter verifications
- Legitimate delivery notifications
- Legitimate account communications

### 3.3 Preserve existing test coverage
- All existing 50 benchmark cases remain pass/fail as baseline
- No existing test cases modified or removed
- New test cases added alongside existing ones

### 3.4 Evidence traceability
Every improved detection must produce:
- `actual_signal_names`: list of signals that matched
- `indicators_correctly_detected`: which expected indicators were found
- `indicators_missed`: which expected indicators were not found
- `num_signals`: count of signals triggered

This ensures the RiskScorer's signal deduplication and evidence traceability requirements are maintained.

### 3.5 Database isolation
- No SQLite database modifications
- No unrelated architecture changes
- All changes confined to detection pattern matching and test coverage

---
## Stage 4: Verify

### 4.1 Run all backend tests
- Execute full test suite to confirm no regressions
- Verify all 50 original benchmark cases still pass
- Confirm holdout dataset evaluation

### 4.2 Run original 50-case benchmark
- Compare new results against verified baseline:
  - TP: still 18 (or improved)
  - TN: still 24 (or improved, without introducing new FPs)
  - FP: should not increase beyond 2
  - FN: should decrease toward or below 6
  - Accuracy: should improve toward or exceed 84%
  - Precision: should remain at or above 90%
  - Recall: should improve above 75%

### 4.3 Run separate 10-case holdout
- Evaluate model on 10 previously unseen cases
- Report classification metrics
- No tuning adjustments based on holdout results

### 4.4 Frontend production build
- Verify frontend build compiles successfully
- No breaking changes to API surfaces
- Detection results consistent with backend output

### 4.5 Compare baseline and new results
| Metric | Baseline (Phase 8a) | Target (Phase 8b) |
|--------|--------------------|-------------------|
| True Positives | 18 | >= 18 (ideally >18) |
| True Negatives | 24 | <= 24 (ideally same, no new FPs) |
| False Positives | 2 | <= 2 (no increase) |
| False Negatives | 6 | < 6 (ideally 4-5) |
| Accuracy | 84% | > 84% |
| Precision | 90% | >= 90% |
| Recall | 75% | > 75% |
| F1 Score | 0.8182 | > 0.8182 |

### 4.6 Investigate the 19 risk-band mismatches separately
- The 19 cases where predicted risk band differs from expected risk band are documented in phase8a_verified_baseline.md
- These are **not** to be resolved by changing risk thresholds
- Separate investigation required into why risk scores don't match expected bands
- Key patterns: 6 FN cases with risk_score=0.0 but expected high/critical bands; band prediction inconsistencies across banking_phishing cases
- Investigation report to be produced independently; do not use threshold changes to "fix" band mismatches

### 4.7 Targets
- **Recall above 75%**: New detection patterns should specifically target the 6 currently-missed false negative categories
- **Precision at least 90%, if achievable**: Ensure new patterns do not increase false positives beyond the current 2; the 10% FP tolerance threshold
- **No artificial score inflation**: New signals must only trigger on genuine fraud indicators
- **No benchmark-label changes**: All 50 expected classifications remain as originally defined
- **Investigate 19 risk-band mismatches separately**: Independent study; threshold changes prohibited as fix mechanism
```

