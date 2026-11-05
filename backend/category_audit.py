from tests.test_scam_detector import *
from app.services.scam_detector import ScamDetector
from app.services.risk_scoring import RiskScorer

detector = ScamDetector()
scorer = RiskScorer()

# Category mapping
category_map = {}
all_messages = SCAM_MESSAGES + LEGITIMATE_MESSAGES + AMBIGUOUS_MESSAGES
for text, expected, category in all_messages:
    category_map[text] = category

# Track per-category results
category_results = {}
for text, expected, category in all_messages:
    if category not in category_results:
        category_results[category] = {'tp': 0, 'fp': 0, 'fn': 0, 'total': 0}
    category_results[category]['total'] += 1

    signals = detector.detect(text)
    result = scorer.score([{'score': s.score, 'weight': s.weight} for s in signals])
    predicted_scam = result['risk_score'] >= 25.0

    if expected == 'scam':
        if predicted_scam:
            category_results[category]['tp'] += 1
        else:
            category_results[category]['fn'] += 1
    elif expected == 'legit':
        if predicted_scam:
            category_results[category]['fp'] += 1
    else:  # ambiguous
        if predicted_scam:
            category_results[category]['fp'] += 1

print('Category-wise detection performance:')
print(f'{"Category":<25} {"TP":<5} {"FN":<5} {"FP":<5} {"Total":<6} {"Rate":<8}')
print('-' * 58)
for cat, r in sorted(category_results.items()):
    tp = r['tp']
    fn = r['fn']
    total = r['total']
    rate = f'{tp}/{total}' if total > 0 else '0/0'
    # For scam categories, precision = tp/(tp+fp), but we don't have fp per category easily
    # Show tp/total and fn/total
    print(f'{cat:<25} {tp:<5} {fn:<5} {rate:<8}')

print()
print('Scam categories only:')
scam_categories = [cat for cat in category_results if cat == 'scam']  # This won't work
# Let me just print scam-related categories
for cat in ['phishing', 'fake_recruitment', 'upi_payment_fraud', 'otp_scam', 'impersonation', 'investment_fraud', 'lottery_prize_scam', 'advance_fee_fraud', 'urgency_intimidation']:
    if cat in category_results:
        r = category_results[cat]
        print(f'{cat:<25} {r["tp"]:<5} {r["fn"]:<5} {r["total"]-r["tp"]-r["fn"]:<5} {r["total"]:<6}')
" 2>&1