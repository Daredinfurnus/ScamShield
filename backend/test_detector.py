from app.services.scam_detector import ScamDetector

d = ScamDetector()
test_cases = [
    "URGENT: Your account has been suspended. Click here to verify your password now!",
    "Hello, this is a legitimate meeting reminder for tomorrow at 2pm.",
    "Congratulations! You have won a $1000 lottery prize. Click here to claim.",
    "Your OTP is 123456. Do not share it with anyone.",
    "Please review the Q3 budget report attached to this email.",
]

for text in test_cases:
    result = d.detect(text)
    print(f"\nText: {text[:70]}...")
    print(f"  Signals: {len(result)}")
    for s in result:
        print(f"    {s.name}: score={s.score}, conf={s.confidence}, evidence=\"{s.evidence_snippet}\"")
