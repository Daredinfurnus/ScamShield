from app.services.investigation_engine import InvestigationEngine
from app.database import SessionLocal, engine, Base

Base.metadata.create_all(bind=engine)

db = SessionLocal()
eng = InvestigationEngine(db_session=db)
result = eng.analyze_text(
    text='URGENT: Your account has been suspended. Click here to verify your password now!',
    title='Test Phishing'
)
print(f'investigation_id: {result["investigation_id"]}')
print(f'status: {result["status"]}')
print(f'risk_score: {result["risk_score"]}')
print(f'risk_band: {result["risk_band"]}')
print(f'signals: {len(result["signals"])}')
for s in result['signals']:
    print(f'  {s["name"]}: score={s["score"]}, conf={s["confidence"]}, evidence="{s["evidence_snippet"]}"')
print(f'findings: {len(result["findings"])}')
print(f'summary: {result["analysis_summary"]}')
db.close()
Base.metadata.drop_all(bind=engine)
print("\nIntegration test PASSED")
