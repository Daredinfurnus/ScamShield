from fastapi import APIRouter

router = APIRouter()


@router.get("/")
def get_report(investigation_id: int):
    # TODO Phase 9: wire into report_generation service
    return {"investigation_id": investigation_id, "note": "Report generation not yet implemented (Phase 9)."}