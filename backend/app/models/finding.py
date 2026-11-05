from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Finding(Base):
    """An individual piece of evidence contributing to an investigation's risk score.

    Every finding references actual evidence (snippet + source) so that AI
    explanations can be grounded in observable data rather than invented claims.
    """

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False)
    finding_type = Column(String, nullable=False)  # text | url | ocr | entity | relationship
    title = Column(String, nullable=False)
    description = Column(Text)
    evidence_snippet = Column(Text)  # the actual observed evidence
    evidence_source = Column(String)  # e.g. message_body | ocr | url_heuristic | safe_browsing
    score = Column(Float, default=0.0)  # contribution toward the 0-100 risk score
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    investigation = relationship("Investigation", back_populates="findings")