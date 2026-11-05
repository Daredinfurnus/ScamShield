from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Investigation(Base):
    """A single investigation case (message, URL, or screenshot submitted by a user)."""

    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    input_type = Column(String, nullable=False)  # text | url | image
    input_content = Column(Text, nullable=False)  # raw message / URL / uploaded filename
    risk_score = Column(Float, default=0.0)  # 0-100, set by backend scoring engine
    risk_band = Column(String, default="low")  # low | medium | high | critical
    status = Column(String, default="pending")  # pending | completed | failed
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="investigation", cascade="all, delete-orphan")