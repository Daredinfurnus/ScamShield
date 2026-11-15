from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Investigation(Base):
    """A single investigation case (message, URL, or screenshot submitted by a user)."""

    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)

    title = Column(String, nullable=False)
    input_type = Column(String, nullable=False)  # text | url | image
    input_content = Column(Text, nullable=False)  # raw message / URL / uploaded filename
    risk_score = Column(Float, default=0.0)  # 0-100, set by backend scoring engine
    risk_band = Column(String, default="low")  # low | medium | high | critical
    status = Column(String, default="pending")  # pending | completed | failed

    # Anonymous public intake capabilities
    is_anonymous = Column(Boolean, default=False, index=True)
    access_token_hash = Column(String(128), index=True, nullable=True)
    access_token_expires_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    tenant = relationship("Tenant", back_populates="investigations")
    created_by_user = relationship("User", back_populates="investigations")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    entities = relationship("Entity", back_populates="investigation", cascade="all, delete-orphan")
