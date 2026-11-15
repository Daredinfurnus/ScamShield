from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Tenant(Base):
    """An organizational tenant boundary for investigations, users, and API keys."""

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, index=True, nullable=False)
    status = Column(String(50), default="active", nullable=False)  # active | suspended
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="tenant")
    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")
