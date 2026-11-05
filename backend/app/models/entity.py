from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Entity(Base):
    """An extracted entity (phone number, URL, email, address, person, organization)."""

    __tablename__ = "entities"

    id = Column(Integer, primary_key=True, index=True)
    investigation_id = Column(Integer, ForeignKey("investigations.id"), nullable=False)
    entity_type = Column(String, nullable=False)  # phone | url | email | address | person | org
    value = Column(Text, nullable=False)
    normalized_value = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    investigation = relationship("Investigation", back_populates="entities")