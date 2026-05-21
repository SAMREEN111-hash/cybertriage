from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    event_type = Column(String, index=True)
    log_message = Column(String)
    tool = Column(String)  # splunk | crowdstrike | elk

    # Triage output
    severity = Column(String)           # critical | high | medium | low
    risk_score = Column(Float)          # 0-100
    mitre_technique = Column(String)
    mitre_tactic = Column(String)
    recommended_action = Column(String)

    # AbuseIPDB enrichment
    ip_abuse_score = Column(Float, nullable=True)
    ip_country = Column(String, nullable=True)
    ip_is_tor = Column(String, nullable=True)

    # Analyst workflow
    status = Column(String, default="open")  # open | investigating | resolved | false_positive
    analyst_notes = Column(String, nullable=True)
    extra_data = Column(JSON, nullable=True)

    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="alerts")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
