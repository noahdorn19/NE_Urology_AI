# providers_db.py
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Float, Text, Index, UniqueConstraint
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

# Use SQLite file; switch to Postgres by changing the URL
ENGINE_URL = "sqlite:///providers.db"

engine = create_engine(ENGINE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

class ProviderPref(Base):
    __tablename__ = "provider_prefs"
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), index=True, nullable=False)

    # core extracted fields from the doc
    children_policy = Column(String(128))       # e.g., "No kids", "No kids under 16", "Yes only for certain things"
    special_requests = Column(Text)             # freeform notes column
    on_call_routing = Column(Text)              # text describing message/phone routing on call days
    non_call_routing = Column(Text)             # same for non-call
    pm_out = Column(String(256))                # PM out notes
    direct_phone = Column(String(64))           # provider phone listed in table
    er_dr_hospital_rules = Column(Text)         # lines about ER/consults/Drs or ER
    provider_call_rules = Column(Text)          # “Provider call” column text
    last_source = Column(String(512))           # path to doc / version
    imported_at = Column(DateTime, default=datetime.utcnow)

    # convenience flags your bot can use
    allows_vasectomy = Column(Boolean)          # nullable; only set when doc is explicit (e.g., TMK No Vasectomies)
    sees_new_kids = Column(Boolean)             # nullable
    sees_pessary = Column(Boolean)

class Provider(Base):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True)
    abbr = Column(String(16), nullable=False, unique=True, index=True)   # e.g., DLH
    full_name = Column(String(128), nullable=False)                       # e.g., Dr. Don Henslee
    role = Column(String(64), nullable=False)                             # MD, PA-C, APRN, ...
    department = Column(String(64), nullable=True)                        # optional
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    aliases = relationship("ProviderAlias", back_populates="provider", cascade="all, delete-orphan")
    notes = relationship("ProviderNote", back_populates="provider", cascade="all, delete-orphan")

class ProviderAlias(Base):
    __tablename__ = "provider_aliases"
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), nullable=False, index=True)
    alias = Column(String(128), nullable=False, index=True)               # e.g., "Brandon Henslee", "Dr. Henslee (son)"
    normalized = Column(String(128), nullable=False, index=True)          # lowercase/trim
    confidence = Column(Float, nullable=False, default=1.0)               # 0..1 (for auto-mined aliases)
    source = Column(String(256), nullable=True)                           # e.g., file path / rule / manual
    pending_review = Column(Boolean, nullable=False, default=False)       # require human review?
    created_at = Column(DateTime, default=datetime.utcnow)

    provider = relationship("Provider", back_populates="aliases")
    __table_args__ = (
        UniqueConstraint("provider_id", "normalized", name="uq_alias_per_provider"),
        Index("ix_alias_normalized", "normalized"),
    )

class ProviderNote(Base):
    __tablename__ = "provider_notes"
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), nullable=False, index=True)
    note = Column(Text, nullable=False)             # freeform facts (e.g., “No testosterone teaching on SCM schedule”)
    source = Column(String(256), nullable=True)     # originating doc path or URL
    created_at = Column(DateTime, default=datetime.utcnow)

    provider = relationship("Provider", back_populates="notes")

class AmbiguityRule(Base):
    __tablename__ = "ambiguity_rules"
    id = Column(Integer, primary_key=True)
    trigger = Column(String(128), nullable=False, index=True)   # e.g., "dr. henslee", "henslee"
    prompt = Column(String(256), nullable=False)                # ask-user text
    # comma-separated provider ABBRs to choose between (simple & fast)
    abbrs_csv = Column(String(256), nullable=False)             # e.g., "DLH,BLH"

def init_db():
    Base.metadata.create_all(engine)