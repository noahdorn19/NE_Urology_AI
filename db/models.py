from datetime import datetime
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.dialects.sqlite import JSON

# Database paths (SQLite files in project root)
ENGINE_URL = "sqlite:///ai_ref.db"
PROVIDERS_ENGINE_URL = "sqlite:///providers.db"

# Separate bases: one for AI ref DB, one for providers DB
Base = declarative_base()
ProvidersBase = declarative_base()

# ---------- Providers DB (providers.db) ----------
class Provider(ProvidersBase):
    __tablename__ = "providers"
    id = Column(Integer, primary_key=True)
    abbr = Column(String(16), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    role = Column(String(64), nullable=False, default="MD")
    department = Column(String(64), nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class ProviderAlias(ProvidersBase):
    __tablename__ = "provider_aliases"
    id = Column(Integer, primary_key=True)
    provider_id = Column(Integer, ForeignKey("providers.id", ondelete="CASCADE"), index=True, nullable=False)
    alias = Column(String(128), nullable=False, unique=True)
    normalized = Column(String(128), nullable=False, index=True)
    confidence = Column(Integer, default=1)
    source = Column(String(256), nullable=True)
    pending_review = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------- AI Reference DB (ai_ref.db) ----------
class ProviderPref(Base):
    __tablename__ = "provider_prefs"
    id = Column(Integer, primary_key=True)
    provider_abbr = Column(String(16), index=True, nullable=False)
    children_policy = Column(String(128))
    special_requests = Column(Text)
    on_call_routing = Column(Text)
    non_call_routing = Column(Text)
    pm_out = Column(String(256))
    direct_phone = Column(String(64))
    er_dr_hospital_rules = Column(Text)
    provider_call_rules = Column(Text)
    allows_vasectomy = Column(Boolean)
    sees_new_kids = Column(Boolean)
    sees_pessary = Column(Boolean)
    last_source = Column(String(512))
    imported_at = Column(DateTime, default=datetime.utcnow)

class SchedulingRule(Base):
    __tablename__ = "scheduling_rules"
    id = Column(Integer, primary_key=True)
    rule_id = Column(String(128), unique=True, nullable=False, index=True)
    topic = Column(String(128), nullable=False, index=True)
    description = Column(Text)
    allowed_roles = Column(JSON)
    allowed_providers = Column(JSON)
    disallowed_providers = Column(JSON)
    disallowed_roles = Column(JSON)
    conditions = Column(JSON)
    enforce = Column(Boolean, default=True, nullable=False)
    status = Column(String(32), default="ready", nullable=False)
    source = Column(String(256), default="Scheduling Decision Tree.xlsx")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    source = Column(String(256), nullable=False)
    path = Column(String(512))
    meta_json = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

# Engines and sessions
engine = create_engine(ENGINE_URL, future=True)
providers_engine = create_engine(PROVIDERS_ENGINE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
ProvidersSession = sessionmaker(bind=providers_engine, autoflush=False, autocommit=False, future=True)

def init_all():
    """Initialize both databases and create all tables."""
    Base.metadata.create_all(engine)
    ProvidersBase.metadata.create_all(providers_engine)