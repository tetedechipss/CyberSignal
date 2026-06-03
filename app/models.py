from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Company(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    sector: Optional[str] = None
    country: Optional[str] = None
    created_at: str = Field(default_factory=utcnow)


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    company_id: int = Field(index=True)
    asset_type: str
    value: str
    created_at: str = Field(default_factory=utcnow)


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    company_id: int = Field(index=True)
    source: str
    finding_type: str
    title: str
    description: str
    severity: str
    score: int
    confidence: int
    related_asset: Optional[str] = None
    cve_id: Optional[str] = None
    url: Optional[str] = None
    raw_data: Optional[str] = None
    created_at: str = Field(default_factory=utcnow)


class Report(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    company_id: int = Field(index=True)
    summary: Optional[str] = None
    file_path: str
    created_at: str = Field(default_factory=utcnow)