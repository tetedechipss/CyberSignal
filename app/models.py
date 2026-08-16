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


class CVE(SQLModel, table=True):
    __tablename__ = "cves"

    cve_id: str = Field(primary_key=True)
    published_at: Optional[str] = Field(default=None, index=True)
    last_modified_at: Optional[str] = Field(default=None, index=True)
    cvss: Optional[float] = None
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = Field(default=False)
    source: str = Field(default="NVD")
    created_at: str = Field(default_factory=utcnow)
    updated_at: str = Field(default_factory=utcnow)


class CVEProduct(SQLModel, table=True):
    __tablename__ = "cve_products"

    cve_id: str = Field(foreign_key="cves.cve_id", primary_key=True)
    vendor: str = Field(primary_key=True, index=True)
    product: str = Field(primary_key=True, index=True)


class CVESyncState(SQLModel, table=True):
    __tablename__ = "cve_sync_state"

    name: str = Field(primary_key=True)
    status: str = Field(default="idle")
    cursor_at: Optional[str] = None
    last_successful_at: Optional[str] = None
    last_error: Optional[str] = None
    updated_at: str = Field(default_factory=utcnow)


class CompanyIgnoredCVE(SQLModel, table=True):
    __tablename__ = "company_ignored_cves"

    company_id: int = Field(foreign_key="company.id", primary_key=True)
    cve_id: str = Field(foreign_key="cves.cve_id", primary_key=True)
    created_at: str = Field(default_factory=utcnow)
