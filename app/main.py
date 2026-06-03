from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from app.database import init_db, engine
from app.models import Company, Asset, Finding
from app.services.collector import collect_for_company
from app.report import generate_company_report

app = FastAPI(title="CyberSignal")


class CompanyCreate(BaseModel):
    name: str
    sector: str | None = None
    country: str | None = None


class AssetCreate(BaseModel):
    company_id: int
    asset_type: str
    value: str


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "app": "CyberSignal"}


@app.post("/companies")
def create_company(payload: CompanyCreate):
    with Session(engine) as session:
        company = Company(
            name=payload.name,
            sector=payload.sector,
            country=payload.country,
        )

        session.add(company)
        session.commit()
        session.refresh(company)

        return company


@app.get("/companies")
def list_companies():
    with Session(engine) as session:
        return session.exec(select(Company)).all()


@app.post("/assets")
def create_asset(payload: AssetCreate):
    with Session(engine) as session:
        company = session.get(Company, payload.company_id)

        if not company:
            raise HTTPException(status_code=404, detail="Company introuvable")

        asset = Asset(
            company_id=payload.company_id,
            asset_type=payload.asset_type,
            value=payload.value,
        )

        session.add(asset)
        session.commit()
        session.refresh(asset)

        return asset


@app.post("/companies/{company_id}/collect")
def collect(company_id: int):
    finding_ids = collect_for_company(company_id)
    return {"created_findings": finding_ids}


@app.get("/companies/{company_id}/findings")
def get_findings(company_id: int):
    with Session(engine) as session:
        return session.exec(
            select(Finding)
            .where(Finding.company_id == company_id)
            .order_by(Finding.score.desc())
        ).all()


@app.post("/companies/{company_id}/report")
def report(company_id: int):
    path = generate_company_report(company_id)
    return {"report_path": path}