from sqlmodel import Session, func, select

from app.models import Asset, Company, Finding
from app.services import collector
from app.services.cve_repository import get_cve, upsert_cve


def _company_with_fortios(db_engine) -> int:
    with Session(db_engine) as session:
        company = Company(name="Thales", country="France")
        session.add(company)
        session.flush()
        session.add(
            Asset(company_id=company.id, asset_type="technology", value="FortiOS")
        )
        session.commit()
        return company.id


def test_collector_prefers_local_scoring_and_deduplicates(db_engine, monkeypatch):
    company_id = _company_with_fortios(db_engine)
    with Session(db_engine) as session:
        upsert_cve(
            session,
            {
                "cve_id": "CVE-2026-5000",
                "published_at": "2026-08-01T00:00:00Z",
                "last_modified_at": "2026-08-02T00:00:00Z",
                "cvss": 9.8,
                "epss": 0.8,
                "epss_percentile": 0.99,
                "kev": True,
                "source": "NVD",
            },
            [("fortinet", "fortios")],
        )
        session.commit()

    monkeypatch.setattr(collector, "engine", db_engine)
    monkeypatch.setattr(
        collector,
        "search_cves_by_keyword",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("NVD appele")),
    )
    first_ids = collector.collect_for_company(company_id)
    second_ids = collector.collect_for_company(company_id)

    assert len(first_ids) == 1
    assert second_ids == []
    with Session(db_engine) as session:
        findings = session.exec(
            select(Finding).where(Finding.company_id == company_id)
        ).all()
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2026-5000"
        assert findings[0].score == 100


def test_collector_fallback_enriches_repository(db_engine, monkeypatch):
    company_id = _company_with_fortios(db_engine)
    monkeypatch.setattr(collector, "engine", db_engine)
    monkeypatch.setattr(collector, "fetch_kev_index", lambda: {"CVE-2026-6000": {}})
    monkeypatch.setattr(
        collector,
        "get_epss_data",
        lambda cve_id: {"epss": 0.4, "epss_percentile": 0.8},
    )
    monkeypatch.setattr(
        collector,
        "search_cves_by_keyword",
        lambda *args, **kwargs: [
            {
                "cve_id": "CVE-2026-6000",
                "published": "2026-08-01T00:00:00Z",
                "last_modified": "2026-08-02T00:00:00Z",
                "description": "Fallback result",
                "cvss": 8.0,
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-6000",
                "products": [("fortinet", "fortios")],
            }
        ],
    )

    assert len(collector.collect_for_company(company_id)) == 1
    with Session(db_engine) as session:
        cve = get_cve(session, "CVE-2026-6000")
        assert cve.cvss == 8.0
        assert cve.epss == 0.4
        assert cve.kev is True
        assert session.exec(select(func.count()).select_from(Finding)).one() == 1
