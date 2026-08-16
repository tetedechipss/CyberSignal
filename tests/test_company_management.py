import pytest
from sqlmodel import Session, func, select

from app.models import (
    Asset,
    Company,
    CompanyIgnoredCVE,
    CVE,
    CVEProduct,
    Finding,
    Report,
)
from app.services import collector
from app.services.company_management import (
    delete_company,
    delete_company_technologies,
    delete_company_technology,
    ignore_company_cve,
    ignore_company_cves,
    restore_company_cve,
)
from app.services.cve_repository import get_company_cve_findings, upsert_cve


def _finding(company_id: int, cve_id: str, technology: str) -> Finding:
    return Finding(
        company_id=company_id,
        source="NVD/CISA/EPSS",
        finding_type="vulnerability",
        title=f"{cve_id} liee a {technology}",
        description="",
        severity="high",
        score=80,
        confidence=80,
        related_asset=technology,
        cve_id=cve_id,
    )


def test_delete_technology_is_scoped_to_its_company_and_preserves_cves(db_engine):
    with Session(db_engine) as session:
        company = Company(name="Thales")
        other_company = Company(name="Autre")
        session.add(company)
        session.add(other_company)
        session.flush()
        fortinet = Asset(
            company_id=company.id,
            asset_type="technology",
            value="Fortinet",
        )
        session.add(fortinet)
        session.add(
            Asset(company_id=company.id, asset_type="technology", value="Microsoft")
        )
        session.flush()
        upsert_cve(session, {"cve_id": "CVE-2026-1001"}, [("fortinet", "fortios")])
        upsert_cve(session, {"cve_id": "CVE-2026-1002"}, [("microsoft", "windows")])
        session.add(_finding(company.id, "CVE-2026-1001", "Fortinet"))
        session.add(_finding(company.id, "CVE-2026-1002", "Microsoft"))
        session.add(_finding(other_company.id, "CVE-2026-1001", "Fortinet"))
        session.commit()
        company_id = company.id
        other_company_id = other_company.id
        fortinet_id = fortinet.id

    result = delete_company_technology(
        company_id,
        fortinet_id,
        db_engine=db_engine,
    )

    assert result == {"technology": "Fortinet", "deleted_findings": 1}
    with Session(db_engine) as session:
        assets = session.exec(
            select(Asset).where(Asset.company_id == company_id)
        ).all()
        findings = session.exec(
            select(Finding).where(Finding.company_id == company_id)
        ).all()
        other_findings = session.exec(
            select(Finding).where(Finding.company_id == other_company_id)
        ).all()
        assert [asset.value for asset in assets] == ["Microsoft"]
        assert [finding.cve_id for finding in findings] == ["CVE-2026-1002"]
        assert [finding.cve_id for finding in other_findings] == ["CVE-2026-1001"]
        assert session.exec(select(func.count()).select_from(CVE)).one() == 2


def test_delete_multiple_technologies_is_atomic_and_keeps_unselected_asset(db_engine):
    with Session(db_engine) as session:
        company = Company(name="Thales")
        session.add(company)
        session.flush()
        assets = [
            Asset(company_id=company.id, asset_type="technology", value=value)
            for value in ["Fortinet", "WordPress", "Microsoft"]
        ]
        session.add_all(assets)
        session.flush()
        for index, technology in enumerate(
            ["Fortinet", "WordPress", "Microsoft"],
            start=1,
        ):
            cve_id = f"CVE-2026-11{index:02d}"
            upsert_cve(session, {"cve_id": cve_id})
            session.add(_finding(company.id, cve_id, technology))
        session.commit()
        company_id = company.id
        selected_ids = [assets[0].id, assets[2].id]

    result = delete_company_technologies(
        company_id,
        selected_ids,
        db_engine=db_engine,
    )

    assert result["technologies"] == ["Fortinet", "Microsoft"]
    assert result["deleted_assets"] == 2
    assert result["deleted_findings"] == 2
    with Session(db_engine) as session:
        assert [
            asset.value
            for asset in session.exec(
                select(Asset).where(Asset.company_id == company_id)
            ).all()
        ] == ["WordPress"]
        assert [
            finding.related_asset
            for finding in session.exec(
                select(Finding).where(Finding.company_id == company_id)
            ).all()
        ] == ["WordPress"]
        assert session.exec(select(func.count()).select_from(CVE)).one() == 3


def test_bulk_asset_delete_rejects_cross_company_selection_atomically(db_engine):
    with Session(db_engine) as session:
        company_a = Company(name="A")
        company_b = Company(name="B")
        session.add_all([company_a, company_b])
        session.flush()
        asset_a = Asset(
            company_id=company_a.id,
            asset_type="technology",
            value="Fortinet",
        )
        asset_b = Asset(
            company_id=company_b.id,
            asset_type="technology",
            value="Microsoft",
        )
        session.add_all([asset_a, asset_b])
        session.commit()
        company_a_id = company_a.id
        asset_ids = [asset_a.id, asset_b.id]

    with pytest.raises(ValueError, match="introuvable"):
        delete_company_technologies(
            company_a_id,
            asset_ids,
            db_engine=db_engine,
        )

    with Session(db_engine) as session:
        assert session.exec(select(func.count()).select_from(Asset)).one() == 2


def test_delete_company_removes_dependencies_but_preserves_repository(
    db_engine,
    tmp_path,
):
    reports_root = tmp_path / "reports"
    reports_root.mkdir()
    report_path = reports_root / "thales.md"
    report_path.write_text("rapport", encoding="utf-8")

    with Session(db_engine) as session:
        company = Company(name="Thales")
        session.add(company)
        session.flush()
        session.add(
            Asset(company_id=company.id, asset_type="technology", value="Fortinet")
        )
        upsert_cve(session, {"cve_id": "CVE-2026-2001"}, [("fortinet", "fortios")])
        session.add(_finding(company.id, "CVE-2026-2001", "Fortinet"))
        session.add(CompanyIgnoredCVE(company_id=company.id, cve_id="CVE-2026-2001"))
        session.add(Report(company_id=company.id, file_path=str(report_path)))
        session.commit()
        company_id = company.id

    result = delete_company(
        company_id,
        db_engine=db_engine,
        reports_root=reports_root,
    )

    assert result == {
        "ignored_cves": 1,
        "findings": 1,
        "assets": 1,
        "reports": 1,
        "report_files": 1,
    }
    assert not report_path.exists()
    with Session(db_engine) as session:
        assert session.get(Company, company_id) is None
        assert session.exec(select(func.count()).select_from(Asset)).one() == 0
        assert session.exec(select(func.count()).select_from(Finding)).one() == 0
        assert session.exec(select(func.count()).select_from(Report)).one() == 0
        assert session.exec(
            select(func.count()).select_from(CompanyIgnoredCVE)
        ).one() == 0
        assert session.get(CVE, "CVE-2026-2001") is not None
        assert session.exec(select(func.count()).select_from(CVEProduct)).one() == 1


def test_ignored_cve_stays_hidden_after_collection_and_can_be_restored(
    db_engine,
    monkeypatch,
):
    with Session(db_engine) as session:
        company = Company(name="Thales")
        session.add(company)
        session.flush()
        session.add(
            Asset(company_id=company.id, asset_type="technology", value="FortiOS")
        )
        upsert_cve(
            session,
            {
                "cve_id": "CVE-2026-3001",
                "published_at": "2026-08-01T00:00:00Z",
                "cvss": 9.8,
                "source": "NVD",
            },
            [("fortinet", "fortios")],
        )
        session.commit()
        company_id = company.id

    monkeypatch.setattr(collector, "engine", db_engine)
    assert len(collector.collect_for_company(company_id)) == 1
    assert ignore_company_cve(
        company_id,
        "cve-2026-3001",
        db_engine=db_engine,
    )
    assert not ignore_company_cve(
        company_id,
        "CVE-2026-3001",
        db_engine=db_engine,
    )

    assert collector.collect_for_company(company_id) == []
    with Session(db_engine) as session:
        assert get_company_cve_findings(session, company_id) == []
        ignored = get_company_cve_findings(
            session,
            company_id,
            ignored_only=True,
        )
        assert [record["finding"].cve_id for record in ignored] == ["CVE-2026-3001"]
        assert session.exec(select(func.count()).select_from(Finding)).one() == 1
        assert session.get(CVE, "CVE-2026-3001") is not None

    assert restore_company_cve(
        company_id,
        "cve-2026-3001",
        db_engine=db_engine,
    )
    with Session(db_engine) as session:
        restored = get_company_cve_findings(session, company_id)
        assert [record["finding"].cve_id for record in restored] == ["CVE-2026-3001"]


def test_ignore_multiple_cves_is_atomic_and_preserves_global_cves(db_engine):
    with Session(db_engine) as session:
        company = Company(name="Thales")
        session.add(company)
        session.flush()
        cve_ids = ["CVE-2026-4001", "CVE-2026-4002", "CVE-2026-4003"]
        for cve_id in cve_ids:
            upsert_cve(session, {"cve_id": cve_id})
            session.add(_finding(company.id, cve_id, "Fortinet"))
        session.commit()
        company_id = company.id

    result = ignore_company_cves(
        company_id,
        ["cve-2026-4001", "CVE-2026-4003", "CVE-2026-4001"],
        db_engine=db_engine,
    )

    assert result == {
        "cve_ids": ["CVE-2026-4001", "CVE-2026-4003"],
        "created": 2,
        "already_ignored": 0,
    }
    with Session(db_engine) as session:
        visible = get_company_cve_findings(session, company_id)
        ignored = get_company_cve_findings(session, company_id, ignored_only=True)
        assert [record["finding"].cve_id for record in visible] == ["CVE-2026-4002"]
        assert {record["finding"].cve_id for record in ignored} == {
            "CVE-2026-4001",
            "CVE-2026-4003",
        }
        assert session.exec(select(func.count()).select_from(CVE)).one() == 3


def test_bulk_ignore_rejects_cross_company_selection_atomically(db_engine):
    with Session(db_engine) as session:
        company_a = Company(name="A")
        company_b = Company(name="B")
        session.add_all([company_a, company_b])
        session.flush()
        upsert_cve(session, {"cve_id": "CVE-2026-5001"})
        upsert_cve(session, {"cve_id": "CVE-2026-5002"})
        session.add(_finding(company_a.id, "CVE-2026-5001", "Fortinet"))
        session.add(_finding(company_b.id, "CVE-2026-5002", "Microsoft"))
        session.commit()
        company_b_id = company_b.id

    with pytest.raises(ValueError, match="n'appartient pas"):
        ignore_company_cves(
            company_b_id,
            ["CVE-2026-5001", "CVE-2026-5002"],
            db_engine=db_engine,
        )

    with Session(db_engine) as session:
        assert session.exec(
            select(func.count()).select_from(CompanyIgnoredCVE)
        ).one() == 0
