from datetime import datetime, timezone

from streamlit.testing.v1 import AppTest
from sqlmodel import Session, select

from app import database, report
from app.models import Asset, CVE, Company, Finding
from app.services import collector, trends
from app.services.cve_repository import upsert_cve


def test_streamlit_company_and_trends_views_render(monkeypatch, db_engine):
    now = datetime.now(timezone.utc)
    with Session(db_engine) as session:
        company = Company(name="Thales", country="France")
        session.add(company)
        session.flush()
        session.add(
            Asset(company_id=company.id, asset_type="technology", value="Fortinet")
        )
        upsert_cve(
            session,
            {
                "cve_id": "CVE-2026-59841",
                "published_at": now,
                "last_modified_at": now,
                "cvss": 9.8,
                "epss": 0.72,
                "epss_percentile": 0.97,
                "kev": True,
                "source": "NVD",
            },
            [("fortinet", "fortios")],
        )
        session.add(
            Finding(
                company_id=company.id,
                source="NVD/CISA/EPSS",
                finding_type="vulnerability",
                title="Legacy title",
                description="",
                severity="medium",
                score=30,
                confidence=80,
                related_asset="Fortinet",
                cve_id="CVE-2026-59841",
            )
        )
        session.add(Company(name="Airbus", country="France"))
        session.commit()

    monkeypatch.setattr(database, "engine", db_engine)
    monkeypatch.setattr(collector, "engine", db_engine)
    monkeypatch.setattr(report, "engine", db_engine)
    monkeypatch.setattr(
        trends,
        "collect_vulnerability_trend_events",
        lambda max_feeds=25: {
            "collected_at": now,
            "article_count": 1,
            "term_count": 1,
            "source_count": 1,
            "events": [
                {
                    "term": "Fortinet",
                    "count": 2,
                    "article_key": "test-article",
                    "title": "Test vulnerability article",
                    "url": "https://example.com/article",
                    "source": "example.com",
                    "country": "France",
                    "country_code": "FR",
                    "confident": 1,
                    "source_weight": 1.0,
                    "published_at": now,
                    "published": now.isoformat(),
                }
            ],
        },
    )

    app = AppTest.from_file("ui/streamlit_app.py")
    app.run(timeout=30)

    assert not app.exception
    assert [tab.label for tab in app.tabs] == [
        "Recherche CVE",
        "Suivi entreprise",
        "Tendances vulnérabilités",
    ]
    assert [item.value for item in app.tabs[0].subheader] == ["CVE recentes"]
    assert "CVE recentes" not in [item.value for item in app.tabs[1].subheader]
    assert not app.tabs[0].expander
    assert [expander.label for expander in app.tabs[1].expander][0] == (
        "Creer une entreprise"
    )
    assert not app.tabs[2].expander
    assert not app.sidebar.header
    assert any(item.value == "CVE recentes" for item in app.subheader)
    assert any(item.value == "Resume des tendances" for item in app.subheader)
    expected_finding_columns = [
        "Technology",
        "CVE",
        "Date publication",
        "Vendor",
        "Product",
        "CVSS",
        "EPSS",
        "EPSS percentile",
        "KEV",
    ]
    assert any(
        list(dataframe.value.columns) == expected_finding_columns
        for dataframe in app.dataframe
    )
    assert all(
        "Sélection" not in dataframe.value.columns
        for dataframe in app.tabs[1].dataframe
    )
    assert app.button(key="edit_assets_1")
    assert app.button(key="edit_findings_1")

    app.text_input(key="company_create_name").set_value("Safran")
    app.button(key="create_company").click().run(timeout=30)
    assert not app.exception
    with Session(db_engine) as session:
        assert session.exec(select(Company).where(Company.name == "Safran")).first()

    app.button(key="edit_assets_1").click().run(timeout=30)
    assert not app.exception
    assert any(
        {"Sélection", "type", "value"}.issubset(dataframe.value.columns)
        for dataframe in app.tabs[1].dataframe
    )
    assert app.button(key="request_asset_selection_delete_1")
    assert app.button(key="cancel_asset_editing_1")

    app.button(key="edit_findings_1").click().run(timeout=30)
    assert not app.exception
    assert any(
        [
            "Sélection",
            "Technology",
            "CVE",
            "Date publication",
            "Vendor",
            "Product",
            "CVSS",
            "EPSS",
            "EPSS percentile",
            "KEV",
        ]
        == [column for column in dataframe.value.columns if not column.startswith("_")]
        for dataframe in app.tabs[1].dataframe
    )
    assert app.button(key="cancel_asset_editing_1")
    assert app.button(key="cancel_finding_editing_1")

    app.button(key="cancel_asset_editing_1").click().run(timeout=30)
    assert not app.exception
    assert app.button(key="edit_assets_1")
    assert app.button(key="cancel_finding_editing_1")

    app.button(key="cancel_finding_editing_1").click().run(timeout=30)
    assert not app.exception
    assert all(
        "Sélection" not in dataframe.value.columns
        for dataframe in app.tabs[1].dataframe
    )

    app.button(key="edit_assets_1").click().run(timeout=30)
    app.selectbox(key="selected_company").select("2 - Airbus").run(timeout=30)
    assert not app.exception
    assert app.button(key="request_company_delete_2")
    app.selectbox(key="selected_company").select("1 - Thales").run(timeout=30)
    assert not app.exception
    assert app.button(key="edit_assets_1")

    app.button(key="request_company_delete_1").click().run(timeout=30)
    assert not app.exception
    with Session(db_engine) as session:
        assert session.get(Company, 1) is not None
    app.button(key="confirm_company_delete_1").click().run(timeout=30)
    assert not app.exception
    with Session(db_engine) as session:
        assert session.get(Company, 1) is None
        assert session.get(Company, 2) is not None
        assert session.get(CVE, "CVE-2026-59841") is not None
