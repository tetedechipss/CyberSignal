from datetime import datetime, timezone

from sqlmodel import Session

from app.services.cve_repository import count_cves, search_cve_page, search_cves, upsert_cve


def _add_cve(
    session: Session,
    cve_id: str,
    published_at: str,
    *,
    vendor: str,
    product: str,
    cvss: float | None,
    epss: float | None,
    kev: bool = False,
) -> None:
    upsert_cve(
        session,
        {
            "cve_id": cve_id,
            "published_at": published_at,
            "last_modified_at": published_at,
            "cvss": cvss,
            "epss": epss,
            "epss_percentile": epss,
            "kev": kev,
            "source": "NVD",
        },
        [(vendor, product)],
    )


def _seed_browse_data(db_engine) -> None:
    with Session(db_engine) as session:
        _add_cve(
            session,
            "CVE-2026-8101",
            "2026-08-15T10:00:00Z",
            vendor="Microsoft",
            product="Windows_11",
            cvss=7.0,
            epss=0.2,
            kev=True,
        )
        _add_cve(
            session,
            "CVE-2026-8102",
            "2026-08-14T10:00:00Z",
            vendor="Fortinet",
            product="FortiOS",
            cvss=9.8,
            epss=0.8,
        )
        _add_cve(
            session,
            "CVE-2026-8103",
            "2026-08-13T10:00:00Z",
            vendor="Fortinet",
            product="FortiGate",
            cvss=None,
            epss=None,
            kev=True,
        )
        _add_cve(
            session,
            "CVE-2026-8104",
            "2026-08-12T10:00:00Z",
            vendor="Citrix",
            product="NetScaler",
            cvss=8.5,
            epss=0.5,
        )
        _add_cve(
            session,
            "CVE-2026-8105",
            "2026-08-11T10:00:00Z",
            vendor="Fortinet",
            product="FortiOS",
            cvss=6.0,
            epss=0.95,
            kev=True,
        )
        session.commit()


def test_default_today_and_yesterday_period(db_engine):
    _seed_browse_data(db_engine)
    with Session(db_engine) as session:
        rows = search_cves(
            session,
            date_from=datetime(2026, 8, 14, tzinfo=timezone.utc),
            date_to=datetime(2026, 8, 15, 23, 59, 59, tzinfo=timezone.utc),
            limit=100,
        )
    assert [row.cve_id for row in rows] == ["CVE-2026-8101", "CVE-2026-8102"]


def test_custom_dates_vendor_product_and_case_insensitive_search(db_engine):
    _seed_browse_data(db_engine)
    with Session(db_engine) as session:
        assert count_cves(
            session,
            date_from="2026-08-12T00:00:00Z",
            date_to="2026-08-14T23:59:59Z",
        ) == 3
        assert count_cves(session, technology="fOrTiNeT") == 3
        assert count_cves(session, technology="FoRtIoS") == 2
        assert count_cves(session, technology="windows") == 1


def test_sql_sorts_put_missing_scores_last(db_engine):
    _seed_browse_data(db_engine)
    with Session(db_engine) as session:
        recent = search_cves(session, limit=100, sort_by="published_at")
        critical = search_cves(session, limit=100, sort_by="cvss")
        epss = search_cves(session, limit=100, sort_by="epss")

    assert [row.cve_id for row in recent] == [
        "CVE-2026-8101",
        "CVE-2026-8102",
        "CVE-2026-8103",
        "CVE-2026-8104",
        "CVE-2026-8105",
    ]
    assert critical[0].cve_id == "CVE-2026-8102"
    assert critical[-1].cve_id == "CVE-2026-8103"
    assert epss[0].cve_id == "CVE-2026-8105"
    assert epss[-1].cve_id == "CVE-2026-8103"


def test_combined_filters_and_kev_only(db_engine):
    _seed_browse_data(db_engine)
    with Session(db_engine) as session:
        assert count_cves(session, technology="fortinet", kev_only=False) == 3
        rows = search_cves(
            session,
            technology="fortinet",
            date_from="2026-08-10T00:00:00Z",
            date_to="2026-08-13T23:59:59Z",
            kev_only=True,
            sort_by="epss",
            limit=100,
        )
    assert [row.cve_id for row in rows] == ["CVE-2026-8105", "CVE-2026-8103"]


def test_pagination_keeps_total_and_applies_limit_offset(db_engine):
    _seed_browse_data(db_engine)
    with Session(db_engine) as session:
        first = search_cve_page(session, limit=2, offset=0)
        second = search_cve_page(session, limit=2, offset=2)
        third = search_cve_page(session, limit=2, offset=4)

    assert first["total"] == second["total"] == third["total"] == 5
    all_ids = [
        item["cve"].cve_id
        for page in (first, second, third)
        for item in page["items"]
    ]
    assert all_ids == [
        "CVE-2026-8101",
        "CVE-2026-8102",
        "CVE-2026-8103",
        "CVE-2026-8104",
        "CVE-2026-8105",
    ]
