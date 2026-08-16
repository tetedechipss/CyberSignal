from datetime import datetime, timezone

from sqlmodel import Session, select

from app.models import CVEProduct
from app.providers.nvd import parse_nvd_vulnerability
from app.services.cve_repository import get_cve, search_cves, upsert_cve


def _record(cve_id: str, published: str, cvss: float = 7.0) -> dict:
    return {
        "cve_id": cve_id,
        "published_at": published,
        "last_modified_at": published,
        "cvss": cvss,
        "source": "NVD",
    }


def test_upsert_products_search_filter_and_sort(db_engine):
    with Session(db_engine) as session:
        upsert_cve(
            session,
            _record("CVE-2026-0001", "2026-01-01T00:00:00Z"),
            [("Fortinet", "FortiOS"), ("Fortinet", "FortiProxy")],
        )
        upsert_cve(
            session,
            _record("CVE-2026-0002", "2026-06-01T00:00:00Z"),
            [("Fortinet", "FortiOS")],
        )
        session.commit()

        upsert_cve(
            session,
            _record("CVE-2026-0001", "2026-01-01T00:00:00Z", cvss=9.8),
            [("Fortinet", "FortiOS"), ("Fortinet", "FortiProxy")],
        )
        session.commit()

        assert get_cve(session, "cve-2026-0001").cvss == 9.8
        products = session.exec(
            select(CVEProduct).where(CVEProduct.cve_id == "CVE-2026-0001")
        ).all()
        assert {(item.vendor, item.product) for item in products} == {
            ("fortinet", "fortios"),
            ("fortinet", "fortiproxy"),
        }
        assert [item.cve_id for item in search_cves(session, vendor="Fortinet")] == [
            "CVE-2026-0002",
            "CVE-2026-0001",
        ]
        assert [
            item.cve_id
            for item in search_cves(
                session,
                products=["fortios"],
                published_since=datetime(2026, 3, 1, tzinfo=timezone.utc),
            )
        ] == ["CVE-2026-0002"]


def test_nvd_parser_keeps_only_vulnerable_cpes():
    parsed = parse_nvd_vulnerability(
        {
            "cve": {
                "id": "CVE-2026-9999",
                "published": "2026-08-01T00:00:00Z",
                "lastModified": "2026-08-02T00:00:00Z",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:fortinet:fortios:*:*:*:*:*:*:*:*",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    )
    assert parsed["record"]["cvss"] == 8.8
    assert parsed["products"] == [("fortinet", "fortios")]
