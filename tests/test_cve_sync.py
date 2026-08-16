from datetime import datetime, timedelta, timezone

import pytest
from sqlmodel import Session

from app.services import cve_sync
from app.services.cve_repository import get_cve, get_sync_state


def _item(cve_id: str, cvss: float = 7.5) -> dict:
    return {
        "record": {
            "cve_id": cve_id,
            "published_at": "2026-07-02T00:00:00Z",
            "last_modified_at": "2026-07-03T00:00:00Z",
            "cvss": cvss,
            "source": "NVD",
        },
        "products": [("fortinet", "fortios")],
    }


def test_initial_import_replays_failed_window_without_duplicates(db_engine, monkeypatch):
    calls = {"count": 0}

    def failing_pages(*args, **kwargs):
        calls["count"] += 1
        yield [_item("CVE-2026-1000")]
        if calls["count"] == 1:
            raise RuntimeError("temporary NVD error")

    monkeypatch.setattr(cve_sync, "iter_cve_pages", failing_pages)
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    end = start + timedelta(days=2)
    with pytest.raises(RuntimeError):
        cve_sync.run_initial_import(
            since=start,
            end_at=end,
            db_engine=db_engine,
            progress=lambda _: None,
        )

    result = cve_sync.run_initial_import(
        since=start,
        end_at=end,
        db_engine=db_engine,
        progress=lambda _: None,
    )
    assert result["imported"] == 1
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-1000") is not None
        assert get_sync_state(session, cve_sync.INITIAL_IMPORT).status == "success"


def test_incremental_upserts_modified_cve(db_engine, monkeypatch):
    monkeypatch.setattr(
        cve_sync,
        "iter_cve_pages",
        lambda *args, **kwargs: iter([[_item("CVE-2026-2000", cvss=9.4)]]),
    )
    cve_sync.run_nvd_incremental(
        end_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        db_engine=db_engine,
        progress=lambda _: None,
    )
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-2000").cvss == 9.4
        state = get_sync_state(session, cve_sync.NVD_INCREMENTAL)
        assert state.status == "success"
        assert state.last_successful_at is not None


def test_epss_add_update_percentile_and_missing(db_engine, monkeypatch):
    monkeypatch.setattr(
        cve_sync,
        "iter_cve_pages",
        lambda *args, **kwargs: iter([[_item("CVE-2026-3000"), _item("CVE-2026-3001")]]),
    )
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    cve_sync.run_initial_import(
        since=start,
        end_at=start + timedelta(days=1),
        db_engine=db_engine,
        progress=lambda _: None,
    )
    monkeypatch.setattr(
        cve_sync,
        "iter_current_epss_scores",
        lambda: iter(
            [
                {"cve_id": "CVE-2026-3000", "epss": 0.2, "epss_percentile": 0.7},
                {"cve_id": "CVE-NOT-LOCAL", "epss": 0.9, "epss_percentile": 0.99},
            ]
        ),
    )
    cve_sync.run_epss_sync(db_engine=db_engine, progress=lambda _: None)
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-3000").epss == 0.2
        assert get_cve(session, "CVE-2026-3000").epss_percentile == 0.7
        assert get_cve(session, "CVE-2026-3001").epss is None

    monkeypatch.setattr(
        cve_sync,
        "iter_current_epss_scores",
        lambda: iter(
            [{"cve_id": "CVE-2026-3000", "epss": 0.8, "epss_percentile": 0.95}]
        ),
    )
    cve_sync.run_epss_sync(db_engine=db_engine, progress=lambda _: None)
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-3000").epss == 0.8


def test_kev_false_to_true_and_catalog_reset(db_engine, monkeypatch):
    monkeypatch.setattr(
        cve_sync,
        "iter_cve_pages",
        lambda *args, **kwargs: iter([[_item("CVE-2026-4000"), _item("CVE-2026-4001")]]),
    )
    start = datetime(2026, 7, 1, tzinfo=timezone.utc)
    cve_sync.run_initial_import(
        since=start,
        end_at=start + timedelta(days=1),
        db_engine=db_engine,
        progress=lambda _: None,
    )
    monkeypatch.setattr(
        cve_sync,
        "fetch_kev_index",
        lambda **kwargs: {"CVE-2026-4000": {}},
    )
    cve_sync.run_kev_sync(db_engine=db_engine, progress=lambda _: None)
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-4000").kev is True
        assert get_cve(session, "CVE-2026-4001").kev is False

    monkeypatch.setattr(
        cve_sync,
        "fetch_kev_index",
        lambda **kwargs: {"CVE-2026-4001": {}},
    )
    cve_sync.run_kev_sync(db_engine=db_engine, progress=lambda _: None)
    with Session(db_engine) as session:
        assert get_cve(session, "CVE-2026-4000").kev is False
        assert get_cve(session, "CVE-2026-4001").kev is True
