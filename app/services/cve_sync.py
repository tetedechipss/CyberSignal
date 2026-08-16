from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from sqlalchemy import update
from sqlmodel import Session

from app.database import engine as default_engine
from app.models import CVE
from app.providers.cisa_kev import fetch_kev_index
from app.providers.epss import iter_current_epss_scores
from app.providers.nvd import iter_cve_pages
from app.services.cve_repository import (
    count_cve_products,
    count_cves,
    get_sync_state,
    normalize_datetime,
    update_sync_state,
    upsert_cve,
)

INITIAL_IMPORT = "initial_import"
INITIAL_IMPORT_SCOPE = "initial_import_scope"
NVD_INCREMENTAL = "nvd_incremental"
EPSS_SYNC = "epss"
KEV_SYNC = "kev"
ALL_HISTORY_START = datetime(1999, 1, 1, tzinfo=timezone.utc)
NVD_WINDOW = timedelta(days=119)
NVD_OVERLAP = timedelta(minutes=5)
EPSS_BATCH_SIZE = 2_000
Progress = Callable[[str], None]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def iter_windows(start_at: datetime, end_at: datetime) -> Iterable[tuple[datetime, datetime]]:
    cursor = _utc(start_at)
    end_at = _utc(end_at)
    while cursor < end_at:
        window_end = min(cursor + NVD_WINDOW, end_at)
        yield cursor, window_end
        cursor = window_end


def _persist_nvd_window(db_engine, page_iterator, progress: Progress) -> int:
    imported = 0
    for page in page_iterator:
        with Session(db_engine) as session:
            for item in page:
                upsert_cve(session, item["record"], item["products"])
            session.commit()
        imported += len(page)
        progress(f"Page NVD persistee : {len(page)} CVE ({imported} cumulees)")
    return imported


def run_initial_import(
    *,
    since: datetime | None = None,
    all_history: bool = False,
    end_at: datetime | None = None,
    db_engine=default_engine,
    progress: Progress = print,
) -> dict:
    if all_history == (since is not None):
        raise ValueError("Choisir exactement --since ou --all-history")

    requested_start = ALL_HISTORY_START if all_history else _utc(since)
    end_at = _utc(end_at or datetime.now(timezone.utc))

    with Session(db_engine) as session:
        state = get_sync_state(session, INITIAL_IMPORT)
        scope_state = get_sync_state(session, INITIAL_IMPORT_SCOPE)
        same_scope = (
            scope_state
            and _parse_datetime(scope_state.cursor_at) == requested_start
        )
        resumable = state and state.status in {"running", "error"} and same_scope
        resume_at = _parse_datetime(state.cursor_at) if resumable else None
        start_at = max(requested_start, resume_at) if resume_at else requested_start
        previous_success = state.last_successful_at if state else None
        update_sync_state(
            session,
            INITIAL_IMPORT,
            status="running",
            cursor_at=start_at,
            last_error=None,
        )
        update_sync_state(
            session,
            INITIAL_IMPORT_SCOPE,
            status="running",
            cursor_at=requested_start,
            last_error=None,
        )
        session.commit()

    imported = 0
    try:
        for window_start, window_end in iter_windows(start_at, end_at):
            progress(
                f"Fenetre NVD publication : {window_start.isoformat()} -> {window_end.isoformat()}"
            )
            imported += _persist_nvd_window(
                db_engine,
                iter_cve_pages(window_start, window_end, date_filter="published"),
                progress,
            )
            with Session(db_engine) as session:
                update_sync_state(
                    session,
                    INITIAL_IMPORT,
                    status="running",
                    cursor_at=window_end,
                    last_error=None,
                )
                session.commit()

        with Session(db_engine) as session:
            update_sync_state(
                session,
                INITIAL_IMPORT,
                status="success",
                cursor_at=end_at,
                last_successful_at=end_at,
                last_error=None,
            )
            update_sync_state(
                session,
                INITIAL_IMPORT_SCOPE,
                status="success",
                cursor_at=requested_start,
                last_successful_at=end_at,
                last_error=None,
            )
            session.commit()
    except Exception as exc:
        with Session(db_engine) as session:
            state = update_sync_state(
                session,
                INITIAL_IMPORT,
                status="error",
                last_error=str(exc),
            )
            if previous_success and not state.last_successful_at:
                state.last_successful_at = previous_success
            session.commit()
        raise

    return {"imported": imported, "start_at": start_at, "end_at": end_at}


def run_nvd_incremental(
    *,
    end_at: datetime | None = None,
    db_engine=default_engine,
    progress: Progress = print,
) -> dict:
    end_at = _utc(end_at or datetime.now(timezone.utc))
    with Session(db_engine) as session:
        state = get_sync_state(session, NVD_INCREMENTAL)
        initial_state = get_sync_state(session, INITIAL_IMPORT)
        previous_success = state.last_successful_at if state else None
        base = (
            _parse_datetime(state.cursor_at if state and state.status in {"running", "error"} else None)
            or _parse_datetime(previous_success)
            or _parse_datetime(initial_state.last_successful_at if initial_state else None)
            or end_at - NVD_WINDOW
        )
        start_at = min(base - NVD_OVERLAP, end_at)
        update_sync_state(
            session,
            NVD_INCREMENTAL,
            status="running",
            cursor_at=start_at,
            last_error=None,
        )
        session.commit()

    imported = 0
    try:
        for window_start, window_end in iter_windows(start_at, end_at):
            progress(
                f"Fenetre NVD modifications : {window_start.isoformat()} -> {window_end.isoformat()}"
            )
            imported += _persist_nvd_window(
                db_engine,
                iter_cve_pages(window_start, window_end, date_filter="last_modified"),
                progress,
            )
            with Session(db_engine) as session:
                update_sync_state(
                    session,
                    NVD_INCREMENTAL,
                    status="running",
                    cursor_at=window_end,
                    last_successful_at=window_end,
                    last_error=None,
                )
                session.commit()

        with Session(db_engine) as session:
            update_sync_state(
                session,
                NVD_INCREMENTAL,
                status="success",
                cursor_at=end_at,
                last_successful_at=end_at,
                last_error=None,
            )
            session.commit()
    except Exception as exc:
        with Session(db_engine) as session:
            update_sync_state(
                session,
                NVD_INCREMENTAL,
                status="error",
                last_error=str(exc),
            )
            session.commit()
        raise

    return {"imported": imported, "start_at": start_at, "end_at": end_at}


def run_epss_sync(
    *,
    db_engine=default_engine,
    progress: Progress = print,
) -> dict:
    started_at = datetime.now(timezone.utc)
    with Session(db_engine) as session:
        update_sync_state(session, EPSS_SYNC, status="running", last_error=None)
        session.commit()

    updated = 0
    batch = []
    try:
        with Session(db_engine) as session:
            for item in iter_current_epss_scores():
                batch.append(
                    (
                        item["epss"],
                        item["epss_percentile"],
                        normalize_datetime(started_at),
                        item["cve_id"],
                    )
                )
                if len(batch) >= EPSS_BATCH_SIZE:
                    result = session.connection().exec_driver_sql(
                        "UPDATE cves SET epss = ?, epss_percentile = ?, updated_at = ? "
                        "WHERE cve_id = ?",
                        batch,
                    )
                    updated += max(result.rowcount, 0)
                    session.commit()
                    batch.clear()
            if batch:
                result = session.connection().exec_driver_sql(
                    "UPDATE cves SET epss = ?, epss_percentile = ?, updated_at = ? "
                    "WHERE cve_id = ?",
                    batch,
                )
                updated += max(result.rowcount, 0)
                session.commit()

        completed_at = datetime.now(timezone.utc)
        with Session(db_engine) as session:
            update_sync_state(
                session,
                EPSS_SYNC,
                status="success",
                cursor_at=completed_at,
                last_successful_at=completed_at,
                last_error=None,
            )
            session.commit()
        progress(f"EPSS mis a jour pour {updated} CVE locales")
    except Exception as exc:
        with Session(db_engine) as session:
            update_sync_state(session, EPSS_SYNC, status="error", last_error=str(exc))
            session.commit()
        raise
    return {"updated": updated}


def run_kev_sync(
    *,
    db_engine=default_engine,
    progress: Progress = print,
) -> dict:
    with Session(db_engine) as session:
        update_sync_state(session, KEV_SYNC, status="running", last_error=None)
        session.commit()

    try:
        kev_index = fetch_kev_index(raise_errors=True)
        completed_at = datetime.now(timezone.utc)
        with Session(db_engine) as session:
            session.execute(update(CVE).values(kev=False))
            cve_ids = list(kev_index)
            for offset in range(0, len(cve_ids), 500):
                session.execute(
                    update(CVE)
                    .where(CVE.cve_id.in_(cve_ids[offset : offset + 500]))
                    .values(kev=True, updated_at=normalize_datetime(completed_at))
                )
            update_sync_state(
                session,
                KEV_SYNC,
                status="success",
                cursor_at=completed_at,
                last_successful_at=completed_at,
                last_error=None,
            )
            session.commit()
        progress(f"Catalogue KEV synchronise : {len(kev_index)} entrees")
    except Exception as exc:
        with Session(db_engine) as session:
            update_sync_state(session, KEV_SYNC, status="error", last_error=str(exc))
            session.commit()
        raise
    return {"catalog_entries": len(kev_index)}


def run_full_sync(*, db_engine=default_engine, progress: Progress = print) -> dict:
    return {
        "nvd": run_nvd_incremental(db_engine=db_engine, progress=progress),
        "epss": run_epss_sync(db_engine=db_engine, progress=progress),
        "kev": run_kev_sync(db_engine=db_engine, progress=progress),
    }


def get_repository_status(*, db_engine=default_engine) -> dict:
    with Session(db_engine) as session:
        states = {}
        for name in (INITIAL_IMPORT, NVD_INCREMENTAL, EPSS_SYNC, KEV_SYNC):
            state = get_sync_state(session, name)
            states[name] = {
                "status": state.status if state else "not_started",
                "cursor_at": state.cursor_at if state else None,
                "last_successful_at": state.last_successful_at if state else None,
                "last_error": state.last_error if state else None,
            }
        return {
            "cves": count_cves(session),
            "cve_products": count_cve_products(session),
            "states": states,
        }
