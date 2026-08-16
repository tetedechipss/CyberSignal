import re
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session

from app.models import (
    CVE,
    CVEProduct,
    CVESyncState,
    CompanyIgnoredCVE,
    Finding,
    utcnow,
)


def normalize_name(value: str) -> str:
    normalized = (value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return re.sub(r"_+", "_", normalized)


def normalize_datetime(value: str | datetime | None) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        candidate = value.strip().replace("Z", "+00:00")
        if not candidate:
            return None
        parsed = datetime.fromisoformat(candidate)
    else:
        parsed = value

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc).isoformat()


def upsert_cve(
    session: Session,
    record: dict,
    products: Iterable[tuple[str, str]] = (),
) -> None:
    cve_id = record["cve_id"].strip().upper()
    now = utcnow()
    values = {
        "cve_id": cve_id,
        "published_at": normalize_datetime(record.get("published_at")),
        "last_modified_at": normalize_datetime(record.get("last_modified_at")),
        "cvss": record.get("cvss"),
        "source": record.get("source") or "NVD",
        "updated_at": now,
    }

    if "epss" in record:
        values["epss"] = record.get("epss")
    if "epss_percentile" in record:
        values["epss_percentile"] = record.get("epss_percentile")
    if "kev" in record:
        values["kev"] = bool(record.get("kev"))

    insert_values = {**values, "created_at": record.get("created_at") or now}
    update_values = {key: value for key, value in values.items() if key != "cve_id"}
    statement = sqlite_insert(CVE).values(**insert_values)
    statement = statement.on_conflict_do_update(
        index_elements=[CVE.cve_id],
        set_=update_values,
    )
    session.execute(statement)

    normalized_products = {
        (normalize_name(vendor), normalize_name(product))
        for vendor, product in products
        if normalize_name(vendor) not in {"", "*", "-"}
        and normalize_name(product) not in {"", "*", "-"}
    }

    session.execute(delete(CVEProduct).where(CVEProduct.cve_id == cve_id))
    for vendor, product in normalized_products:
        product_statement = sqlite_insert(CVEProduct).values(
            cve_id=cve_id,
            vendor=vendor,
            product=product,
        )
        session.execute(product_statement.on_conflict_do_nothing())


def _build_filtered_cve_ids(
    *,
    vendor: str | None = None,
    products: Iterable[str] = (),
    technology: str | None = None,
    published_since: str | datetime | None = None,
    date_from: str | datetime | None = None,
    date_to: str | datetime | None = None,
    kev_only: bool = False,
):
    vendor_name = normalize_name(vendor or "")
    product_names = {
        normalize_name(product)
        for product in products
        if normalize_name(product)
    }
    technology_name = normalize_name(technology or "")
    conditions = []
    needs_product_join = bool(vendor_name or product_names or technology_name)

    if vendor_name and product_names:
        conditions.append(
            and_(
                CVEProduct.vendor == vendor_name,
                CVEProduct.product.in_(product_names),
            )
        )
    elif vendor_name:
        conditions.append(CVEProduct.vendor == vendor_name)
    elif product_names:
        conditions.append(CVEProduct.product.in_(product_names))

    if technology_name:
        pattern = f"%{technology_name}%"
        conditions.append(
            or_(
                func.lower(CVEProduct.vendor).like(pattern),
                func.lower(CVEProduct.product).like(pattern),
            )
        )

    effective_date_from = date_from if date_from is not None else published_since
    normalized_from = normalize_datetime(effective_date_from)
    normalized_to = normalize_datetime(date_to)
    if normalized_from:
        conditions.append(CVE.published_at >= normalized_from)
    if normalized_to:
        conditions.append(CVE.published_at <= normalized_to)
    if kev_only:
        conditions.append(CVE.kev.is_(True))

    statement = select(CVE.cve_id)
    if needs_product_join:
        statement = statement.join(CVEProduct, CVEProduct.cve_id == CVE.cve_id)
    if conditions:
        statement = statement.where(*conditions)
    return statement.distinct()


def count_cves(
    session: Session,
    *,
    vendor: str | None = None,
    products: Iterable[str] = (),
    technology: str | None = None,
    published_since: str | datetime | None = None,
    date_from: str | datetime | None = None,
    date_to: str | datetime | None = None,
    kev_only: bool = False,
) -> int:
    filtered_ids = _build_filtered_cve_ids(
        vendor=vendor,
        products=products,
        technology=technology,
        published_since=published_since,
        date_from=date_from,
        date_to=date_to,
        kev_only=kev_only,
    ).subquery()
    statement = select(func.count()).select_from(filtered_ids)
    return int(session.execute(statement).scalar_one())


def count_cve_products(session: Session) -> int:
    return int(session.execute(select(func.count()).select_from(CVEProduct)).scalar_one())


def get_cve(session: Session, cve_id: str) -> CVE | None:
    return session.get(CVE, cve_id.strip().upper())


def search_cves(
    session: Session,
    *,
    vendor: str | None = None,
    products: Iterable[str] = (),
    technology: str | None = None,
    published_since: str | datetime | None = None,
    date_from: str | datetime | None = None,
    date_to: str | datetime | None = None,
    kev_only: bool = False,
    sort_by: str = "published_at",
    limit: int | None = 10,
    offset: int = 0,
) -> list[CVE]:
    filtered_ids = _build_filtered_cve_ids(
        vendor=vendor,
        products=products,
        technology=technology,
        published_since=published_since,
        date_from=date_from,
        date_to=date_to,
        kev_only=kev_only,
    )
    statement = select(CVE).where(CVE.cve_id.in_(filtered_ids))

    if sort_by in {"cvss", "critical"}:
        statement = statement.order_by(
            CVE.cvss.is_(None),
            CVE.cvss.desc(),
            CVE.published_at.desc(),
            CVE.cve_id.desc(),
        )
    elif sort_by == "epss":
        statement = statement.order_by(
            CVE.epss.is_(None),
            CVE.epss.desc(),
            CVE.published_at.desc(),
            CVE.cve_id.desc(),
        )
    else:
        statement = statement.order_by(
            CVE.published_at.is_(None),
            CVE.published_at.desc(),
            CVE.cve_id.desc(),
        )

    statement = statement.offset(max(0, offset))
    if limit is not None:
        statement = statement.limit(max(1, limit))
    return list(session.execute(statement).scalars().all())


def get_products_for_cves(
    session: Session,
    cve_ids: Iterable[str],
) -> dict[str, list[tuple[str, str]]]:
    normalized_ids = [cve_id.strip().upper() for cve_id in cve_ids if cve_id]
    products_by_cve = {cve_id: [] for cve_id in normalized_ids}
    if not normalized_ids:
        return products_by_cve

    statement = (
        select(CVEProduct)
        .where(CVEProduct.cve_id.in_(normalized_ids))
        .order_by(CVEProduct.cve_id, CVEProduct.vendor, CVEProduct.product)
    )
    for item in session.execute(statement).scalars():
        products_by_cve[item.cve_id].append((item.vendor, item.product))
    return products_by_cve


def search_cve_page(
    session: Session,
    *,
    date_from: str | datetime | None = None,
    date_to: str | datetime | None = None,
    technology: str | None = None,
    kev_only: bool = False,
    sort_by: str = "published_at",
    limit: int = 100,
    offset: int = 0,
) -> dict:
    filters = {
        "date_from": date_from,
        "date_to": date_to,
        "technology": technology,
        "kev_only": kev_only,
    }
    total = count_cves(session, **filters)
    cves = search_cves(
        session,
        **filters,
        sort_by=sort_by,
        limit=limit,
        offset=offset,
    )
    products_by_cve = get_products_for_cves(
        session,
        [cve.cve_id for cve in cves],
    )
    return {
        "total": total,
        "items": [
            {"cve": cve, "products": products_by_cve[cve.cve_id]}
            for cve in cves
        ],
    }


def get_company_cve_findings(
    session: Session,
    company_id: int,
    *,
    include_ignored: bool = False,
    ignored_only: bool = False,
) -> list[dict]:
    statement = (
        select(Finding, CVE)
        .outerjoin(CVE, CVE.cve_id == Finding.cve_id)
        .outerjoin(
            CompanyIgnoredCVE,
            and_(
                CompanyIgnoredCVE.company_id == Finding.company_id,
                CompanyIgnoredCVE.cve_id == Finding.cve_id,
            ),
        )
        .where(Finding.company_id == company_id)
        .order_by(
            CVE.published_at.is_(None),
            CVE.published_at.desc(),
            CVE.cvss.is_(None),
            CVE.cvss.desc(),
            Finding.id.desc(),
        )
    )
    if ignored_only:
        statement = statement.where(CompanyIgnoredCVE.cve_id.is_not(None))
    elif not include_ignored:
        statement = statement.where(CompanyIgnoredCVE.cve_id.is_(None))

    records = session.execute(statement).all()
    cve_ids = [cve.cve_id for _, cve in records if cve is not None]
    products_by_cve = get_products_for_cves(session, cve_ids)
    return [
        {
            "finding": finding,
            "cve": cve,
            "products": products_by_cve.get(cve.cve_id, []) if cve else [],
        }
        for finding, cve in records
    ]


def get_sync_state(session: Session, name: str) -> CVESyncState | None:
    return session.get(CVESyncState, name)


def update_sync_state(
    session: Session,
    name: str,
    *,
    status: str,
    cursor_at: str | datetime | None = None,
    last_successful_at: str | datetime | None = None,
    last_error: str | None = None,
) -> CVESyncState:
    state = get_sync_state(session, name) or CVESyncState(name=name)
    state.status = status
    if cursor_at is not None:
        state.cursor_at = normalize_datetime(cursor_at)
    if last_successful_at is not None:
        state.last_successful_at = normalize_datetime(last_successful_at)
    state.last_error = last_error
    state.updated_at = utcnow()
    session.add(state)
    return state
