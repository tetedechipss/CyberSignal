import json

from sqlmodel import Session, select

from app.database import engine
from app.models import Asset, Company, CVE, Finding
from app.providers.cisa_kev import fetch_kev_index
from app.providers.epss import get_epss_data
from app.providers.nvd import search_cves_by_keyword
from app.scoring import score_vulnerability
from app.services.cve_repository import count_cves, search_cves, upsert_cve
from app.services.technology_mapping import resolve_technology


def _local_cve_payload(cve: CVE) -> dict:
    return {
        "cve_id": cve.cve_id,
        "published": cve.published_at,
        "last_modified": cve.last_modified_at,
        "description": "",
        "cvss": cve.cvss or 0.0,
        "epss": cve.epss or 0.0,
        "epss_percentile": cve.epss_percentile,
        "is_kev": cve.kev,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
        "origin": "local",
    }


def _find_local_cves(session: Session, technology: str) -> list[dict]:
    mapping = resolve_technology(technology)
    matches = search_cves(
        session,
        vendor=mapping["vendor"],
        products=mapping["products"],
        technology=None if mapping["mapped"] else mapping["technology"],
        limit=10,
    )
    return [_local_cve_payload(cve) for cve in matches]


def _fallback_cves(
    session: Session,
    technology: str,
    kev_index: dict,
) -> list[dict]:
    results = search_cves_by_keyword(technology, results_per_page=10)
    enriched = []
    for cve in results:
        cve_id = cve["cve_id"]
        epss_data = get_epss_data(cve_id)
        epss = epss_data["epss"] if epss_data else 0.0
        percentile = epss_data["epss_percentile"] if epss_data else None
        is_kev = cve_id in kev_index
        record = {
            "cve_id": cve_id,
            "published_at": cve.get("published"),
            "last_modified_at": cve.get("last_modified"),
            "cvss": cve.get("cvss"),
            "epss": epss,
            "epss_percentile": percentile,
            "kev": is_kev,
            "source": "NVD",
        }
        upsert_cve(session, record, cve.get("products", []))
        enriched.append(
            {
                **cve,
                "epss": epss,
                "epss_percentile": percentile,
                "is_kev": is_kev,
                "origin": "nvd_fallback",
            }
        )
    session.commit()
    return enriched


def _save_finding(
    session: Session,
    *,
    company_id: int,
    technology: str,
    cve: dict,
) -> int | None:
    cve_id = cve["cve_id"]
    cvss = float(cve.get("cvss") or 0.0)
    epss = float(cve.get("epss") or 0.0)
    is_kev = bool(cve.get("is_kev"))
    score, severity, confidence = score_vulnerability(
        cvss=cvss,
        epss=epss,
        is_kev=is_kev,
        asset_match=True,
    )
    values = {
        "source": "NVD/CISA/EPSS",
        "finding_type": "vulnerability",
        "title": f"{cve_id} liee a {technology}",
        "description": (cve.get("description") or "")[:3000],
        "severity": severity,
        "score": score,
        "confidence": confidence,
        "related_asset": technology,
        "cve_id": cve_id,
        "url": cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "raw_data": json.dumps(
            {
                "technology": technology,
                "origin": cve.get("origin"),
            },
            ensure_ascii=False,
        ),
    }
    existing = session.exec(
        select(Finding)
        .where(Finding.company_id == company_id, Finding.cve_id == cve_id)
        .order_by(Finding.id)
    ).first()
    if existing:
        if not values["description"]:
            values["description"] = existing.description
        for field, value in values.items():
            setattr(existing, field, value)
        session.add(existing)
        return None

    finding = Finding(company_id=company_id, **values)
    session.add(finding)
    session.flush()
    return finding.id


def collect_for_company(company_id: int) -> list[int]:
    created_finding_ids = []
    with Session(engine) as session:
        company = session.get(Company, company_id)
        if not company:
            raise ValueError(f"Company introuvable: {company_id}")

        assets = session.exec(select(Asset).where(Asset.company_id == company_id)).all()
        technologies = [
            asset.value
            for asset in assets
            if asset.asset_type.lower() == "technology"
        ]
        if not technologies:
            print("[Collector] Aucun asset de type technology.")
            return []

        repository_available = count_cves(session) > 0
        kev_index = None
        seen_cves = set()

        for technology in technologies:
            cves = _find_local_cves(session, technology) if repository_available else []
            if not cves:
                if kev_index is None:
                    kev_index = fetch_kev_index()
                cves = _fallback_cves(session, technology, kev_index)

            for cve in cves:
                cve_id = cve["cve_id"]
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                finding_id = _save_finding(
                    session,
                    company_id=company_id,
                    technology=technology,
                    cve=cve,
                )
                if finding_id is not None:
                    created_finding_ids.append(finding_id)

        session.commit()
    return created_finding_ids
