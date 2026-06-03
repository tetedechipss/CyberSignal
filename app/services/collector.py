import json
from sqlmodel import Session, select

from app.database import engine
from app.models import Company, Asset, Finding
from app.providers.cisa_kev import fetch_kev_index
from app.providers.nvd import search_cves_by_keyword
from app.providers.epss import get_epss_score
from app.scoring import score_vulnerability


def collect_for_company(company_id: int) -> list[int]:
    created_finding_ids = []

    with Session(engine) as session:
        company = session.get(Company, company_id)

        if not company:
            raise ValueError(f"Company introuvable: {company_id}")

        assets = session.exec(
            select(Asset).where(Asset.company_id == company_id)
        ).all()

        technologies = [
            asset.value
            for asset in assets
            if asset.asset_type.lower() == "technology"
        ]

        if not technologies:
            print("[Collector] Aucun asset de type technology.")
            return []

        kev_index = fetch_kev_index()
        seen_cves = set()

        for technology in technologies:
            cves = search_cves_by_keyword(technology, results_per_page=10)

            for cve in cves:
                cve_id = cve["cve_id"]

                if cve_id in seen_cves:
                    continue

                seen_cves.add(cve_id)

                epss = get_epss_score(cve_id)
                is_kev = cve_id in kev_index
                cvss = float(cve.get("cvss", 0.0))

                score, severity, confidence = score_vulnerability(
                    cvss=cvss,
                    epss=epss,
                    is_kev=is_kev,
                    asset_match=True,
                )

                finding = Finding(
                    company_id=company_id,
                    source="NVD/CISA/EPSS",
                    finding_type="vulnerability",
                    title=f"{cve_id} liée à {technology}",
                    description=cve.get("description", "")[:3000],
                    severity=severity,
                    score=score,
                    confidence=confidence,
                    related_asset=technology,
                    cve_id=cve_id,
                    url=cve.get("url"),
                    raw_data=json.dumps(
                        {
                            "technology": technology,
                            "cvss": cvss,
                            "epss": epss,
                            "is_kev": is_kev,
                            "kev_data": kev_index.get(cve_id),
                        },
                        ensure_ascii=False,
                    ),
                )

                session.add(finding)
                session.commit()
                session.refresh(finding)
                created_finding_ids.append(finding.id)

        return created_finding_ids