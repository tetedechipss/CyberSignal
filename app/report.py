from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

from app.database import engine
from app.models import Asset, Company, Report
from app.services.cve_presentation import NVD_CVE_URL, format_company_finding_rows
from app.services.cve_repository import get_company_cve_findings


def slugify(value: str) -> str:
    return (
        value.lower()
        .replace(" ", "_")
        .replace("/", "_")
        .replace("\\", "_")
        .replace("'", "")
    )


def generate_company_report(company_id: int) -> str:
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    with Session(engine) as session:
        company = session.get(Company, company_id)
        if not company:
            raise ValueError(f"Company introuvable: {company_id}")

        assets = session.exec(
            select(Asset).where(Asset.company_id == company_id)
        ).all()
        finding_records = get_company_cve_findings(session, company_id)
        rows = format_company_finding_rows(finding_records)

        today = datetime.now().strftime("%Y-%m-%d")
        filename = f"{slugify(company.name)}_{today}.md"
        path = reports_dir / filename
        kev_count = sum(1 for row in rows if row["KEV"])
        critical_cvss_count = sum(
            1
            for row in rows
            if isinstance(row["CVSS"], (int, float)) and row["CVSS"] >= 9.0
        )

        lines = [
            f"# Cyber Exposure Brief - {company.name}",
            "",
            f"Date : {today}",
            f"Secteur : {company.sector or 'Non renseigne'}",
            f"Pays : {company.country or 'Non renseigne'}",
            "",
            "## Assets surveilles",
            "",
        ]
        if assets:
            lines.extend(f"- **{asset.asset_type}** : {asset.value}" for asset in assets)
        else:
            lines.append("- Aucun asset renseigne")

        lines.extend(
            [
                "",
                "## Resume executif",
                "",
                f"{len(rows)} vulnerabilites detectees, dont {kev_count} KEV et "
                f"{critical_cvss_count} avec un CVSS superieur ou egal a 9.0.",
                "",
                "## Vulnerabilites detectees",
                "",
            ]
        )
        if not rows:
            lines.append("Aucune vulnerabilite detectee pour le moment.")
        else:
            lines.append(
                "| Technology | CVE | Date publication | Vendor | Product | CVSS | "
                "EPSS | EPSS percentile | KEV |"
            )
            lines.append("|---|---|---|---|---|---:|---:|---:|:---:|")
            for row in rows:
                cve_id = row["CVE"]
                cve_link = f"[{cve_id}]({NVD_CVE_URL}/{cve_id})"
                lines.append(
                    f"| {row['Technology']} | {cve_link} | {row['Date publication']} | "
                    f"{row['Vendor']} | {row['Product']} | {row['CVSS']} | "
                    f"{row['EPSS']} | {row['EPSS percentile']} | {row['KEV']} |"
                )

            lines.extend(
                [
                    "",
                    "## Action recommandee",
                    "",
                    "Verifier si les technologies concernees sont utilisees et exposees, "
                    "confirmer les versions installees et appliquer les correctifs disponibles. "
                    "Prioriser les CVE KEV, les CVSS eleves et les probabilites EPSS fortes.",
                ]
            )

        path.write_text("\n".join(lines), encoding="utf-8")
        report = Report(
            company_id=company_id,
            summary=f"{len(rows)} vulnerabilites detectees",
            file_path=str(path),
        )
        session.add(report)
        session.commit()
        return str(path)
