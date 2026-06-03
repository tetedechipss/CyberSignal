from datetime import datetime
from pathlib import Path
from sqlmodel import Session, select

from app.database import engine
from app.models import Company, Asset, Finding, Report


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

        findings = session.exec(
            select(Finding)
            .where(Finding.company_id == company_id)
            .order_by(Finding.score.desc())
        ).all()

        today = datetime.now().strftime("%Y-%m-%d")
        filename = f"{slugify(company.name)}_{today}.md"
        path = reports_dir / filename

        lines = []
        lines.append(f"# Cyber Exposure Brief — {company.name}")
        lines.append("")
        lines.append(f"Date : {today}")
        lines.append(f"Secteur : {company.sector or 'Non renseigné'}")
        lines.append(f"Pays : {company.country or 'Non renseigné'}")
        lines.append("")
        lines.append("## Assets surveillés")
        lines.append("")

        if assets:
            for asset in assets:
                lines.append(f"- **{asset.asset_type}** : {asset.value}")
        else:
            lines.append("- Aucun asset renseigné")

        lines.append("")
        lines.append("## Résumé exécutif")
        lines.append("")

        critical_count = len([f for f in findings if f.severity == "critical"])
        high_count = len([f for f in findings if f.severity == "high"])
        medium_count = len([f for f in findings if f.severity == "medium"])

        lines.append(
            f"{len(findings)} signaux détectés : "
            f"{critical_count} critiques, {high_count} élevés, {medium_count} moyens."
        )

        lines.append("")
        lines.append("## Findings prioritaires")
        lines.append("")

        if not findings:
            lines.append("Aucun finding détecté pour le moment.")
        else:
            for index, finding in enumerate(findings[:20], start=1):
                lines.append(f"### {index}. {finding.title}")
                lines.append("")
                lines.append(f"- Sévérité : **{finding.severity}**")
                lines.append(f"- Score : **{finding.score}/100**")
                lines.append(f"- Confiance : **{finding.confidence}/100**")
                lines.append(f"- Source : {finding.source}")

                if finding.related_asset:
                    lines.append(f"- Asset concerné : {finding.related_asset}")

                if finding.cve_id:
                    lines.append(f"- CVE : {finding.cve_id}")

                if finding.url:
                    lines.append(f"- URL : {finding.url}")

                lines.append("")
                lines.append("**Description :**")
                lines.append("")
                lines.append(finding.description or "Pas de description.")
                lines.append("")
                lines.append("**Action recommandée :**")
                lines.append("")
                lines.append(
                    "Vérifier si l'asset concerné est utilisé et exposé. "
                    "Si oui, confirmer la version installée, vérifier les correctifs disponibles "
                    "et prioriser la remédiation selon la criticité."
                )
                lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")

        report = Report(
            company_id=company_id,
            summary=f"{len(findings)} findings détectés",
            file_path=str(path),
        )

        session.add(report)
        session.commit()

        return str(path)