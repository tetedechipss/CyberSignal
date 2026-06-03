import sys
import yaml
from sqlmodel import Session, select

from app.database import init_db, engine
from app.models import Company, Asset
from app.services.collector import collect_for_company
from app.report import generate_company_report


def add_asset_if_missing(
    session: Session,
    company_id: int,
    asset_type: str,
    value: str,
) -> None:
    existing = session.exec(
        select(Asset).where(
            Asset.company_id == company_id,
            Asset.asset_type == asset_type,
            Asset.value == value,
        )
    ).first()

    if existing:
        return

    session.add(
        Asset(
            company_id=company_id,
            asset_type=asset_type,
            value=value,
        )
    )


def main(yaml_path: str):
    init_db()

    with open(yaml_path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    company_data = data["company"]

    with Session(engine) as session:
        company = session.exec(
            select(Company).where(Company.name == company_data["name"])
        ).first()

        if not company:
            company = Company(
                name=company_data["name"],
                sector=company_data.get("sector"),
                country=company_data.get("country"),
            )

            session.add(company)
            session.commit()
            session.refresh(company)

        assets_data = company_data.get("assets", {})

        for technology in assets_data.get("technologies", []):
            add_asset_if_missing(session, company.id, "technology", technology)

        for domain in assets_data.get("domains", []):
            add_asset_if_missing(session, company.id, "domain", domain)

        for keyword in assets_data.get("keywords", []):
            add_asset_if_missing(session, company.id, "keyword", keyword)

        session.commit()
        company_id = company.id

    finding_ids = collect_for_company(company_id)
    report_path = generate_company_report(company_id)

    print(f"Findings créés : {len(finding_ids)}")
    print(f"Rapport généré : {report_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_brief.py examples/demo_company.yaml")
        raise SystemExit(1)

    main(sys.argv[1])