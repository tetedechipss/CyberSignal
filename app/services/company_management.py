from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session

from app.database import engine as default_engine
from app.models import Asset, Company, CompanyIgnoredCVE, Finding, Report


def _rowcount(result) -> int:
    return max(result.rowcount or 0, 0)


def ignore_company_cves(
    company_id: int,
    cve_ids: list[str],
    *,
    db_engine=default_engine,
) -> dict:
    normalized_cve_ids = list(
        dict.fromkeys(cve_id.strip().upper() for cve_id in cve_ids if cve_id.strip())
    )
    with Session(db_engine) as session:
        try:
            if not session.get(Company, company_id):
                raise ValueError(f"Company introuvable: {company_id}")
            company_cve_ids = set(
                session.execute(
                    select(Finding.cve_id).where(
                        Finding.company_id == company_id,
                        Finding.cve_id.in_(normalized_cve_ids),
                    )
                ).scalars()
            )
            if company_cve_ids != set(normalized_cve_ids):
                raise ValueError("Une CVE n'appartient pas aux findings de cette entreprise")
            created = 0
            for cve_id in normalized_cve_ids:
                statement = sqlite_insert(CompanyIgnoredCVE).values(
                    company_id=company_id,
                    cve_id=cve_id,
                )
                created += _rowcount(
                    session.execute(statement.on_conflict_do_nothing())
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
    return {
        "cve_ids": normalized_cve_ids,
        "created": created,
        "already_ignored": len(normalized_cve_ids) - created,
    }


def ignore_company_cve(company_id: int, cve_id: str, *, db_engine=default_engine) -> bool:
    result = ignore_company_cves(company_id, [cve_id], db_engine=db_engine)
    return result["created"] > 0


def restore_company_cve(company_id: int, cve_id: str, *, db_engine=default_engine) -> bool:
    with Session(db_engine) as session:
        result = session.execute(
            delete(CompanyIgnoredCVE).where(
                CompanyIgnoredCVE.company_id == company_id,
                CompanyIgnoredCVE.cve_id == cve_id.strip().upper(),
            )
        )
        session.commit()
        return result.rowcount > 0


def delete_company_technology(
    company_id: int,
    asset_id: int,
    *,
    db_engine=default_engine,
) -> dict:
    result = delete_company_technologies(
        company_id,
        [asset_id],
        db_engine=db_engine,
    )
    return {
        "technology": result["technologies"][0],
        "deleted_findings": result["deleted_findings"],
    }


def delete_company_technologies(
    company_id: int,
    asset_ids: list[int],
    *,
    db_engine=default_engine,
) -> dict:
    unique_asset_ids = list(dict.fromkeys(int(asset_id) for asset_id in asset_ids))
    if not unique_asset_ids:
        return {"technologies": [], "deleted_assets": 0, "deleted_findings": 0}

    with Session(db_engine) as session:
        try:
            assets = list(
                session.execute(
                    select(Asset).where(
                        Asset.company_id == company_id,
                        Asset.id.in_(unique_asset_ids),
                    )
                ).scalars()
            )
            assets_by_id = {asset.id: asset for asset in assets}
            if set(assets_by_id) != set(unique_asset_ids):
                raise ValueError("Un asset est introuvable pour cette entreprise")
            if any(asset.asset_type.lower() != "technology" for asset in assets):
                raise ValueError("Seuls les assets technology sont geres ici")

            ordered_assets = [assets_by_id[asset_id] for asset_id in unique_asset_ids]
            technologies = [asset.value for asset in ordered_assets]
            for asset in ordered_assets:
                session.delete(asset)
            session.flush()

            deleted_findings = 0
            unique_technologies = list(
                dict.fromkeys(technology.strip().lower() for technology in technologies)
            )
            for normalized_technology in unique_technologies:
                remaining_equivalent = session.execute(
                    select(func.count())
                    .select_from(Asset)
                    .where(
                        Asset.company_id == company_id,
                        func.lower(Asset.asset_type) == "technology",
                        func.lower(Asset.value) == normalized_technology,
                    )
                ).scalar_one()
                if remaining_equivalent == 0:
                    deleted_findings += _rowcount(
                        session.execute(
                            delete(Finding).where(
                                Finding.company_id == company_id,
                                func.lower(Finding.related_asset)
                                == normalized_technology,
                            )
                        )
                    )
            session.commit()
        except Exception:
            session.rollback()
            raise
    return {
        "technologies": technologies,
        "deleted_assets": len(ordered_assets),
        "deleted_findings": deleted_findings,
    }


def delete_company(
    company_id: int,
    *,
    db_engine=default_engine,
    reports_root: str | Path = "reports",
) -> dict:
    with Session(db_engine) as session:
        try:
            company = session.get(Company, company_id)
            if not company:
                raise ValueError(f"Company introuvable: {company_id}")
            report_paths = list(
                session.execute(
                    select(Report.file_path).where(Report.company_id == company_id)
                ).scalars()
            )
            counts = {
                "ignored_cves": max(
                    session.execute(
                        delete(CompanyIgnoredCVE).where(
                            CompanyIgnoredCVE.company_id == company_id
                        )
                    ).rowcount or 0,
                    0,
                ),
                "findings": max(
                    session.execute(
                        delete(Finding).where(Finding.company_id == company_id)
                    ).rowcount,
                    0,
                ),
                "assets": max(
                    session.execute(
                        delete(Asset).where(Asset.company_id == company_id)
                    ).rowcount,
                    0,
                ),
                "reports": max(
                    session.execute(
                        delete(Report).where(Report.company_id == company_id)
                    ).rowcount,
                    0,
                ),
            }
            session.delete(company)
            session.commit()
        except Exception:
            session.rollback()
            raise

    root = Path(reports_root).resolve()
    deleted_files = 0
    for raw_path in report_paths:
        path = Path(raw_path)
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
        if path.is_relative_to(root) and path.is_file():
            path.unlink()
            deleted_files += 1
    return {**counts, "report_files": deleted_files}
