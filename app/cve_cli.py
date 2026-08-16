import argparse
import json
from datetime import datetime, timezone

from app.database import init_db
from app.services.cve_sync import (
    get_repository_status,
    run_epss_sync,
    run_full_sync,
    run_initial_import,
    run_kev_sync,
)


def _parse_date(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Date attendue au format YYYY-MM-DD") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Referentiel CVE local CyberSignal")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="Construire le referentiel CVE")
    scope = init_parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--since", type=_parse_date, help="Importer depuis YYYY-MM-DD")
    scope.add_argument(
        "--all-history",
        action="store_true",
        help="Importer tout l'historique NVD disponible",
    )

    commands.add_parser("sync", help="Synchroniser NVD, EPSS et CISA KEV")
    commands.add_parser("status", help="Afficher l'etat local du referentiel")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    init_db()

    if args.command == "init":
        result = run_initial_import(since=args.since, all_history=args.all_history)
        print(f"Import NVD termine : {result['imported']} CVE traitees")
        print("Enrichissement EPSS...")
        run_epss_sync()
        print("Synchronisation CISA KEV...")
        run_kev_sync()
        return 0

    if args.command == "sync":
        result = run_full_sync()
        print(json.dumps(result, indent=2, default=str))
        return 0

    status = get_repository_status()
    print(f"CVE locales : {status['cves']}")
    print(f"Couples vendor/product : {status['cve_products']}")
    for name, state in status["states"].items():
        print(
            f"{name}: {state['status']} | derniere reussite: "
            f"{state['last_successful_at'] or '-'} | curseur: {state['cursor_at'] or '-'}"
        )
        if state["last_error"]:
            print(f"  erreur: {state['last_error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
