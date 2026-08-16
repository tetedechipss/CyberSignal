import csv
import gzip
import io
from collections.abc import Iterator

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def get_epss_data(cve_id: str) -> dict | None:
    try:
        response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=20)
        response.raise_for_status()
        data = response.json().get("data", [])
        if not data:
            return None
        return {
            "cve_id": cve_id.upper(),
            "epss": float(data[0].get("epss", 0.0)),
            "epss_percentile": float(data[0].get("percentile", 0.0)),
        }
    except Exception as exc:
        print(f"[EPSS] Erreur pour {cve_id}: {exc}")
        return None


def get_epss_score(cve_id: str) -> float:
    data = get_epss_data(cve_id)
    return data["epss"] if data else 0.0


def iter_current_epss_scores() -> Iterator[dict]:
    with requests.get(EPSS_CSV_URL, stream=True, timeout=120) as response:
        response.raise_for_status()
        response.raw.decode_content = False
        with gzip.GzipFile(fileobj=response.raw) as compressed:
            with io.TextIOWrapper(compressed, encoding="utf-8", newline="") as text_stream:
                lines = (line for line in text_stream if not line.startswith("#"))
                for row in csv.DictReader(lines):
                    cve_id = (row.get("cve") or "").strip().upper()
                    if not cve_id:
                        continue
                    try:
                        yield {
                            "cve_id": cve_id,
                            "epss": float(row["epss"]),
                            "epss_percentile": float(row["percentile"]),
                        }
                    except (KeyError, TypeError, ValueError):
                        continue
