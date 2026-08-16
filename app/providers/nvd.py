import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Iterator
from urllib.parse import unquote

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_RESULTS_PER_PAGE = 2_000
_request_lock = threading.Lock()
_last_request_at = 0.0


def _build_session() -> requests.Session:
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        status=5,
        backoff_factor=1.0,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _headers() -> dict[str, str]:
    api_key = os.getenv("NVD_API_KEY")
    return {"apiKey": api_key} if api_key else {}


def _request_json(params: dict) -> dict:
    global _last_request_at
    default_delay = 0.6 if os.getenv("NVD_API_KEY") else 6.0
    delay = float(os.getenv("NVD_REQUEST_DELAY_SECONDS", default_delay))
    with _build_session() as session:
        with _request_lock:
            elapsed = time.monotonic() - _last_request_at
            if elapsed < delay:
                time.sleep(delay - elapsed)
            response = session.get(NVD_URL, headers=_headers(), params=params, timeout=60)
            _last_request_at = time.monotonic()
            response.raise_for_status()
            return response.json()


def _format_nvd_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _extract_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            try:
                return float(metric["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


def _split_cpe(criteria: str) -> list[str]:
    parts = re.split(r"(?<!\\):", criteria)
    return [unquote(part).replace(r"\:", ":").replace(r"\\", "\\") for part in parts]


def _extract_products(cve: dict) -> set[tuple[str, str]]:
    products: set[tuple[str, str]] = set()

    def visit(node: dict) -> None:
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable"):
                continue
            parts = _split_cpe(match.get("criteria", ""))
            if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                vendor, product = parts[3], parts[4]
                if vendor not in {"", "*", "-"} and product not in {"", "*", "-"}:
                    products.add((vendor, product))
        for child in node.get("nodes", []):
            visit(child)

    for configuration in cve.get("configurations", []):
        visit(configuration)
    return products


def parse_nvd_vulnerability(item: dict) -> dict | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    return {
        "record": {
            "cve_id": cve_id,
            "published_at": cve.get("published"),
            "last_modified_at": cve.get("lastModified"),
            "cvss": _extract_cvss(cve),
            "source": "NVD",
        },
        "products": sorted(_extract_products(cve)),
        "description": _extract_description(cve),
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def iter_cve_pages(
    start_at: datetime,
    end_at: datetime,
    *,
    date_filter: str = "published",
    results_per_page: int = NVD_MAX_RESULTS_PER_PAGE,
) -> Iterator[list[dict]]:
    if date_filter not in {"published", "last_modified"}:
        raise ValueError("date_filter doit etre 'published' ou 'last_modified'")

    prefix = "pub" if date_filter == "published" else "lastMod"
    page_size = min(max(1, results_per_page), NVD_MAX_RESULTS_PER_PAGE)
    start_index = 0

    while True:
        params = {
            f"{prefix}StartDate": _format_nvd_datetime(start_at),
            f"{prefix}EndDate": _format_nvd_datetime(end_at),
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        data = _request_json(params)
        parsed = [
            result
            for item in data.get("vulnerabilities", [])
            if (result := parse_nvd_vulnerability(item)) is not None
        ]
        if parsed:
            yield parsed

        received = len(data.get("vulnerabilities", []))
        total = int(data.get("totalResults", received))
        start_index += received
        if received == 0 or start_index >= total:
            break


def search_cves_by_keyword(keyword: str, results_per_page: int = 10) -> list[dict]:
    limit = min(max(1, results_per_page), NVD_MAX_RESULTS_PER_PAGE)
    try:
        summary = _request_json(
            {"keywordSearch": keyword, "resultsPerPage": 1, "startIndex": 0}
        )
        total = int(summary.get("totalResults", 0))
        if total == 0:
            return []
        start_index = max(0, total - limit)
        data = _request_json(
            {
                "keywordSearch": keyword,
                "resultsPerPage": limit,
                "startIndex": start_index,
            }
        )
    except Exception as exc:
        print(f"[NVD] Erreur pour {keyword}: {exc}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        parsed = parse_nvd_vulnerability(item)
        if not parsed:
            continue
        record = parsed["record"]
        results.append(
            {
                "cve_id": record["cve_id"],
                "published": record["published_at"],
                "last_modified": record["last_modified_at"],
                "description": parsed["description"],
                "cvss": record["cvss"] or 0.0,
                "url": parsed["url"],
                "products": parsed["products"],
            }
        )

    return sorted(
        results,
        key=lambda item: (item.get("published") or "", item["cve_id"]),
        reverse=True,
    )[:limit]


def fetch_recent_cves(days: int = 7, results_per_page: int = 50) -> list[dict]:
    end_at = datetime.now(timezone.utc)
    start_at = end_at - timedelta(days=days)
    results = []
    try:
        for page in iter_cve_pages(
            start_at,
            end_at,
            date_filter="published",
            results_per_page=min(results_per_page, NVD_MAX_RESULTS_PER_PAGE),
        ):
            for parsed in page:
                record = parsed["record"]
                results.append(
                    {
                        "cve_id": record["cve_id"],
                        "published": record["published_at"],
                        "last_modified": record["last_modified_at"],
                        "description": parsed["description"],
                        "cvss": record["cvss"] or 0.0,
                        "url": parsed["url"],
                        "products": parsed["products"],
                    }
                )
                if len(results) >= results_per_page:
                    return results
    except Exception as exc:
        print(f"[NVD] Erreur tendances recentes: {exc}")
    return results
