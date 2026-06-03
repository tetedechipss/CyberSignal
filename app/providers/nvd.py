import os
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_description(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])

    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")

    return descriptions[0].get("value", "") if descriptions else ""


def _extract_cvss(cve: dict) -> float:
    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)

        if values:
            try:
                return float(values[0]["cvssData"]["baseScore"])
            except Exception:
                continue

    return 0.0


def search_cves_by_keyword(keyword: str, results_per_page: int = 10) -> list[dict]:
    headers = {}
    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }

    try:
        response = requests.get(NVD_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        print(f"[NVD] Erreur pour {keyword}: {exc}")
        return []

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        if not cve_id:
            continue

        results.append(
            {
                "cve_id": cve_id,
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "description": _extract_description(cve),
                "cvss": _extract_cvss(cve),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )

    return results