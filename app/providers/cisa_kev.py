import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_index(*, raise_errors: bool = False) -> dict:
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("Catalogue CISA KEV invalide: vulnerabilities absent")
        return {
            item.get("cveID"): item
            for item in vulnerabilities
            if item.get("cveID")
        }
    except Exception as exc:
        if raise_errors:
            raise
        print(f"[CISA KEV] Erreur: {exc}")
        return {}
