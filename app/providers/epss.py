import requests

EPSS_URL = "https://api.first.org/data/v1/epss"


def get_epss_score(cve_id: str) -> float:
    try:
        response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=20)
        response.raise_for_status()
        data = response.json().get("data", [])

        if not data:
            return 0.0

        return float(data[0].get("epss", 0.0))
    except Exception as exc:
        print(f"[EPSS] Erreur pour {cve_id}: {exc}")
        return 0.0