from functools import lru_cache
from pathlib import Path

import yaml

from app.services.cve_repository import normalize_name

MAPPING_PATH = Path(__file__).resolve().parents[2] / "config" / "technology_mappings.yaml"


@lru_cache(maxsize=1)
def load_technology_mappings() -> dict[str, dict]:
    if not MAPPING_PATH.exists():
        return {}
    with MAPPING_PATH.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return {normalize_name(key): value or {} for key, value in data.items()}


def resolve_technology(technology: str) -> dict:
    normalized = normalize_name(technology)
    mapping = load_technology_mappings().get(normalized, {})
    vendor = mapping.get("vendor")
    products = mapping.get("products") or []
    return {
        "vendor": normalize_name(vendor) if vendor else None,
        "products": [normalize_name(product) for product in products],
        "technology": normalized,
        "mapped": bool(mapping),
    }
