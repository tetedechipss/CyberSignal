from app.models import CVE

MISSING_VALUE = "Non disponible"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail"


def display_cpe_name(value: str) -> str:
    return value.replace("_", " ").strip().title()


def display_cve_products(
    products: list[tuple[str, str]],
    *,
    max_pairs: int = 5,
) -> tuple[str, str]:
    if not products:
        return MISSING_VALUE, MISSING_VALUE

    visible = products[:max_pairs]
    vendors = " ; ".join(display_cpe_name(vendor) for vendor, _ in visible)
    product_names = " ; ".join(display_cpe_name(product) for _, product in visible)
    if len(products) > len(visible):
        suffix = f" ; +{len(products) - len(visible)}"
        vendors += suffix
        product_names += suffix
    return vendors, product_names


def format_cve_row(
    cve: CVE | None,
    products: list[tuple[str, str]],
    *,
    technology: str | None = None,
    fallback_cve_id: str | None = None,
    cve_as_link: bool = False,
) -> dict:
    cve_id = cve.cve_id if cve else fallback_cve_id
    vendors, product_names = display_cve_products(products)
    row = {}
    if technology is not None:
        row["Technology"] = technology or MISSING_VALUE
    row.update(
        {
            "CVE": (
                f"{NVD_CVE_URL}/{cve_id}"
                if cve_as_link and cve_id
                else cve_id or MISSING_VALUE
            ),
            "Date publication": (
                cve.published_at[:10]
                if cve and cve.published_at
                else MISSING_VALUE
            ),
            "Vendor": vendors,
            "Product": product_names,
            "CVSS": cve.cvss if cve and cve.cvss is not None else MISSING_VALUE,
            "EPSS": cve.epss if cve and cve.epss is not None else MISSING_VALUE,
            "EPSS percentile": (
                cve.epss_percentile
                if cve and cve.epss_percentile is not None
                else MISSING_VALUE
            ),
            "KEV": cve.kev if cve else False,
        }
    )
    return row


def format_company_finding_rows(
    records: list[dict],
    *,
    cve_as_link: bool = False,
) -> list[dict]:
    return [
        format_cve_row(
            record["cve"],
            record["products"],
            technology=record["finding"].related_asset or MISSING_VALUE,
            fallback_cve_id=record["finding"].cve_id,
            cve_as_link=cve_as_link,
        )
        for record in records
    ]
