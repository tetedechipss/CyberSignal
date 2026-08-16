import csv
import calendar
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import escape, unescape
from pathlib import Path
from urllib.parse import urlparse

from app.providers.rss import fetch_rss_feed


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCES_PATH = ROOT / "config" / "sources.csv"
DEFAULT_BLOCKLIST_PATH = ROOT / "config" / "blocklist_words.txt"

CONFIDENCE_WEIGHTS = {
    1: 1.0,
    2: 0.5,
    3: 0.2,
}

ZONE_COUNTRY_CODES = {
    "Europe": {
        "AT",
        "BE",
        "CH",
        "DE",
        "DK",
        "ES",
        "FI",
        "FR",
        "GB",
        "GR",
        "HR",
        "IE",
        "IT",
        "LU",
        "LV",
        "NL",
        "PL",
        "RO",
        "SE",
        "SI",
        "SK",
        "UA",
    },
    "Amerique du Nord": {"CA", "US"},
    "Asie-Pacifique": {"AU", "HK", "IN", "JP"},
    "Moyen-Orient et Afrique": {"DZ", "EG", "IL", "NG", "ZA"},
}

ATTACKER_PATTERNS = [
    r"\bAPT\d+\b",
    r"\bFIN\d+\b",
    r"\bHFG\d+\b",
    r"\bTA\d{3,}\b",
    r"\bUNC\d{3,}\b",
]

STOP_WORDS = {
    "about",
    "after",
    "again",
    "against",
    "avec",
    "been",
    "before",
    "being",
    "cela",
    "cette",
    "chez",
    "click",
    "could",
    "dans",
    "data",
    "des",
    "does",
    "from",
    "have",
    "having",
    "into",
    "leur",
    "mais",
    "more",
    "news",
    "notre",
    "nous",
    "pour",
    "read",
    "sont",
    "that",
    "their",
    "these",
    "this",
    "using",
    "were",
    "when",
    "where",
    "with",
    "would",
}

BANNED_WORDS = STOP_WORDS | {
    "alert",
    "alerts",
    "also",
    "already",
    "article",
    "articles",
    "attack",
    "attacks",
    "address",
    "addresses",
    "blog",
    "breach",
    "campaign",
    "critical",
    "cyber",
    "cybersecurity",
    "details",
    "email",
    "emails",
    "exploit",
    "exploited",
    "feed",
    "flaw",
    "flaws",
    "hacker",
    "hackers",
    "latest",
    "last",
    "malicious",
    "malware",
    "patch",
    "patched",
    "phone",
    "published",
    "read",
    "remote",
    "report",
    "research",
    "risk",
    "security",
    "threat",
    "threats",
    "update",
    "updates",
    "vulnerability",
    "vulnerabilities",
    "zero",
}

_BLOCKLIST_CACHE: set[str] | None = None

DOMAIN_EXTENSIONS = {
    ".com",
    ".net",
    ".org",
    ".io",
    ".co",
    ".gov",
    ".edu",
    ".fr",
    ".uk",
    ".de",
    ".es",
    ".it",
    ".au",
    ".ca",
    ".jp",
    ".in",
    ".ru",
    ".cn",
}

IMPORTANT_PRODUCTS = {
    "active directory",
    "adobe",
    "android",
    "apache",
    "apple",
    "atlassian",
    "azure",
    "chrome",
    "cisco",
    "citrix",
    "confluence",
    "debian",
    "edge",
    "exchange",
    "firefox",
    "fortinet",
    "github",
    "gitlab",
    "google",
    "ios",
    "ivanti",
    "jenkins",
    "linux",
    "microsoft",
    "office",
    "openssl",
    "oracle",
    "palo alto",
    "python",
    "sap",
    "sharepoint",
    "sonicwall",
    "vmware",
    "windows",
    "wordpress",
}


@dataclass(frozen=True)
class TrendSource:
    confident: int
    url: str
    country: str
    country_code: str

    @property
    def domain(self) -> str:
        domain = urlparse(self.url).netloc.lower()
        return domain[4:] if domain.startswith("www.") else domain

    @property
    def weight(self) -> float:
        return CONFIDENCE_WEIGHTS.get(self.confident, CONFIDENCE_WEIGHTS[3])


def load_trend_sources(path: Path = DEFAULT_SOURCES_PATH) -> list[TrendSource]:
    if not path.exists():
        print(f"[Trends] sources.csv introuvable: {path}")
        return []

    sources = []
    seen_urls = set()

    try:
        with path.open("r", encoding="utf-8", newline="") as csv_file:
            reader = csv.DictReader(csv_file, delimiter=";")

            for row in reader:
                url = (row.get("url") or "").strip()

                if not url or url in seen_urls:
                    continue

                try:
                    confident = int((row.get("confident") or "3").strip())
                except ValueError:
                    confident = 3

                confident = min(max(confident, 1), 3)
                seen_urls.add(url)
                sources.append(
                    TrendSource(
                        confident=confident,
                        url=url,
                        country=(row.get("country") or "").strip() or "Unknown",
                        country_code=(row.get("country_code") or "").strip().upper(),
                    )
                )
    except Exception as exc:
        print(f"[Trends] Erreur lecture sources.csv: {exc}")
        return []

    return sources


def _normalize_blocklist_word(word: str) -> str:
    return re.sub(r"\s+", " ", (word or "").strip()).casefold()


def load_blocklist_words(path: Path = DEFAULT_BLOCKLIST_PATH) -> set[str]:
    words = {_normalize_blocklist_word(word) for word in BANNED_WORDS}
    words = {word for word in words if word}

    if not path.exists():
        print(f"[Trends] blocklist introuvable: {path}")
        return words

    try:
        with path.open("r", encoding="utf-8") as blocklist_file:
            for line in blocklist_file:
                word = _normalize_blocklist_word(line)

                if word:
                    words.add(word)
    except Exception as exc:
        print(f"[Trends] Erreur lecture blocklist: {exc}")

    return words


def get_blocklist_words() -> set[str]:
    global _BLOCKLIST_CACHE

    if _BLOCKLIST_CACHE is None:
        _BLOCKLIST_CACHE = load_blocklist_words()

    return _BLOCKLIST_CACHE


def clear_blocklist_cache() -> None:
    global _BLOCKLIST_CACHE
    _BLOCKLIST_CACHE = None


def get_blocklist_size() -> int:
    return len(get_blocklist_words())


def add_blocklist_word(word: str, path: Path = DEFAULT_BLOCKLIST_PATH) -> bool:
    cleaned = re.sub(r"\s+", " ", (word or "").strip())
    normalized = _normalize_blocklist_word(cleaned)

    if not normalized:
        return False

    if normalized in get_blocklist_words():
        return False

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8", newline="\n") as blocklist_file:
        blocklist_file.write(f"{cleaned}\n")

    clear_blocklist_cache()
    return True


def is_blocked_word(word: str) -> bool:
    normalized = _normalize_blocklist_word(word)

    if not normalized:
        return True

    if re.fullmatch(r"cve-\d{4}-\d{4,7}", normalized):
        return False

    if re.fullmatch(r"(apt|fin|hfg|ta|unc)\d+", normalized):
        return False

    blocklist = get_blocklist_words()

    if normalized in blocklist:
        return True

    parts = [
        part
        for part in re.split(r"\s+", normalized)
        if part
    ]

    return len(parts) > 1 and any(part in blocklist for part in parts)


def get_country_filter_options(sources: list[TrendSource]) -> list[str]:
    countries = sorted({source.country for source in sources if source.country})
    zones = [f"Zone: {zone}" for zone in ZONE_COUNTRY_CODES]
    return ["Tous les pays", *zones, *countries]


def filter_sources(
    sources: list[TrendSource],
    country_filter: str = "Tous les pays",
    max_confident: int = 3,
    max_feeds: int = 25,
) -> list[TrendSource]:
    filtered = [
        source
        for source in sources
        if source.confident <= max_confident
    ]

    if country_filter.startswith("Zone: "):
        zone = country_filter.replace("Zone: ", "", 1)
        country_codes = ZONE_COUNTRY_CODES.get(zone, set())
        filtered = [
            source
            for source in filtered
            if source.country_code in country_codes
        ]
    elif country_filter != "Tous les pays":
        filtered = [
            source
            for source in filtered
            if source.country == country_filter
        ]

    filtered.sort(key=lambda source: (source.confident, source.country, source.domain))
    return filtered[:max_feeds]


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _parse_struct_time(value) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromtimestamp(calendar.timegm(value), tz=timezone.utc)
    except Exception:
        return None


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None

    try:
        parsed = parsedate_to_datetime(value)
    except Exception:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def get_article_datetime(item: dict) -> datetime | None:
    for key in ["published_parsed", "updated_parsed"]:
        parsed = _parse_struct_time(item.get(key))

        if parsed:
            return parsed

    for key in ["published", "updated"]:
        parsed = _parse_date(item.get(key, ""))

        if parsed:
            return parsed

    return None


def _is_in_time_range(
    value: datetime | None,
    start_at: datetime,
    end_at: datetime,
) -> bool:
    if value is None:
        return False

    normalized = ensure_utc(value)
    return start_at <= normalized <= end_at


def _matches_country_filter(item: dict, country_filter: str) -> bool:
    if country_filter.startswith("Zone: "):
        zone = country_filter.replace("Zone: ", "", 1)
        country_codes = ZONE_COUNTRY_CODES.get(zone, set())
        return item.get("country_code") in country_codes

    if country_filter != "Tous les pays":
        return item.get("country") == country_filter

    return True


def _format_article_datetime(value: datetime | None) -> str:
    if value is None:
        return "Date inconnue"

    return ensure_utc(value).strftime("%Y-%m-%d %H:%M UTC")


def _strip_html(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(value or ""))).strip()


def _clean_term(term: str) -> str:
    cleaned = re.sub(r"\s+", " ", term).strip(" -_:.,;()[]{}'\"")

    if not cleaned:
        return ""

    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cleaned, re.IGNORECASE):
        return cleaned.upper()

    if re.fullmatch(r"(APT|FIN|HFG|TA|UNC)\d+", cleaned, re.IGNORECASE):
        return cleaned.upper()

    known_product = cleaned.lower()
    if known_product in IMPORTANT_PRODUCTS:
        return " ".join(part.upper() if part in {"ios", "sap"} else part.title() for part in known_product.split())

    if cleaned.isupper():
        return cleaned

    return cleaned[:1].upper() + cleaned[1:]


def _is_banned_term(term: str) -> bool:
    lowered = term.lower().strip()

    if not lowered or len(lowered) <= 3:
        return True

    if is_blocked_word(term):
        return True

    if lowered.startswith(("http", "www.", "#", "@")):
        return True

    if any(lowered.endswith(extension) for extension in DOMAIN_EXTENSIONS):
        return True

    if re.fullmatch(r"\d+", lowered):
        return True

    if re.fullmatch(r"v?\d+(?:\.\d+){1,}", lowered):
        return True

    return False


def _add_product_matches(text: str, counter: Counter) -> None:
    lowered = text.lower()

    for product in IMPORTANT_PRODUCTS:
        if is_blocked_word(product):
            continue

        if re.search(rf"\b{re.escape(product)}\b", lowered):
            counter[_clean_term(product)] += 2


def extract_trend_terms(text: str) -> Counter:
    counter: Counter = Counter()
    cleaned_text = _strip_html(text)

    for cve_id in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", cleaned_text, flags=re.IGNORECASE):
        counter[cve_id.upper()] += 4

    for pattern in ATTACKER_PATTERNS:
        for attacker in re.findall(pattern, cleaned_text, flags=re.IGNORECASE):
            counter[attacker.upper()] += 4

    _add_product_matches(cleaned_text, counter)

    for phrase in re.findall(
        r"\b[A-Z][A-Za-z0-9.+-]{2,}(?:\s+[A-Z][A-Za-z0-9.+-]{2,}){0,2}\b",
        cleaned_text,
    ):
        term = _clean_term(phrase)

        if _is_banned_term(term):
            continue

        counter[term] += 2

    for token in re.findall(r"\b[a-zA-Z][a-zA-Z0-9.+-]{3,}\b", cleaned_text):
        term = _clean_term(token)

        if _is_banned_term(term):
            continue

        if token.lower() in IMPORTANT_PRODUCTS:
            continue

        counter[term] += 1

    return counter


def _article_key(item: dict, source: TrendSource) -> str:
    article_url = (item.get("link") or "").strip()
    title = _strip_html(item.get("title", ""))

    if article_url:
        return article_url

    return f"{source.domain}:{title}"


def collect_vulnerability_trend_events(
    max_articles_per_feed: int = 20,
    max_feeds: int = 100,
) -> dict:
    sources = load_trend_sources()
    sources.sort(key=lambda source: (source.confident, source.country, source.domain))
    events = []
    seen_articles = set()
    seen_terms = set()

    for source in sources[:max_feeds]:
        for item in fetch_rss_feed(source.url)[:max_articles_per_feed]:
            article_key = _article_key(item, source)
            title = _strip_html(item.get("title", ""))
            display_title = title or "Article sans titre"
            summary = _strip_html(item.get("summary", ""))
            published_at = get_article_datetime(item)
            term_counts = extract_trend_terms(f"{title} {title} {summary}")

            if not term_counts:
                continue

            seen_articles.add(article_key)

            for term, count in term_counts.items():
                seen_terms.add(term)
                events.append(
                    {
                        "term": term,
                        "count": count,
                        "article_key": article_key,
                        "title": display_title[:140],
                        "url": (item.get("link") or "").strip(),
                        "source": source.domain,
                        "country": source.country,
                        "country_code": source.country_code,
                        "confident": source.confident,
                        "source_weight": source.weight,
                        "published_at": published_at,
                        "published": _format_article_datetime(published_at),
                    }
                )

    return {
        "collected_at": datetime.now(timezone.utc),
        "events": events,
        "article_count": len(seen_articles),
        "term_count": len(seen_terms),
        "source_count": min(len(sources), max_feeds),
    }


def aggregate_trend_events(
    events: list[dict],
    start_at: datetime,
    end_at: datetime,
    max_terms: int = 60,
    max_confident: int = 3,
    country_filter: str = "Tous les pays",
    term_query: str = "",
) -> list[dict]:
    start_at = ensure_utc(start_at)
    end_at = ensure_utc(end_at)
    query = term_query.strip().lower()
    stats = {}

    for event in events:
        if is_blocked_word(event["term"]):
            continue

        if event["confident"] > max_confident:
            continue

        if not _matches_country_filter(event, country_filter):
            continue

        if not _is_in_time_range(event.get("published_at"), start_at, end_at):
            continue

        if query and query not in event["term"].lower():
            continue

        term = event["term"]

        if term not in stats:
            stats[term] = {
                "term": term,
                "occurrence": 0,
                "weighted_score": 0.0,
                "sources": set(),
                "articles": [],
                "article_keys": set(),
                "confidence_sum": 0,
                "confidence_count": 0,
            }

        stats[term]["occurrence"] += event["count"]
        stats[term]["weighted_score"] += event["count"] * event["source_weight"]
        stats[term]["sources"].add(event["source"])

        if event["article_key"] in stats[term]["article_keys"]:
            continue

        stats[term]["article_keys"].add(event["article_key"])
        stats[term]["confidence_sum"] += event["confident"]
        stats[term]["confidence_count"] += 1

        if len(stats[term]["articles"]) < 20:
            stats[term]["articles"].append(
                {
                    "title": event["title"] or "Article sans titre",
                    "url": event["url"],
                    "source": event["source"],
                    "country_code": event["country_code"],
                    "confident": event["confident"],
                    "published": event["published"],
                }
            )

    ranked_terms = sorted(
        stats.values(),
        key=lambda item: (item["weighted_score"], item["occurrence"], len(item["sources"])),
        reverse=True,
    )

    return [
        {
            "term": item["term"],
            "occurrence": item["occurrence"],
            "weighted_score": round(item["weighted_score"], 2),
            "average_confident": round(
                item["confidence_sum"] / item["confidence_count"],
                2,
            ) if item["confidence_count"] else None,
            "source_count": len(item["sources"]),
            "sources": ", ".join(sorted(item["sources"])),
            "articles": item["articles"],
        }
        for item in ranked_terms[:max_terms]
    ]


def build_vulnerability_trends(
    days: int = 7,
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    max_terms: int = 60,
    max_articles_per_feed: int = 20,
    max_feeds: int = 25,
    max_confident: int = 3,
    country_filter: str = "Tous les pays",
) -> list[dict]:
    end_at = ensure_utc(end_at or datetime.now(timezone.utc))
    start_at = ensure_utc(start_at or end_at - timedelta(days=days))
    dataset = collect_vulnerability_trend_events(
        max_articles_per_feed=max_articles_per_feed,
        max_feeds=max_feeds,
    )
    return aggregate_trend_events(
        dataset["events"],
        start_at=start_at,
        end_at=end_at,
        max_terms=max_terms,
        max_confident=max_confident,
        country_filter=country_filter,
    )


def render_word_cloud_html(terms: list[dict]) -> str:
    if not terms:
        return ""

    weights = [item["weighted_score"] for item in terms]
    min_weight = min(weights)
    max_weight = max(weights)
    spread = max(max_weight - min_weight, 1)
    chips = []

    for index, item in enumerate(terms):
        term = escape(item["term"])
        weight = item["weighted_score"]
        occurrence = item["occurrence"]
        ratio = (weight - min_weight) / spread
        font_size = 15 + ratio * 48
        opacity = 0.66 + ratio * 0.34
        hue = [199, 348, 145, 38, 262][index % 5]

        chips.append(
            (
                f'<span class="cloud-term" '
                f'style="font-size:{font_size:.1f}px;'
                f'opacity:{opacity:.2f};'
                f'color:hsl({hue}, 63%, 34%);" '
                f'title="{term}: score {weight}, occurrences {occurrence}">{term}</span>'
            )
        )

    return f"""
    <style>
        .word-cloud {{
            min-height: 430px;
            padding: 30px;
            border: 1px solid #d8dee9;
            border-radius: 8px;
            background: #ffffff;
            display: flex;
            flex-wrap: wrap;
            align-content: center;
            justify-content: center;
            gap: 12px 18px;
            overflow: hidden;
        }}
        .cloud-term {{
            display: inline-block;
            line-height: 1;
            font-weight: 750;
            letter-spacing: 0;
            white-space: nowrap;
        }}
    </style>
    <div class="word-cloud">
        {"".join(chips)}
    </div>
    """
