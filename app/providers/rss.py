import feedparser
import requests


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml,application/atom+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
}


def fetch_rss_feed(url: str, timeout: int = 15) -> list[dict]:
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()
        feed = feedparser.parse(response.content)
    except Exception as exc:
        print(f"[RSS] Erreur pour {url}: {exc}")
        return []

    items = []

    for entry in feed.entries:
        items.append(
            {
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "summary": entry.get("summary", ""),
                "published": entry.get("published", ""),
                "published_parsed": entry.get("published_parsed"),
                "updated": entry.get("updated", ""),
                "updated_parsed": entry.get("updated_parsed"),
            }
        )

    return items
