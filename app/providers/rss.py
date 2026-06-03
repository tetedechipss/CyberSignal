import feedparser


def fetch_rss_feed(url: str) -> list[dict]:
    try:
        feed = feedparser.parse(url)
    except Exception as exc:
        print(f"[RSS] Erreur: {exc}")
        return []

    items = []

    for entry in feed.entries:
        items.append(
            {
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "summary": entry.get("summary", ""),
                "published": entry.get("published", ""),
            }
        )

    return items