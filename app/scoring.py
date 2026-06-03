def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def score_vulnerability(
    cvss: float,
    epss: float,
    is_kev: bool,
    asset_match: bool = True,
) -> tuple[int, str, int]:
    score = 0

    if is_kev:
        score += 40

    if cvss >= 9:
        score += 30
    elif cvss >= 7:
        score += 20
    elif cvss >= 4:
        score += 10

    if epss >= 0.7:
        score += 25
    elif epss >= 0.3:
        score += 15
    elif epss >= 0.1:
        score += 5

    if asset_match:
        score += 10

    score = min(score, 100)
    severity = severity_from_score(score)

    confidence = 80
    if is_kev:
        confidence = 95
    elif epss >= 0.3:
        confidence = 85

    return score, severity, confidence