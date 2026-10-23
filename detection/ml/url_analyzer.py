"""URL risk analysis using transparent, rule-based features.

Every rule is deterministic and unit-testable. We never fetch or visit the
submitted URL. Risk is a weighted sum of triggered features (a heuristic score,
explicitly NOT a probability). Optional external reputation lookup is isolated
in :mod:`detection.ml.url_reputation` and disabled unless configured.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List, Tuple
from urllib.parse import urlparse

from .result import FRAUD, INCONCLUSIVE, LEGITIMATE, AnalysisResult

# Suspicious top-level domains commonly abused in phishing (illustrative subset).
RISKY_TLDS = {".xyz", ".top", ".biz", ".click", ".tk", ".ml", ".gq", ".cf", ".country", ".work"}
# Brand-like strings used in misleading-domain checks (substring match).
BRAND_TOKENS = ["paypal", "google", "apple", "microsoft", "amazon", "bank", "netflix", "facebook", "instagram"]

# A single "suspicious character" set used to spot obfuscation.
SUSPICIOUS_CHARS = re.compile(r"[^A-Za-z0-9._~/?#=%&:+-]")

# Thresholds for the heuristic score.
FRAUD_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.3


def _has_ip_host(netloc: str) -> bool:
    host = netloc.split("@")[-1].split(":")[0]
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _misleading_brand(host: str) -> str | None:
    """Brand token appears in the domain but not as the real registrable domain.

    Detects lookalikes such as 'paypa1' or brand names stuffed into a foreign
    domain like 'paypal-security.evil.xyz'.
    """
    host_l = host.lower()
    for brand in BRAND_TOKENS:
        if brand in host_l:
            # Legit use: brand is part of the registered domain itself.
            reg = _registered_domain(host_l)
            if brand in reg and not _has_ip_host(host_l):
                # Still flag lookalike substitutions (e.g. paypa1 vs paypal).
                pass
            # Flag when brand appears with a hyphen/subdomain on a risky domain.
            if any(sep in host_l for sep in [f"{brand}-", f"-{brand}", f"{brand}"]):
                if reg.split(".")[0] != brand:
                    return brand
    # Character-substitution lookalikes: paypal -> paypa1, apple -> apprve style.
    for brand in BRAND_TOKENS:
        if len(brand) >= 5:
            lookalike = re.sub(brand[2], "1", brand)  # crude digit substitution
            if lookalike != brand and lookalike in host.lower():
                return brand
    return None


def _extract_features(raw_url: str) -> List[Tuple[str, float, str]]:
    """Return a list of (name, weight, human-readable description) tuples."""
    signals: List[Tuple[str, float, str]] = []
    url = raw_url.strip()

    parsed = urlparse(url if "://" in url else f"http://{url}")
    netloc = parsed.netloc
    host = netloc.split("@")[-1].split(":")[0]

    if parsed.scheme == "":
        signals.append(("no_scheme", 0.1, "URL has no explicit scheme"))
    elif parsed.scheme == "http":
        signals.append(("insecure_http", 0.1, "Uses insecure http://"))

    if len(url) > 100:
        signals.append(("very_long_url", 0.15, f"Very long URL ({len(url)} chars)"))
    elif len(url) > 75:
        signals.append(("long_url", 0.08, f"Unusually long URL ({len(url)} chars)"))

    if _has_ip_host(netloc):
        signals.append(("ip_address_host", 0.35, "Host is a raw IP address"))

    if "@" in netloc:
        signals.append(("credentials_in_url", 0.35, "URL embeds '@' credentials (host spoofing)"))

    if parsed.port and parsed.port not in (80, 443):
        signals.append(("nonstandard_port", 0.2, f"Non-standard port {parsed.port}"))

    if SUSPICIOUS_CHARS.search(netloc):
        signals.append(("suspicious_characters", 0.2, "Suspicious characters in host"))

    if host.count(".") >= 4:
        signals.append(("excessive_subdomains", 0.15, "Excessive subdomain depth"))

    for tld in RISKY_TLDS:
        if host.lower().endswith(tld):
            signals.append(("risky_tld", 0.25, f"High-risk TLD '{tld}'"))
            break

    brand = _misleading_brand(host)
    if brand:
        signals.append(("misleading_domain", 0.35, f"Domain impersonates '{brand}'"))

    if re.search(r"/(login|signin|verify|secure|update|account|password)", url, re.I):
        signals.append(("credential_path_keyword", 0.15, "Path contains credential-related keyword"))

    if host.count("-") >= 3:
        signals.append(("hyphen_stuffed_host", 0.15, "Host is hyphen-stuffed"))

    return signals


def analyze_url(raw_url: str, include_reputation: bool = False) -> AnalysisResult:
    """Score a URL using transparent rules. Does not visit the URL."""
    if not raw_url or not raw_url.strip():
        raise ValueError("URL must not be empty.")

    features = _extract_features(raw_url)

    # The score is a saturating sum of weights, capped at 1.0.
    score = min(1.0, round(sum(w for _, w, _ in features), 4))
    reasons = [desc for _, _, desc in features]

    if score >= FRAUD_THRESHOLD:
        classification = FRAUD
    elif score >= SUSPICIOUS_THRESHOLD:
        classification = INCONCLUSIVE
    else:
        classification = LEGITIMATE

    recommendations = _recommendations(classification, features)

    detail = {
        "triggered_rules": [name for name, _, _ in features],
        "parsed_host": raw_url,
    }

    # Optional external reputation check (network, off by default).
    if include_reputation:
        from . import url_reputation

        rep = url_reputation.lookup_reputation(raw_url)
        if rep is not None:
            detail["reputation"] = rep
            if rep.get("unsafe"):
                classification = FRAUD
                score = 1.0
                reasons.append(f"Reputation provider flagged URL: {rep.get('verdict')}")

    return AnalysisResult(
        channel="url",
        classification=classification,
        risk_score=score,
        score_kind="heuristic",
        signals=reasons,
        recommendations=recommendations,
        source="url_rules",
        model_version=None,
        detail=detail,
    )


def _recommendations(classification: str, features) -> List[str]:
    recs: List[str] = []
    names = {n for n, _, _ in features}
    if classification == FRAUD:
        recs.append("Do not open this URL. Multiple high-risk indicators present.")
    elif classification == INCONCLUSIVE:
        recs.append("Handle with caution. Verify the destination before entering data.")
    else:
        recs.append("No significant URL risk indicators detected.")
    if "ip_address_host" in names:
        recs.append("Prefer never entering credentials into an IP-address site.")
    if "misleading_domain" in names:
        recs.append("The domain appears to impersonate a known brand.")
    if "insecure_http" in names:
        recs.append("Connection is not encrypted (http).")
    return recs
