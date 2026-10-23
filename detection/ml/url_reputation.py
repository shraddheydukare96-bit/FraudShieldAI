"""Optional external URL reputation lookup.

Design and safety:
  * DISABLED unless an API key is present AND ``URL_REPUTATION_ENABLED=True``.
  * We NEVER visit or download the submitted URL. This uses Google's Safe
    Browsing *Lookup* API, which only sends the URL string to Google's API
    endpoint for a reputation verdict.
  * Any failure (no key, network error, timeout) returns ``None`` so callers
    treat reputation as simply unavailable rather than "safe".

Configure via environment variables (see .env.example):
  URL_REPUTATION_ENABLED   True to enable network lookups (default False)
  GOOGLE_SAFE_BROWSING_KEY Safe Browsing API key
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
)
DEFAULT_TIMEOUT_SECONDS = 5


def is_configured() -> bool:
    return (
        os.getenv("URL_REPUTATION_ENABLED", "False").strip().lower() in {"1", "true", "yes", "on"}
        and bool(os.getenv("GOOGLE_SAFE_BROWSING_KEY"))
    )


def lookup_reputation(url: str) -> Optional[Dict[str, Any]]:
    """Return a verdict dict, or None when lookup is not configured/failed.

    Result dict keys: ``unsafe`` (bool), ``verdict`` (str), ``provider`` (str).
    """
    if not is_configured():
        return None

    key = os.environ["GOOGLE_SAFE_BROWSING_KEY"]
    payload = {
        "client": {"clientId": "fraudshield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    request = urllib.request.Request(
        SAFE_BROWSING_ENDPOINT.format(key=urllib.parse.quote(key)),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        # Honest behaviour: unavailable, not "safe".
        return None

    matches = body.get("matches", [])
    unsafe = bool(matches)
    verdict = matches[0].get("threatType", "UNKNOWN") if unsafe else "clean"
    return {"unsafe": unsafe, "verdict": verdict, "provider": "google_safe_browsing"}
