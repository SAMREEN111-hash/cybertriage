"""
AbuseIPDB Enrichment Service
=============================
Queries AbuseIPDB API to enrich alert source IPs with:
  - Abuse confidence score (0-100)
  - Country of origin
  - Tor exit node flag

Falls back gracefully if API key not configured.
"""

import aiohttp
import ipaddress
from typing import Optional
from app.core.config import settings


KNOWN_MALICIOUS = {
    "185.220.101.45", "45.142.212.100", "194.165.16.11",
    "91.92.136.196", "5.188.206.14", "192.241.220.115",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


async def enrich_ip(ip: str) -> dict:
    """
    Returns enrichment dict:
      { abuse_score, country, is_tor }
    
    Priority:
      1. Private IP → skip (score 0)
      2. Known IOC list → instant high score
      3. AbuseIPDB API (if key configured)
      4. Default zeros
    """
    result = {"abuse_score": 0.0, "country": "Unknown", "is_tor": "false"}

    if _is_private(ip):
        result["country"] = "Internal"
        return result

    if ip in KNOWN_MALICIOUS:
        result["abuse_score"] = 95.0
        result["country"] = "Known Threat Actor"
        return result

    if not settings.ABUSEIPDB_API_KEY:
        return result

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": settings.ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    data = (await resp.json()).get("data", {})
                    result["abuse_score"] = float(data.get("abuseConfidenceScore", 0))
                    result["country"] = data.get("countryCode", "Unknown")
                    result["is_tor"] = str(data.get("isTor", False)).lower()
    except Exception:
        pass  # Graceful degradation — triage works without enrichment

    return result
