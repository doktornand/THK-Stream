"""
THK - Multi-Source Threat Intelligence Analyzer
Core engine (adapted from TH-K1e.py for Streamlit compatibility)
"""

import asyncio
import aiohttp
import json
import os
import re
import base64
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import ipaddress


def safe_get(data: Dict, key: str, default: str = "N/A", max_len: Optional[int] = None) -> str:
    if not isinstance(data, dict):
        return default
    value = data.get(key)
    if value is None or value == "":
        return default
    result = str(value)
    if max_len and len(result) > max_len:
        result = result[:max_len] + "..."
    return result


API_CONFIG = {
    "abuseipdb":      {"url": "https://api.abuseipdb.com/api/v2/check"},
    "alienvault":     {"url": "https://otx.alienvault.com/api/v1/indicators"},
    "greynoise":      {"url": "https://api.greynoise.io/v3/community"},
    "leakix":         {"url": "https://leakix.net"},
    "censys":         {"url": "https://search.censys.io/api/v2/hosts"},
    "securitytrails": {"url": "https://api.securitytrails.com/v1"},
    "shodan":         {"url": "https://api.shodan.io"},
    "virustotal":     {"url": "https://www.virustotal.com/api/v3"},
    "hetrixtools":    {"url": "https://api.hetrixtools.com/v2"},
}


@dataclass
class AnalysisResult:
    target: str
    target_type: str
    timestamp: str
    services: Dict[str, Any]
    risk_score: int
    risk_level: str
    summary: str
    factors: List[str]


class ThreatIntelligenceAnalyzer:
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
        self.session = None
        self.semaphore = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=45, connect=10)
        )
        self.semaphore = asyncio.Semaphore(5)
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    def is_ip(self, target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    async def _get(self, url: str, headers: Dict = None, params: Dict = None) -> tuple:
        try:
            async with self.semaphore:
                async with self.session.get(url, headers=headers, params=params) as r:
                    status = r.status
                    try:
                        body = await r.json(content_type=None)
                    except Exception:
                        body = await r.text()
                    return status, body
        except Exception as e:
            return None, str(e)

    # ── Services ──────────────────────────────────────────────────────────────

    async def query_abuseipdb(self, target: str) -> Dict:
        if not self.is_ip(target):
            return {"status": "skipped", "reason": "IPs uniquement"}
        key = self.api_keys.get("abuseipdb")
        if not key:
            return {"status": "no_key"}
        headers = {"Key": key, "Accept": "application/json"}
        params = {"ipAddress": target, "maxAgeInDays": "90", "verbose": ""}
        status, data = await self._get(API_CONFIG["abuseipdb"]["url"], headers=headers, params=params)
        if status == 200 and isinstance(data, dict):
            d = data.get("data") or {}
            return {
                "status": "success",
                "abuse_confidence": d.get("abuseConfidencePercentage") or 0,
                "total_reports": d.get("totalReports") or 0,
                "last_reported": d.get("lastReportedAt"),
                "country": d.get("countryCode") or "N/A",
                "usage_type": d.get("usageType") or "N/A",
                "isp": d.get("isp") or "N/A",
            }
        return {"status": "error", "code": status}

    async def query_alienvault(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("alienvault")
        if not key:
            return {"status": "no_key"}
        headers = {"X-OTX-API-KEY": key}
        endpoint = f"IPv4/{target}" if target_type == "ip" else f"domain/{target}"
        url = f"{API_CONFIG['alienvault']['url']}/{endpoint}/general"
        status, data = await self._get(url, headers=headers)
        if status == 200 and isinstance(data, dict):
            pulses = (data.get("pulse_info") or {}).get("pulses") or []
            tags = list(set(t for p in pulses[:5] for t in (p.get("tags") or [])))
            return {"status": "success", "pulse_count": len(pulses), "tags": tags[:10]}
        if status == 404:
            return {"status": "success", "pulse_count": 0, "tags": []}
        return {"status": "error", "code": status}

    async def query_greynoise(self, target: str) -> Dict:
        if not self.is_ip(target):
            return {"status": "skipped", "reason": "IPs uniquement"}
        key = self.api_keys.get("greynoise")
        if not key:
            return {"status": "no_key"}
        headers = {"key": key, "Accept": "application/json"}
        url = f"{API_CONFIG['greynoise']['url']}/{target}"
        status, data = await self._get(url, headers=headers)
        if status == 200 and isinstance(data, dict):
            return {
                "status": "success",
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification") or "N/A",
                "name": data.get("name") or "N/A",
                "last_seen": data.get("last_seen") or "N/A",
            }
        if status == 404:
            return {"status": "success", "noise": False, "classification": "unknown"}
        return {"status": "error", "code": status}

    async def query_leakix(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("leakix")
        if not key:
            return {"status": "no_key"}
        headers = {"api-key": key, "Accept": "application/json"}
        endpoint = f"host/{target}" if target_type == "ip" else f"domain/{target}"
        url = f"{API_CONFIG['leakix']['url']}/{endpoint}"
        status, data = await self._get(url, headers=headers)
        if status == 200 and isinstance(data, dict):
            services = data.get("Services") or data.get("services") or []
            leaks = data.get("Leaks") or data.get("leaks") or []
            return {"status": "success", "services_found": len(services), "leaks": len(leaks)}
        return {"status": "error", "code": status}

    async def query_censys(self, target: str) -> Dict:
        if not self.is_ip(target):
            return {"status": "skipped", "reason": "IPs uniquement"}
        key = self.api_keys.get("censys")
        if not key or ":" not in key:
            return {"status": "no_key"}
        auth = base64.b64encode(key.encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
        url = f"{API_CONFIG['censys']['url']}/{target}"
        status, data = await self._get(url, headers=headers)
        if status == 200 and isinstance(data, dict):
            result = data.get("result") or {}
            svcs = [{"port": s.get("port"), "name": s.get("service_name")} for s in (result.get("services") or [])[:5]]
            return {
                "status": "success",
                "services": svcs,
                "os": (result.get("operating_system") or {}).get("product") or "N/A",
                "country": (result.get("location") or {}).get("country") or "N/A",
            }
        return {"status": "error", "code": status}

    async def query_securitytrails(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("securitytrails")
        if not key:
            return {"status": "no_key"}
        headers = {"APIKEY": key}
        if target_type == "domain":
            url = f"{API_CONFIG['securitytrails']['url']}/domain/{target}"
            status, data = await self._get(url, headers=headers)
            if status == 200 and isinstance(data, dict):
                dns = data.get("current_dns") or {}
                a_records = (dns.get("a") or {}).get("records", []) if isinstance(dns.get("a"), dict) else []
                return {
                    "status": "success",
                    "subdomains": len(data.get("subdomains") or []),
                    "a_records": [r.get("ip") for r in a_records[:3]],
                }
        else:
            url = f"{API_CONFIG['securitytrails']['url']}/domains/list"
            status, data = await self._get(url, headers=headers, params={"filter": f"ipv4={target}"})
            if status == 200 and isinstance(data, dict):
                return {"status": "success", "domains_hosted": len(data.get("records") or [])}
        return {"status": "error", "code": status}

    async def query_shodan(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("shodan")
        if not key:
            return {"status": "no_key"}
        if target_type == "ip":
            url = f"{API_CONFIG['shodan']['url']}/shodan/host/{target}?key={key}"
            status, data = await self._get(url)
            if status == 200 and isinstance(data, dict):
                vulns = data.get("vulns") or {}
                vulns_list = list(vulns.keys())[:5] if isinstance(vulns, dict) else (vulns[:5] if isinstance(vulns, list) else [])
                return {
                    "status": "success",
                    "ports": list(set(item.get("port") for item in (data.get("data") or []) if item.get("port")))[:10],
                    "tags": (data.get("tags") or [])[:5],
                    "vulns": vulns_list,
                    "isp": data.get("isp") or "N/A",
                    "os": data.get("os") or "N/A",
                }
            if status == 404:
                return {"status": "success", "ports": [], "tags": [], "vulns": [], "note": "Not in Shodan"}
        else:
            url = f"{API_CONFIG['shodan']['url']}/dns/domain/{target}?key={key}"
            status, data = await self._get(url)
            if status == 200 and isinstance(data, dict):
                subs = [s.get("subdomain") for s in (data.get("subdomains") or [])[:10] if s.get("subdomain")]
                return {"status": "success", "subdomains": subs}
        return {"status": "error", "code": status}

    async def query_virustotal(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("virustotal")
        if not key:
            return {"status": "no_key"}
        headers = {"x-apikey": key, "Accept": "application/json"}
        endpoint = f"{'ip_addresses' if target_type == 'ip' else 'domains'}/{target}"
        url = f"{API_CONFIG['virustotal']['url']}/{endpoint}"
        status, data = await self._get(url, headers=headers)
        if status == 200 and isinstance(data, dict):
            attrs = (data.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            return {
                "status": "success",
                "malicious": stats.get("malicious") or 0,
                "suspicious": stats.get("suspicious") or 0,
                "harmless": stats.get("harmless") or 0,
                "undetected": stats.get("undetected") or 0,
                "total": sum(stats.values()) if stats else 0,
                "reputation": attrs.get("reputation") or 0,
                "country": attrs.get("country") or "N/A",
                "owner": attrs.get("as_owner" if target_type == "ip" else "registrar") or "N/A",
                "tags": (attrs.get("tags") or [])[:5],
            }
        if status == 404:
            return {"status": "success", "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "total": 0}
        return {"status": "error", "code": status}

    async def query_hetrixtools(self, target: str, target_type: str) -> Dict:
        key = self.api_keys.get("hetrixtools")
        if not key:
            return {"status": "no_key"}
        base_url = API_CONFIG["hetrixtools"]["url"]
        if target_type == "ip":
            url = f"{base_url}/{key}/rbl-check/ipv4/{target}/"
            status, data = await self._get(url)
            if status == 200 and isinstance(data, dict) and data.get("status") != "ERROR":
                bl = data.get("blacklisted_count") or 0
                return {
                    "status": "success",
                    "blacklisted_count": bl,
                    "total_checked": data.get("list_count") or 0,
                    "blacklists": [b.get("rbl") for b in (data.get("blacklisted_on") or [])[:5]],
                    "risk_level": "HIGH" if bl > 5 else "MEDIUM" if bl > 0 else "LOW",
                }
        else:
            url = f"{base_url}/{key}/domain-check/{target}/"
            status, data = await self._get(url)
            if status == 200 and isinstance(data, dict) and data.get("status") != "ERROR":
                return {
                    "status": "success",
                    "blacklisted": data.get("blacklisted") or False,
                    "blacklist_count": data.get("blacklist_count") or 0,
                    "spf": data.get("spf_record") or "N/A",
                    "dmarc": data.get("dmarc_record") or "N/A",
                }
        return {"status": "error", "code": status}

    # ── Risk scoring ───────────────────────────────────────────────────────────

    def calculate_risk(self, services: Dict) -> tuple:
        score = 0
        factors = []

        vt = services.get("virustotal", {})
        if vt.get("status") == "success":
            mal = vt.get("malicious") or 0
            susp = vt.get("suspicious") or 0
            total = vt.get("total") or 1
            ratio = (mal + susp * 0.5) / total if total > 0 else 0
            if ratio > 0.3:
                score += 45; factors.append(f"VirusTotal : {mal} malveillants + {susp} suspects")
            elif ratio > 0.1:
                score += 30; factors.append(f"VirusTotal : {mal} détections")
            elif mal > 0:
                score += 15; factors.append(f"VirusTotal : {mal} détection")

        ab = services.get("abuseipdb", {})
        if ab.get("status") == "success":
            reports = ab.get("total_reports") or 0
            conf = ab.get("abuse_confidence") or 0
            if reports > 1000:
                score += 25; factors.append(f"AbuseIPDB : {reports} signalements")
            elif reports > 100:
                score += 15; factors.append(f"AbuseIPDB : {reports} signalements")
            score += min(conf * 0.2, 10)

        ht = services.get("hetrixtools", {})
        if ht.get("status") == "success":
            bl = ht.get("blacklisted_count") or ht.get("blacklist_count") or 0
            if bl > 10:
                score += 20; factors.append(f"Blacklists RBL : {bl} listes")
            elif bl > 0:
                score += 10; factors.append(f"Blacklists RBL : {bl} listes")

        av = services.get("alienvault", {})
        if av.get("status") == "success":
            pulses = av.get("pulse_count") or 0
            if pulses > 20:
                score += 15; factors.append(f"OTX : {pulses} pulses")
            elif pulses > 5:
                score += 8; factors.append(f"OTX : {pulses} pulses")

        gn = services.get("greynoise", {})
        if gn.get("status") == "success":
            if gn.get("classification") == "malicious":
                score += 15; factors.append("GreyNoise : Malveillant")

        sh = services.get("shodan", {})
        if sh.get("status") == "success":
            vulns = sh.get("vulns") or []
            if len(vulns) > 0:
                score += min(len(vulns) * 3, 15)
                factors.append(f"Shodan : {len(vulns)} CVE(s)")

        score = min(score, 100)
        if score > 75:
            level = "CRITIQUE"
        elif score > 50:
            level = "ÉLEVÉ"
        elif score > 25:
            level = "MOYEN"
        else:
            level = "FAIBLE"

        return score, level, factors

    # ── Main analysis ──────────────────────────────────────────────────────────

    async def analyze_target(self, target: str) -> AnalysisResult:
        target = target.strip()
        target_type = "ip" if self.is_ip(target) else "domain"

        tasks = {
            "abuseipdb":      self.query_abuseipdb(target),
            "alienvault":     self.query_alienvault(target, target_type),
            "greynoise":      self.query_greynoise(target),
            "leakix":         self.query_leakix(target, target_type),
            "censys":         self.query_censys(target),
            "securitytrails": self.query_securitytrails(target, target_type),
            "shodan":         self.query_shodan(target, target_type),
            "virustotal":     self.query_virustotal(target, target_type),
            "hetrixtools":    self.query_hetrixtools(target, target_type),
        }

        services = {}
        for svc, coro in tasks.items():
            try:
                services[svc] = await asyncio.wait_for(coro, timeout=40.0)
            except asyncio.TimeoutError:
                services[svc] = {"status": "timeout"}
            except Exception as e:
                services[svc] = {"status": "error", "reason": str(e)}

        score, level, factors = self.calculate_risk(services)
        summary = f"{level} ({score}/100) — " + (" | ".join(factors[:3]) if factors else "Aucun indicateur négatif")

        return AnalysisResult(
            target=target,
            target_type=target_type,
            timestamp=datetime.now().isoformat(),
            services=services,
            risk_score=score,
            risk_level=level,
            summary=summary,
            factors=factors,
        )

    async def analyze_targets(self, targets: List[str]) -> List[AnalysisResult]:
        results = []
        for target in targets:
            if target.strip():
                result = await self.analyze_target(target.strip())
                results.append(result)
        return results


def run_analysis(targets: List[str], api_keys: Dict[str, str]) -> List[AnalysisResult]:
    """Synchronous wrapper for Streamlit compatibility."""
    async def _run():
        async with ThreatIntelligenceAnalyzer(api_keys) as analyzer:
            return await analyzer.analyze_targets(targets)
    return asyncio.run(_run())
