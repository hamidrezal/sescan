import re
import asyncio
import aiohttp
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from django.core.cache import cache
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError


class SecurityGrade(Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class HeaderAnalysis:
    name: str
    present: bool
    value: Optional[str] = None
    severity: str = "medium"  # critical, high, medium, low
    recommendation: str = ""
    cwe_id: Optional[str] = None


@dataclass
class SecurityReport:
    url: str
    status_code: int
    security_score: float
    grade: SecurityGrade
    total_headers: int
    present_headers: int
    missing_headers: List[str]
    present_headers_list: List[str]
    critical_missing: List[str]
    header_analysis: List[HeaderAnalysis]
    recommendations: List[str]
    raw_headers: Dict[str, str]
    ssl_info: Dict[str, any]
    scan_timestamp: float
    scan_duration: float


# Comprehensive security headers with priorities
SECURITY_HEADERS_CONFIG = {
    "Content-Security-Policy": {
        "severity": "critical",
        "cwe": "CWE-693",
        "recommendation": "Implement strict CSP with 'default-src https:' and avoid 'unsafe-inline'"
    },
    "Strict-Transport-Security": {
        "severity": "critical",
        "cwe": "CWE-523",
        "recommendation": "Add HSTS with max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "severity": "critical",
        "cwe": "CWE-1021",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking"
    },
    "X-Content-Type-Options": {
        "severity": "critical",
        "cwe": "CWE-693",
        "recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME type sniffing"
    },
    "Referrer-Policy": {
        "severity": "high",
        "cwe": "CWE-200",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin or no-referrer"
    },
    "Permissions-Policy": {
        "severity": "high",
        "cwe": "CWE-693",
        "recommendation": "Define Permissions-Policy to limit browser features (geolocation, camera, etc.)"
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "medium",
        "cwe": "CWE-346",
        "recommendation": "Set COEP: require-corp for cross-origin isolation"
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "medium",
        "cwe": "CWE-346",
        "recommendation": "Set COOP: same-origin to protect against cross-origin attacks"
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "medium",
        "cwe": "CWE-346",
        "recommendation": "Set CORP: same-origin to control cross-origin resource loading"
    },
    "Cache-Control": {
        "severity": "low",
        "cwe": "CWE-524",
        "recommendation": "Set Cache-Control: no-store for sensitive data"
    },
    "Clear-Site-Data": {
        "severity": "low",
        "cwe": "CWE-693",
        "recommendation": "Implement Clear-Site-Data for logout functionality"
    }
}


class URLValidatorService:
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """Validate URL security and format"""
        # Check protocol
        allowed_schemes = ['http', 'https']
        parsed = urlparse(url)

        if parsed.scheme not in allowed_schemes:
            return False, "Only HTTP and HTTPS protocols are allowed"

        # Block internal/local addresses (SSRF protection)
        blocked_patterns = [
            r'^localhost$',
            r'^127\.\d+\.\d+\.\d+$',
            r'^10\.\d+\.\d+\.\d+$',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$',
            r'^192\.168\.\d+\.\d+$',
            r'^169\.254\.\d+\.\d+$',
            r'^::1$',
            r'^fc00:',
            r'^fe80:'
        ]

        hostname = parsed.hostname or ''
        for pattern in blocked_patterns:
            if re.match(pattern, hostname):
                return False, "Internal/private IP addresses are not allowed"

        # URL format validation
        validator = URLValidator()
        try:
            validator(url)
        except ValidationError:
            return False, "Invalid URL format"

        return True, ""


class HeaderAnalyzer:
    @staticmethod
    def analyze_headers(headers: Dict[str, str]) -> List[HeaderAnalysis]:
        """Detailed analysis of each security header"""
        analysis_results = []

        for header_name, config in SECURITY_HEADERS_CONFIG.items():
            present = header_name in headers
            value = headers.get(header_name) if present else None

            # Generate specific recommendations based on header values
            recommendation = config["recommendation"]

            if present and header_name == "Content-Security-Policy":
                if "unsafe-inline" in value or "unsafe-eval" in value:
                    recommendation = "CSP contains unsafe directives. Remove 'unsafe-inline' and 'unsafe-eval'"
                elif not value.startswith("default-src https:"):
                    recommendation = "Consider using 'default-src https:' for better security"

            elif present and header_name == "Strict-Transport-Security":
                if "max-age=0" in value:
                    recommendation = "HSTS max-age should be at least 31536000 seconds"
                elif "includeSubDomains" not in value:
                    recommendation = "Add includeSubDomains directive to HSTS"

            elif present and header_name == "X-Frame-Options":
                if value.upper() not in ["DENY", "SAMEORIGIN"]:
                    recommendation = "X-Frame-Options should be DENY or SAMEORIGIN"

            analysis_results.append(HeaderAnalysis(
                name=header_name,
                present=present,
                value=value,
                severity=config["severity"],
                recommendation=recommendation,
                cwe_id=config.get("cwe")
            ))

        return analysis_results

    @staticmethod
    def calculate_score(analysis: List[HeaderAnalysis]) -> Tuple[float, SecurityGrade]:
        """Calculate security score with weighted priorities"""
        weights = {
            "critical": 3.0,
            "high": 2.0,
            "medium": 1.0,
            "low": 0.5
        }

        total_weight = sum(weights[item.severity] for item in analysis)
        present_weight = sum(weights[item.severity] for item in analysis if item.present)

        score = (present_weight / total_weight) * 100 if total_weight > 0 else 0

        # Determine grade
        if score >= 95:
            grade = SecurityGrade.A_PLUS
        elif score >= 85:
            grade = SecurityGrade.A
        elif score >= 70:
            grade = SecurityGrade.B
        elif score >= 50:
            grade = SecurityGrade.C
        elif score >= 30:
            grade = SecurityGrade.D
        else:
            grade = SecurityGrade.F

        return round(score, 2), grade

    @staticmethod
    def get_recommendations(analysis: List[HeaderAnalysis]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        # Critical missing headers first
        critical_missing = [item for item in analysis
                            if not item.present and item.severity == "critical"]

        for item in critical_missing:
            recommendations.append(f"[CRITICAL] {item.recommendation}")

        # High severity missing
        high_missing = [item for item in analysis
                        if not item.present and item.severity == "high"]

        for item in high_missing:
            recommendations.append(f"[HIGH] {item.recommendation}")

        # Additional advanced recommendations
        hsts_item = next((item for item in analysis
                          if item.name == "Strict-Transport-Security" and item.present), None)
        if hsts_item and "preload" not in (hsts_item.value or ""):
            recommendations.append("[IMPROVEMENT] Add 'preload' directive to HSTS and submit to HSTS preload list")

        csp_item = next((item for item in analysis
                         if item.name == "Content-Security-Policy" and item.present), None)
        if csp_item and "report-uri" not in (csp_item.value or ""):
            recommendations.append(
                "[MONITORING] Add 'report-uri' or 'report-to' directive to CSP for violation reporting")

        return recommendations


class AsyncSecurityScanner:
    def __init__(self, timeout: int = 30, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def check_ssl_info(self, url: str) -> Dict[str, any]:
        """Check SSL/TLS configuration asynchronously"""
        import ssl
        import socket

        ssl_info = {
            "valid": False,
            "issuer": None,
            "expiry_date": None,
            "protocol": None,
            "error": None
        }

        parsed = urlparse(url)
        hostname = parsed.hostname

        if parsed.scheme != "https":
            ssl_info["error"] = "Not using HTTPS"
            return ssl_info

        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Connect asynchronously (simplified - use asyncio.open_connection for production)
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    ssl_info["valid"] = True
                    ssl_info["issuer"] = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info["expiry_date"] = cert.get('notAfter')
                    ssl_info["protocol"] = ssock.version()

        except Exception as e:
            ssl_info["error"] = str(e)

        return ssl_info

    async def fetch_headers_async(self, url: str) -> Tuple[Optional[Dict], Optional[int], Optional[float]]:
        """Fetch headers asynchronously using aiohttp"""
        import time
        start_time = time.time()

        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=10, ssl=True)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout_config) as session:
            try:
                async with session.get(
                        url,
                        allow_redirects=True,
                        max_redirects=self.max_redirects,
                        headers={
                            'User-Agent': 'Security-Scanner/2.0 (Security Audit Tool)',
                            'Accept': 'text/html,application/xhtml+xml',
                            'Accept-Language': 'en-US,en;q=0.9'
                        }
                ) as response:
                    headers = dict(response.headers)
                    status_code = response.status
                    duration = time.time() - start_time

                    return headers, status_code, duration

            except aiohttp.ClientError as e:
                return None, None, time.time() - start_time

    async def scan_url(self, url: str) -> SecurityReport:
        """Complete security scan of a URL"""
        import time
        scan_start = time.time()

        # Validate URL
        is_valid, error_msg = URLValidatorService.validate_url(url)
        if not is_valid:
            raise ValueError(error_msg)

        # Fetch headers asynchronously
        headers, status_code, fetch_duration = await self.fetch_headers_async(url)

        if headers is None:
            raise ConnectionError(f"Failed to fetch headers from {url}")

        # Analyze headers
        header_analysis = HeaderAnalyzer.analyze_headers(headers)
        score, grade = HeaderAnalyzer.calculate_score(header_analysis)
        recommendations = HeaderAnalyzer.get_recommendations(header_analysis)

        # Get SSL info
        ssl_info = await self.check_ssl_info(url)

        # Generate lists
        missing_headers = [item.name for item in header_analysis if not item.present]
        present_headers = [item.name for item in header_analysis if item.present]
        critical_missing = [item.name for item in header_analysis
                            if not item.present and item.severity == "critical"]

        # Create report
        report = SecurityReport(
            url=url,
            status_code=status_code,
            security_score=score,
            grade=grade,
            total_headers=len(header_analysis),
            present_headers=len(present_headers),
            missing_headers=missing_headers,
            present_headers_list=present_headers,
            critical_missing=critical_missing,
            header_analysis=header_analysis,
            recommendations=recommendations,
            raw_headers=headers,
            ssl_info=ssl_info,
            scan_timestamp=time.time(),
            scan_duration=time.time() - scan_start
        )

        return report