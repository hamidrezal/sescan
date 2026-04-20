# scanner/url_normalizer.py
from urllib.parse import urlparse
import re


class URLNormalizer:
    """
    URL Normalizer that works both on local and production
    Handles HTTP/HTTPS properly based on environment and URL type
    """

    # Internal/local hostnames that should use HTTP
    LOCAL_HOSTS = {
        'localhost', '127.0.0.1', '::1', '0.0.0.0',
        'local', 'dev.local', 'test.local'
    }

    # Local IP ranges
    LOCAL_IP_PATTERNS = [
        r'^10\.\d+\.\d+\.\d+$',  # 10.0.0.0/8
        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$',  # 172.16.0.0/12
        r'^192\.168\.\d+\.\d+$',  # 192.168.0.0/16
        r'^169\.254\.\d+\.\d+$',  # 169.254.0.0/16
    ]

    @classmethod
    def is_local_host(cls, hostname: str) -> bool:
        """Check if hostname is local/internal"""
        if not hostname:
            return False

        hostname = hostname.lower()

        # Check local hosts set
        if hostname in cls.LOCAL_HOSTS:
            return True

        # Check local IP patterns
        for pattern in cls.LOCAL_IP_PATTERNS:
            if re.match(pattern, hostname):
                return True

        return False

    @classmethod
    def normalize(cls, url: str, prefer_https: bool = True) -> str:
        """
        Normalize URL with proper protocol

        Args:
            url: Input URL string
            prefer_https: Prefer HTTPS for non-local URLs

        Returns:
            Normalized URL with correct protocol
        """
        if not url:
            return url

        url = url.strip()

        # Parse URL
        parsed = urlparse(url)

        # If no scheme, add default
        if not parsed.scheme:
            hostname = parsed.hostname or url.split('/')[0]

            if cls.is_local_host(hostname):
                # Local host -> use HTTP
                url = f'http://{url}'
            else:
                # External host -> use HTTPS (or HTTP if prefer_https is False)
                url = f'https://{url}' if prefer_https else f'http://{url}'

        # If has scheme, validate and fix if needed
        else:
            hostname = parsed.hostname or ''

            # Fix: localhost with HTTPS should be HTTP
            if parsed.scheme == 'https' and cls.is_local_host(hostname):
                url = url.replace('https://', 'http://', 1)

            # Fix: external host with HTTP might want HTTPS (optional)
            elif parsed.scheme == 'http' and not cls.is_local_host(hostname) and prefer_https:
                # Don't force change, but you could add a warning
                pass

        return url

    @classmethod
    def get_safe_url(cls, url: str) -> str:
        """Get URL that's safe to request (always working)"""
        normalized = cls.normalize(url)

        # Second pass: ensure we don't have double protocols
        if '://' in normalized:
            parts = normalized.split('://', 1)
            if len(parts) == 2:
                protocol, rest = parts
                # Remove any remaining protocol in rest
                rest = re.sub(r'^https?://', '', rest)
                return f'{protocol}://{rest}'

        return normalized