# scanner/core.py
import aiohttp
from .url_normalizer import URLNormalizer


class AsyncSecurityScanner:
    def __init__(self, timeout: int = 10, max_redirects: int = 5):
        self.timeout = timeout
        self.max_redirects = max_redirects

    async def fetch_headers_async(self, url: str):
        """Fetch headers with automatic protocol handling"""
        import time
        start_time = time.time()

        # Normalize URL first (این خط مشکل را حل می‌کند)
        url = URLNormalizer.get_safe_url(url)

        # Try with SSL=False for local, True for production
        ssl_context = None  # Auto-detect

        # For localhost, disable SSL verification
        parsed = URLNormalizer.get_safe_url(url)
        from urllib.parse import urlparse
        if URLNormalizer.is_local_host(urlparse(url).hostname or ''):
            ssl_context = False

        timeout_config = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=10, ssl=ssl_context)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout_config) as session:
            try:
                async with session.get(
                        url,
                        allow_redirects=True,
                        max_redirects=self.max_redirects,
                        headers={
                            'User-Agent': 'Security-Scanner/2.0',
                            'Accept': 'text/html,application/xhtml+xml',
                        }
                ) as response:
                    headers = dict(response.headers)
                    status_code = response.status
                    duration = time.time() - start_time
                    return headers, status_code, duration

            except aiohttp.ClientConnectorError as e:
                # If HTTPS fails for local, try HTTP
                if url.startswith('https://') and 'localhost' in url:
                    http_url = url.replace('https://', 'http://')
                    return await self.fetch_headers_async(http_url)
                raise

            except Exception as e:
                return None, None, time.time() - start_time

    async def scan_url(self, url: str):
        """Complete security scan"""
        # Normalize URL at the beginning
        url = URLNormalizer.get_safe_url(url)

        # Rest of your scan logic...
        headers, status_code, duration = await self.fetch_headers_async(url)
        # ... ادامه کد شما