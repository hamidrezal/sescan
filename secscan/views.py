import asyncio
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_http_methods
import json
from secscan.utils import AsyncSecurityScanner, SecurityReport
from secscan.decorators import normalize_url_param

# Initialize scanner
scanner = AsyncSecurityScanner(timeout=10, max_redirects=5)


@never_cache
@ratelimit(key='ip', rate='10/m', method='GET', block=True)
@require_http_methods(["GET"])
# @normalize_url_param('url')
def check_headers_view(request):
    """
    View to check security headers of a given URL
    Supports both HTML rendering and JSON API responses
    """
    url = request.GET.get("url", "").strip()
    api_mode = request.GET.get("api", "").lower() == "true"

    # Return empty form if no URL provided
    if not url:
        if api_mode:
            return JsonResponse({"error": "URL parameter is required"}, status=400)
        return render(request, "sescan/index.html")

    # Add default protocol
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Check cache first
    cache_key = f"security_scan_{url}"
    cached_result = cache.get(cache_key)

    if cached_result and isinstance(cached_result, SecurityReport):
        if api_mode:
            return JsonResponse(serialize_report(cached_result))
        return render(request, "sescan/index.html", {
            "report": cached_result,
            "cached": True
        })

    try:
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        report = loop.run_until_complete(scanner.scan_url(url))
        loop.close()

        # Cache for 1 hour
        cache.set(cache_key, report, 3600)

        if api_mode:
            return JsonResponse(serialize_report(report))

        context = {
            "report": report,
            "cached": False,
            "json_ld": generate_json_ld(report)  # For SEO
        }

        return render(request, "sescan/index.html", context)

    except ValueError as e:
        error_msg = str(e)
        if api_mode:
            return JsonResponse({"error": error_msg}, status=400)
        return render(request, "sescan/index.html", {
            "error": error_msg,
            "url": url
        })

    except ConnectionError as e:
        error_msg = str(e)
        if api_mode:
            return JsonResponse({"error": error_msg}, status=503)
        return render(request, "sescan/index.html", {
            "error": f"Connection error: {error_msg}",
            "url": url
        })

    except TimeoutError:
        if api_mode:
            return JsonResponse({"error": "Request timeout"}, status=504)
        return render(request, "sescan/index.html", {
            "error": "Request timeout - server took too long to respond",
            "url": url
        })

    except Exception as e:
        # Log error here (use proper logging in production)
        print(f"Unexpected error: {str(e)}")

        if api_mode:
            return JsonResponse({"error": "Internal server error"}, status=500)
        return render(request, "sescan/index.html", {
            "error": "An unexpected error occurred",
            "url": url
        })


def serialize_report(report: SecurityReport) -> dict:
    """Convert SecurityReport to JSON serializable dict"""
    return {
        "url": report.url,
        "status_code": report.status_code,
        "security_score": report.security_score,
        "grade": report.grade.value,
        "statistics": {
            "total_headers": report.total_headers,
            "present_headers": report.present_headers,
            "missing_headers_count": len(report.missing_headers)
        },
        "missing_headers": report.missing_headers,
        "critical_missing": report.critical_missing,
        "present_headers": report.present_headers_list,
        "recommendations": report.recommendations,
        "ssl_info": {
            "valid": report.ssl_info.get("valid", False),
            "issuer": report.ssl_info.get("issuer"),
            "expiry_date": report.ssl_info.get("expiry_date"),
            "protocol": report.ssl_info.get("protocol"),
            "error": report.ssl_info.get("error")
        },
        "headers": report.raw_headers,
        "scan_duration": report.scan_duration,
        "timestamp": report.scan_timestamp
    }


def generate_json_ld(report: SecurityReport) -> dict:
    """Generate structured data for SEO"""
    return {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "name": f"Security Headers Analysis for {report.url}",
        "description": f"Security scan results showing {report.security_score}% score with grade {report.grade.value}",
        "mainEntity": {
            "@type": "Audit",
            "report": {
                "securityScore": report.security_score,
                "grade": report.grade.value,
                "missingHeaders": report.missing_headers
            }
        }
    }


# API endpoint for programmatic access
@never_cache
@ratelimit(key='ip', rate='30/m', method='GET', block=True)
@require_http_methods(["GET"])
def api_check_headers(request):
    """REST API endpoint for header checking"""
    return check_headers_view(request)


# Bulk check endpoint
@never_cache
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@require_http_methods(["POST"])
def api_bulk_check_headers(request):
    """Check multiple URLs at once"""
    try:
        data = json.loads(request.body)
        urls = data.get("urls", [])

        if not urls or len(urls) > 10:
            return JsonResponse({"error": "Please provide 1-10 URLs"}, status=400)

        async def scan_multiple():
            tasks = [scanner.scan_url(url) for url in urls]
            return await asyncio.gather(*tasks, return_exceptions=True)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(scan_multiple())
        loop.close()

        serialized_results = []
        for result in results:
            if isinstance(result, Exception):
                serialized_results.append({"error": str(result)})
            else:
                serialized_results.append(serialize_report(result))

        return JsonResponse({"results": serialized_results}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)