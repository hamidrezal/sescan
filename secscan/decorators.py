# decorators.py
from functools import wraps
from urllib.parse import urlparse


def normalize_url_param(param_name='url'):
    """Decorator to normalize URL parameter before view execution"""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Get URL from GET or POST
            url = request.GET.get(param_name) or request.POST.get(param_name)

            if url:
                # Normalize URL
                url = url.strip()
                parsed = urlparse(url)

                # Local hosts detection
                local_hosts = ['localhost', '127.0.0.1', '::1']
                is_local = parsed.hostname in local_hosts or parsed.hostname == 'localhost'

                # Add scheme if missing
                if not parsed.scheme:
                    scheme = 'http' if is_local else 'https'
                    url = f'{scheme}://{url}'

                # Fix wrong scheme for localhost
                elif parsed.scheme == 'https' and is_local:
                    url = url.replace('https://', 'http://', 1)

                # Update request GET or POST
                if param_name in request.GET:
                    request.GET = request.GET.copy()
                    request.GET[param_name] = url
                elif param_name in request.POST:
                    request.POST = request.POST.copy()
                    request.POST[param_name] = url

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator