from functools import wraps
from django.http import JsonResponse

def mcp_endpoint(model_name=None, description=None):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            response = view_func(request, *args, **kwargs)
            if isinstance(response, JsonResponse):
                response_data = response.json()
                response_data['model_context'] = {
                    'model': model_name,
                    'description': description,
                    'status': response_data.get('status', 'unknown')
                }
                return JsonResponse(response_data)
            return response
        return _wrapped_view
    return decorator
