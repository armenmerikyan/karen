from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.shortcuts import render
from functools import wraps
from django.http import HttpResponse 

from .models import WebsiteProfile

def staff_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_staff:
            return HttpResponseForbidden("You are not authorized to view this page.")
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def add_profile_to_context(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Fetch or create the profile
        profile = WebsiteProfile.objects.order_by('-created_at').first()
        if not profile:
            profile = WebsiteProfile(name="add name", about_us="some info about us")
        
        # Call the view function to get the response
        response = view_func(request, *args, **kwargs)

        # If the response is an HttpResponse or TemplateResponse, we can add the context
        if isinstance(response, HttpResponse):
            # Check if it's a TemplateResponse
            if hasattr(response, 'context_data'):
                response.context_data['profile'] = profile
            else:
                # If it's just an HttpResponse, we can't access context_data, so re-render
                context = {'profile': profile}
                if hasattr(response, 'content'):
                    # If response has content, check the view for its template_name and pass the context
                    return render(request, 'products/shop_product_detail.html', context)
        
        return response
    return _wrapped_view