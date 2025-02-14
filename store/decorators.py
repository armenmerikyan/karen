from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.shortcuts import render
from functools import wraps
from django.http import HttpResponse
from django.template.response import TemplateResponse

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

        # If the response is an HttpResponse (rendered), modify the context
        if isinstance(response, HttpResponse):
            if hasattr(response, 'context_data'):
                response.context_data['profile'] = profile
            else:
                # Re-render with profile if it doesn't have context_data
                context = response.context_data if hasattr(response, 'context_data') else {}
                context['profile'] = profile
                return render(request, response.template_name, context)
        
        return response
    return _wrapped_view