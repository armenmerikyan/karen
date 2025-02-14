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
    def wrapper(request, *args, **kwargs):
        profile = WebsiteProfile.objects.order_by('-created_at').first()
        if not profile:
            profile = WebsiteProfile(name="add name", about_us="some info about us")
        
        # Call the original view function
        response = view_func(request, *args, **kwargs)
        
        # Add the profile to the context if the response is a TemplateResponse or HttpResponse
        if isinstance(response, (HttpResponse, TemplateResponse)):
            if hasattr(response, 'context_data'):
                response.context_data['profile'] = profile
            else:
                # If it's an HttpResponse, create a new context
                response.context_data = {'profile': profile}
        
        return response
    return wrapper