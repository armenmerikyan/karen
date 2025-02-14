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
 