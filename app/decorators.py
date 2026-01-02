from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def session_login_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.session.get('user_id'):
            messages.error(request, "Please log in first.")
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def session_role_required(allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            role = request.session.get('rank')
            if role not in allowed_roles:
                messages.error(request, "Unauthorized access.")
                return redirect('home')
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

