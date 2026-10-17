"""Login guard (the application has a single role: admin)."""
import functools

from flask import redirect, request, session, url_for


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped
