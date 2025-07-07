# utils/security.py
from flask_login import current_user, login_required
from functools import wraps
from flask import abort

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper
