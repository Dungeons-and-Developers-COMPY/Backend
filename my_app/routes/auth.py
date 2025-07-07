from flask import Blueprint, request, jsonify, send_from_directory, current_app
from flask_login import login_user, logout_user, current_user, login_required
from models import User
from werkzeug.security import check_password_hash
import os
from flask import make_response

bp = Blueprint("auth", __name__)

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return send_from_directory(
            os.path.join(current_app.static_folder, "admin"),
            "index.html"
    )
        
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    login_user(user)
    return jsonify({"message": "Logged in successfully"})

@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})

@bp.route("/check-auth")
def check_auth():
    if current_user.is_authenticated:
        response = make_response(jsonify({"authenticated": True, "username": current_user.username}))
    else:
        response = make_response(jsonify({"authenticated": False}), 401)
    
    # Add headers to prevent caching
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response