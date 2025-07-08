from flask import Blueprint, request, jsonify, current_app
from flask_login import login_user
from werkzeug.security import check_password_hash
from models import User

student_bp = Blueprint('student', __name__)

@student_bp.route("/login", methods=["POST"])
def student_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    if user.role == "admin":
        return jsonify({"error": "Please login on the admin page!"}), 403
    if user.role != "student":
        return jsonify({"error": "Not authorized"}), 403

    login_user(user)
    return jsonify({"message": "Logged in", "username": user.username, "role": user.role})
