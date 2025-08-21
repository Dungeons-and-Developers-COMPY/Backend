# my_app/routes/student.py
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_user, current_user, login_required
from werkzeug.security import check_password_hash
from models import User

student_bp = Blueprint('student', __name__)

# ------------------ Student Login Route ------------------
@student_bp.route("/login", methods=["POST"])
def student_login():
    """
    Logs in a student user.
    Ensures username/password are correct and user has the role 'student'.
    """
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

    return jsonify({
        "message": "Logged in",
        "username": user.username,
        "role": user.role,
    })

# ------------------ Who Am I Route (Protected) ------------------
@student_bp.route("/whoami", methods=["GET"])
def whoami():
    """
    Returns the current logged-in user's information.
    Requires the user to be authenticated.
    """
    if not current_user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    
    if current_user.role != "student":
        return jsonify({"error": "Not authorized"}), 403
    
    return jsonify({
        "username": current_user.username,
        "role": current_user.role,
        "is_authenticated": True
    })

