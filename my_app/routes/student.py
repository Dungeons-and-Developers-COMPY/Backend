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

    This endpoint authenticates a user with the role 'student' using their
    username and password. Ensures admins or other roles cannot log in here.

    Use Cases:
    - Student login for accessing protected student features
    - Prevents admin users from logging in on the student portal
    - Validates credentials against hashed passwords in the database

    Process:
    1. Validates JSON body exists with 'username' and 'password'.
    2. Fetches user from the database by username.
    3. Checks password hash against stored password.
    4. Ensures the user has role 'student' (rejects admins and other roles).
    5. Logs in the user using Flask-Login.

    Request Body:
        username (str): The student's username
        password (str): The student's password

    Returns:
        JSON response containing:
            - message (str): Confirmation of login
            - username (str): Logged-in user's username
            - role (str): Logged-in user's role
        Or error JSON if authentication fails or role is invalid
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
    Returns information about the currently logged-in student.

    This endpoint allows authenticated students to verify their session
    and view basic account info.

    Use Cases:
    - Displaying current user info in the UI
    - Verifying session authentication
    - Restricting access to student-only features

    Process:
    1. Checks if user is authenticated.
    2. Ensures user has role 'student'.
    3. Returns username, role, and authentication status.

    Returns:
        JSON response containing:
            - username (str): Logged-in student's username
            - role (str): Logged-in student's role
            - is_authenticated (bool): True if session is active
        Or error JSON if user is not authenticated or not authorized
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

