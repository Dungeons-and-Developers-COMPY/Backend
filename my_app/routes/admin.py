from models import Question, db, User
from flask import Blueprint, request, jsonify, send_from_directory, current_app,abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
import os
from flask import make_response

bp = Blueprint('admin', __name__)

# 🔒 Global guard for all admin routes
@bp.before_request
def restrict_to_admins():
    # Don't require login on these routes
    if request.endpoint in ('admin.login', 'admin.check_auth'):
        return

    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    if current_user.role != "admin":
        abort(403)
        
@bp.route("/admin", methods=["GET", "POST"])
def manage_users():
    if not current_app.config.get("ENABLE_ADMIN"):
        return jsonify({"error": "Admin panel is disabled"}), 403

    if request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        role     = data.get("role", "user")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409

        user = User(username=username, role=role)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "User created", "user_id": user.id}), 201

    # GET request: list users
    users = User.query.all()
    return jsonify([
        {"id": u.id, "username": u.username, "role": u.role}
        for u in users
    ])

@bp.route('/questions')
def list_questions():
    questions = Question.query.all()
    data = [
        {
            "id": q.id,
            "title": q.title,
            "difficulty": q.difficulty,
            "tags": q.tags,
            "created_at": q.created_at.isoformat()
        }
        for q in questions
    ]
    return jsonify(data)


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

    if user.role != "admin":
        return jsonify({"error": "Not authorized"}), 403

    login_user(user)

    # ⬇️ Return all required info in one go
    return jsonify({
        "message": "Logged in successfully",
        "username": user.username,
        "role": user.role
    })


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})