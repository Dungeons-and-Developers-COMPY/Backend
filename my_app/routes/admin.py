from models import Question, db, User, QuestionStat
from flask import Blueprint, request, jsonify, send_from_directory, current_app,abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
import os
from flask import make_response
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import cast, Integer
from sqlalchemy import func, text
import traceback

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
        
@bp.route("/check-auth", methods=["GET"])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({
            "username": current_user.username,
            "role": current_user.role
        })
    return jsonify({"error": "Not authenticated"}), 401

@bp.route("/manage", methods=["GET", "POST"])
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


@bp.route('/add-admin', methods=['POST'])
def add_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "User with that username already exists"}), 409

    try:
        new_admin = User(username=username, role="admin")
        new_admin.set_password(password) # Assuming set_password hashes the password
        db.session.add(new_admin)
        db.session.commit()
        return jsonify({"message": f"Admin user '{username}' created successfully", "id": new_admin.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to create admin: {str(e)}"}), 500
    
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


@bp.route("/overview", methods=["GET"])
def get_tag_overview():
    try:
        stats = db.session.query(
            QuestionStat.tag,
            func.sum(cast(QuestionStat.data.op('->>')('attempts'), Integer)).label("total_attempts"),
            func.sum(cast(QuestionStat.data.op('->>')('passed'), Integer)).label("total_passed")
        ).group_by(QuestionStat.tag).all()

        result = [
            {
                "tag": tag,
                "total_attempts": int(attempts or 0),
                "total_passed": int(passed or 0),
                "pass_rate": round((passed / attempts * 100), 2) if attempts else 0.0,
            }
            for tag, attempts, passed in stats
        ]

        return jsonify(result)

    except Exception as e:
        import traceback
        current_app.logger.error("❌ Error generating stats: %s", str(e))
        current_app.logger.debug(traceback.format_exc())
        return jsonify({"error": "Failed to generate stats"}), 500

@bp.route("/question-pass-stats", methods=["GET"])
def get_all_question_pass_stats():
    questions = Question.query.all()
    results = []

    for q in questions:
        stats = QuestionStat.query.filter_by(question_id=q.id).all()
        total_attempts = 0
        total_passed = 0

        for stat in stats:
            total_attempts += stat.data.get("attempts", 0)
            total_passed += stat.data.get("passed", 0)

        pass_rate = (total_passed / total_attempts * 100) if total_attempts > 0 else 0

        results.append({
            "id": q.id,
            "title": q.title,
            "pass_rate": round(pass_rate, 2)
        })

    return jsonify(results)

@bp.route("/login", methods=["POST"])
def login():

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