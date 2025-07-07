from flask import Blueprint
from flask import request, jsonify, current_app
from models import Question, db, User
from flask_login import login_required, current_user
from flask import abort

bp = Blueprint('admin', __name__)

@bp.route("/admin", methods=["GET", "POST"])
@login_required
def manage_users():
    if not current_app.config.get("ENABLE_ADMIN"):
        return jsonify({"error": "Admin panel is disabled"}), 403

    # Allow only admins to add users (POST)
    if request.method == "POST":
        if current_user.role != "admin":
            abort(403)  # Forbidden

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

    # For GET requests, optionally restrict or allow as you want:
    if current_user.role != "admin":
        abort(403)

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
