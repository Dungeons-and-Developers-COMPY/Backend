from models import Question, db, User, QuestionStat
from flask import Blueprint, request, jsonify, send_from_directory, current_app, abort, make_response, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import cast, Integer, func, text
import os, json
import traceback
import ast
import logging

bp = Blueprint('admin', __name__)

# ------------------ Global Admin Route Guard ------------------
logger = logging.getLogger(__name__)

@bp.before_request
def restrict_to_admins():
    """
    Fixed admin route guard with proper session handling
    """
    logger.info(f"Request: {request.method} {request.path}")
    logger.info(f"Endpoint: {request.endpoint}")
    
    public_endpoints = [
        'admin.login', 
        'admin.check_auth', 
        'admin.debug_session',  # Fixed: was 'admin.debug-session'
        'admin.debug_full',     # Fixed: was 'admin.debug-full'
        'admin.test_post',     # Fixed: was 'admin.debug-full'
        'admin.evaluate_and_record_stats'  # This should be public for code submissions
    ]
    
    # Allow OPTIONS requests for CORS
    if request.method == 'OPTIONS':
        return
    
    if request.endpoint in public_endpoints:
        logger.info("Allowing public endpoint")
        return
    
    # Check session first
    user_id = session.get('_user_id')
    logger.info(f"Session user_id: {user_id}")
    logger.info(f"Session keys: {list(session.keys())}")
    
    # Check Flask-Login authentication
    logger.info(f"Flask-Login authenticated: {current_user.is_authenticated}")
    
    if not current_user.is_authenticated:
        logger.warning("Authentication failed - not authenticated")
        return jsonify({"error": "Authentication required"}), 401
    
    # Double-check user exists and has admin role
    if hasattr(current_user, 'role'):
        logger.info(f"User role: '{current_user.role}'")
        if current_user.role != "admin":
            logger.warning(f"Access denied - role '{current_user.role}' != 'admin'")
            return jsonify({"error": "Admin access required"}), 403
    else:
        logger.error("User object missing role attribute")
        return jsonify({"error": "Invalid user object"}), 403
    
    logger.info("Admin access granted")


@bp.route("/admin/test-post", methods=["POST"])
def test_post():
    return "POST OK", 200

@bp.route("/debug-session", methods=["GET"])
def debug_session():
    """
    Debug session and authentication state
    """
    return jsonify({
        "flask_login": {
            "is_authenticated": current_user.is_authenticated,
            "user_id": getattr(current_user, 'id', None),
            "username": getattr(current_user, 'username', None),
            "role": getattr(current_user, 'role', None),
            "is_active": getattr(current_user, 'is_active', None),
            "is_anonymous": getattr(current_user, 'is_anonymous', None)
        },
        "session": {
            "keys": list(session.keys()),
            "data": dict(session),
            "permanent": session.permanent
        },
        "request": {
            "endpoint": request.endpoint,
            "method": request.method,
            "path": request.path,
            "cookies": dict(request.cookies)
        }
    })

@bp.route("/debug-full", methods=["GET"])
def debug_full():
    """
    Comprehensive debug endpoint that returns all auth info
    """
    import sys
    
    debug_info = {
        "authentication": {
            "is_authenticated": current_user.is_authenticated,
            "username": current_user.username if current_user.is_authenticated else None,
            "role": current_user.role if current_user.is_authenticated else None,
            "user_id": current_user.id if current_user.is_authenticated else None
        },
        "request_info": {
            "endpoint": request.endpoint,
            "method": request.method,
            "path": request.path,
            "headers": dict(request.headers)
        },
        "flask_login_info": {
            "login_manager_configured": hasattr(current_app, 'login_manager'),
            "session_protection": getattr(current_app.login_manager, 'session_protection', None) if hasattr(current_app, 'login_manager') else None
        },
        "session_info": {
            "session_keys": list(session.keys()) if 'session' in globals() else [],
            "has_user_id": '_user_id' in session if 'session' in globals() else False
        }
    }
    
    return jsonify(debug_info)

# ------------------ Authentication Check Endpoint ------------------
@bp.route("/check-auth", methods=["GET"])
def check_auth():
    """
    Returns the current user's authentication and role info.
    """
    if current_user.is_authenticated:
        return jsonify({
            "username": current_user.username,
            "role": current_user.role
        })
    return jsonify({"error": "Not authenticated"}), 401

# ------------------ User Management (Admin Panel) ------------------
@bp.route("/manage", methods=["GET", "POST"])
def manage_users():
    """
    GET: Lists all users.
    POST: Creates a new user (admin or regular).
    Access is only granted if ENABLE_ADMIN is True in config.
    """
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

    users = User.query.all()
    return jsonify([
        {"id": u.id, "username": u.username, "role": u.role}
        for u in users
    ])

# ------------------ Get One Question (Admin) ------------------
@bp.route("/questions/<int:question_id>", methods=["GET"])
def get_question_page(question_id):
    """
    Returns full data for a specific question by ID.
    Admin-only route.
    """
    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    return jsonify({
        "id": question.id,
        "title": question.title,
        "prompt_md": question.prompt_md,
        "difficulty": question.difficulty,
        "tags": question.tags,
        "question_number": question.question_number,
        "test_cases": question.test_cases
    })

# ------------------ Create Question ------------------
@bp.route("/questions/", methods=["POST"])
def create_question():
    """
    Creates a new coding question with auto-assigned question_number.
    """
    try:
        data = request.get_json()

        # Find available question number
        existing_numbers = {
            q.question_number
            for q in Question.query.with_entities(Question.question_number)
            if isinstance(q.question_number, int)
        }

        question_number = 1
        while question_number in existing_numbers:
            question_number += 1

        # Create and save new question
        question = Question(
            title=data["title"],
            prompt_md=data["prompt_md"],
            difficulty=data["difficulty"],
            tags=data.get("tags", ""),
            question_number=question_number,
            test_cases=data.get("test_cases", "[]")
        )

        db.session.add(question)
        db.session.commit()

        return jsonify({
            "message": "Question added",
            "question_number": question.question_number,
            "id": question.id
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
# ------------------ Add New Admin User ------------------
@bp.route('/add-admin', methods=['POST'])
def add_admin():
    """
    Creates a new admin user.
    Returns error if username already exists.
    
    """
    if current_user.username != "Ibrahim":
        return jsonify({"error": "Only Ibrahim may add admin users"}), 403
    
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
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        return jsonify({"message": f"Admin user '{username}' created successfully", "id": new_admin.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to create admin: {str(e)}"}), 500

# ------------------ List All Questions ------------------
@bp.route('/questionsAll/', methods=["POST"])
def list_questions():
    """
    Returns a list of all questions with metadata.
    """
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

# ------------------ Stats Overview By Tag ------------------
@bp.route("/overview", methods=["GET"])
def get_tag_overview():
    """
    Aggregates total attempts and pass counts per tag.
    Returns pass rates for each tag.
    """
    try:
        stats = db.session.query(
            QuestionStat.tag,
            func.sum(cast(QuestionStat.data.op('->>')('attempts'), Integer)).label("total_attempts"),
            func.sum(cast(QuestionStat.data.op('->>')('passed'), Integer)).label("total_passed")
        ).group_by(QuestionStat.tag).all()

        result = []
        for tag, attempts, passed in stats:
            attempts = attempts or 0
            passed = passed or 0
            pass_rate = round((passed / attempts * 100), 2) if attempts else 0.0

            result.append({
                "tag": tag,
                "total_attempts": int(attempts),
                "total_passed": int(passed),
                "pass_rate": pass_rate
            })

        return jsonify(result)

    except Exception as e:
        current_app.logger.error("Error generating stats: %s", str(e))
        current_app.logger.debug(traceback.format_exc())
        return jsonify({"error": "Failed to generate stats"}), 500

    
# ------------------ Delete a Question ------------------
@bp.route("/test-delete/<int:question_id>", methods=["DELETE","POST"])
def delete_question_via_post(question_id):
    # Check for override method
    if request.method == "POST" and request.form.get("_method", "").upper() != "DELETE":
        return jsonify({"error": "Invalid method override"}), 400

    print(f"Attempting to delete question {question_id}")
    
    # Your delete logic here
    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"message": f"Question {question_id} deleted"}), 200


# ------------------ Update Question ------------------
@bp.route("/questions/<int:question_id>", methods=["POST", "PUT"])
@login_required
def update_question(question_id):
    """
    Updates a question with new data.
    Supports PUT method with JSON body or
    POST method with form data containing _method=PUT and JSON string in 'data'.
    """
    # Handle POST with method override
    if request.method == "POST":
        override = request.form.get("_method", "").upper()
        if override != "PUT":
            return jsonify({"error": "Invalid method override"}), 400
        # Extract JSON data from form param 'data'
        data_json = request.form.get("data")
        if not data_json:
            return jsonify({"error": "Missing data parameter"}), 400
        try:
            data = json.loads(data_json)
        except Exception as e:
            return jsonify({"error": f"Invalid JSON in data parameter: {str(e)}"}), 400
    else:
        # Normal PUT with JSON body
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    # Update fields
    question.title = data.get("title", question.title)
    question.prompt_md = data.get("prompt_md", question.prompt_md)
    question.difficulty = data.get("difficulty", question.difficulty)
    question.tags = data.get("tags", question.tags)
    question.question_number = data.get("question_number", question.question_number)
    question.test_cases = data.get("test_cases", question.test_cases)

    db.session.commit()
    return jsonify({"message": "Question updated"})


# ------------------ Submit Code and Record Stats ------------------
@bp.route("/questions/stats/<int:question_number>", methods=["POST"])
def evaluate_and_record_stats(question_number):
    """
    Accepts user code, evaluates against test cases, and records attempt/pass stats.
    """
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing JSON body or 'code' field"}), 400
    user_code = data["code"]

    question = Question.query.filter_by(question_number=question_number).first()
    if not question:
        return jsonify({"error": f"Question {question_number} not found"}), 404

    try:
        test_cases = json.loads(question.test_cases or "[]")
    except json.JSONDecodeError as e:
        return jsonify({"error": "Invalid test case format", "details": str(e)}), 500

    all_passed = True
    failed_case = None
    error_occurred = False
    error_msg = ""

    # Setup isolated environment
    exec_env = {}

    try:
        exec(user_code, exec_env)
    except Exception as e:
        return jsonify({"success": False, "error": f"Code compilation error: {str(e)}"}), 200

    func = exec_env.get("func")
    if not callable(func):
        return jsonify({
            "success": False,
            "error": "Function 'func' not found in submitted code."
        }), 200

    for case in test_cases:
        raw_input_data = case["input"]
        expected_output = case["output"]

        try:
            parsed_input = ast.literal_eval(raw_input_data)
        except Exception:
            parsed_input = raw_input_data  # fallback

        try:
            result = func(parsed_input)
            result_str = str(result).strip()

            if result_str != expected_output.strip():
                all_passed = False
                failed_case = case
                break
        except Exception as e:
            error_occurred = True
            error_msg = str(e)
            failed_case = case
            all_passed = False
            break

    # Update per-tag stats
    tags = (question.tags or "").split(",")
    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue
        stat = QuestionStat.query.filter_by(question_id=question.id, tag=tag).first()
        if not stat:
            stat = QuestionStat(question_id=question.id, tag=tag, data={})
            db.session.add(stat)
        stat.bump(passed=all_passed)

    db.session.commit()

    # Final response
    if error_occurred:
        return jsonify({
            "success": False,
            "error": f"Code runtime error: {error_msg}",
            "failed_case": failed_case
        }), 200

    if all_passed:
        return jsonify({
            "success": True,
            "message": "All test cases passed!",
            "question_number": question_number
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "At least one test case failed.",
            "failed_case": failed_case,
            "expected": expected_output,
            "got": result_str,
            "question_number": question_number
        }), 200
        
        
# ------------------ Reset All Question Stats ------------------
@bp.route("/questions/stats/reset", methods=["DELETE", "POST"])
def reset_all_stats():
    """
    Resets attempt/pass counts for all questions to zero.
    Supports DELETE method or POST with _method=DELETE override.
    """
    if request.method == "POST":
        override = request.form.get("_method", "").upper()
        if override != "DELETE":
            return jsonify({"error": "Invalid method override"}), 400

    stats = QuestionStat.query.all()
    for stat in stats:
        stat.data = {"attempts": 0, "passed": 0}
    db.session.commit()
    return jsonify({"message": "All question stats have been reset."})


# ------------------ Question-Specific Pass Stats ------------------

@bp.route("/question-pass-stats", methods=["GET"])
def get_all_question_pass_stats():
    """
    Returns pass rates per question.
    Iterates through QuestionStats to compute stats for each question.
    """
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
# ------------------ Admin Login ------------------
@bp.route("/login", methods=["POST"])
def login():
    """
    Enhanced login with explicit session management
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    logger.info(f"Login attempt for username: {username}")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    if user is None:
        logger.warning(f"User not found: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    if not check_password_hash(user.password_hash, password):
        logger.warning(f"Invalid password for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    logger.info(f"User found: {user.username}, Role: {user.role}")

    if user.role != "admin":
        logger.warning(f"User {username} is not an admin. Role: {user.role}")
        return jsonify({"error": "Not authorized"}), 403

    # Clear any existing session data
    session.clear()
    
    # Login user with Flask-Login
    login_user(user, remember=True)
    
    # Explicitly set session data
    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session.permanent = True
    
    logger.info(f"Successfully logged in user: {username}")
    logger.info(f"Session after login: {dict(session)}")

    return jsonify({
        "message": "Logged in successfully",
        "username": user.username,
        "role": user.role,
        "user_id": user.id
    })


# ------------------ Admin Logout ------------------
@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    Logs out the current user.
    """
    logout_user()
    return jsonify({"message": "Logged out"})
