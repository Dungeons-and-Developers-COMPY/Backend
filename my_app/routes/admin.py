from models import Question, db, User, QuestionStat
from flask import Blueprint, request, jsonify, send_from_directory, current_app, abort, make_response, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import cast, Integer, func, text
import os, json, datetime
import traceback
import ast
import logging
import traceback
import io
import contextlib
import urllib 
import re

bp = Blueprint('admin', __name__)


logger = logging.getLogger(__name__)

def log_submission_error(question_number, user_code, error_type, error_message, failed_case=None, tb=None):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"question_{question_number}_errors.txt")  # fixed file per question

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a", encoding="utf-8") as f:  # append mode
        f.write(f"[{timestamp}] Error Type: {error_type}\n")
        if failed_case:
            f.write(f"Failed Test Case: {failed_case}\n")
        f.write(f"Error Message: {error_message}\n")
        if tb:
            f.write("Traceback:\n")
            f.write(tb)
        f.write("User Code:\n")
        f.write(user_code)
        f.write("\n" + "-"*60 + "\n\n")

        
# ------------------ Global Admin Route Guard ------------------    
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
        'admin.debug_session',  
        'admin.debug_full',     
        'admin.test_post',     
        'admin.evaluate_and_record_stats',  
        'admin.get_tag_overview',
        'admin.get_all_question_pass_stats',
        'admin.run_code'
    ]
    
    # Allow OPTIONS requests for CORS
    if request.method == 'OPTIONS':
        return
    
    if request.endpoint in public_endpoints:
        logger.info("Allowing public endpoint")
        return
    
    # Check session first
    user_id = session.get('user_id')
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

import traceback
import ast

@bp.route("/run-code", methods=["POST"])
def run_code():
    """
    Executes submitted code and returns the return value from func().
    Accepts optional 'input' as a string to pass to func().
    """
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing 'code' in request body"}), 400

    user_code = data["code"]
    input_value = data.get("input")

    exec_env = {}

    try:
        compile(user_code, "<string>", "exec")
    except SyntaxError as e:
        return jsonify({
            "success": False,
            "error": f"SyntaxError: {str(e)}",
            "traceback": traceback.format_exc()
        }), 400

    try:
        exec(user_code, exec_env)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Runtime error during exec: {str(e)}",
            "traceback": traceback.format_exc()
        }), 400

    func = exec_env.get("func")
    if not callable(func):
        return jsonify({
            "success": False,
            "error": "Function 'func' not found"
        }), 400

    try:
        if input_value:
            try:
                parsed_input = ast.literal_eval(input_value)
            except Exception:
                parsed_input = input_value
            result = func(parsed_input)
        else:
            result = func()
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Error while calling func(): {str(e)}",
            "traceback": traceback.format_exc()
        }), 400

    return jsonify({
        "success": True,
        "result": result
    }), 200


# ------------------ Submit Code and Record Stats ------------------
@bp.route("/questions/stats/<int:question_number>", methods=["POST"])
def evaluate_and_record_stats(question_number):
    """
    Accepts user code, evaluates it against test cases, and records attempt/pass stats.
    Logs detailed errors to file.
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

    exec_env = {}

    try:
        # Try compiling the code first to catch syntax errors upfront
        compile(user_code, "<string>", "exec")
    except SyntaxError as e:
        tb = traceback.format_exc()
        log_submission_error(
            question_number,
            user_code,
            error_type="SyntaxError",
            error_message=str(e),
            tb=tb
        )
        return jsonify({
            "success": False,
            "error": f"Code compilation error (SyntaxError): {str(e)}",
            "traceback": tb
        }), 400
    except Exception as e:
        tb = traceback.format_exc()
        log_submission_error(
            question_number,
            user_code,
            error_type="CompilationError",
            error_message=str(e),
            tb=tb
        )
        return jsonify({
            "success": False,
            "error": f"Code compilation error: {str(e)}",
            "traceback": tb
        }), 400

    try:
        exec(user_code, exec_env)
    except Exception as e:
        tb = traceback.format_exc()
        log_submission_error(
            question_number,
            user_code,
            error_type="RuntimeErrorOnExec",
            error_message=str(e),
            tb=tb
        )
        return jsonify({
            "success": False,
            "error": f"Runtime error during code execution: {str(e)}",
            "traceback": tb
        }), 400

    func = exec_env.get("func")
    if not callable(func):
        error_msg = "Function 'func' not found in submitted code."
        log_submission_error(
            question_number,
            user_code,
            error_type="MissingFunction",
            error_message=error_msg,
        )
        return jsonify({"success": False, "error": error_msg}), 400

    for case in test_cases:
        if "input" not in case or ("output" not in case and "expected_output" not in case):
            log_submission_error(
                question_number,
                user_code,
                error_type="InvalidTestCase",
                error_message="Test case missing 'input' and 'output'/'expected_output'",
                failed_case=case,
            )
            return jsonify({
                "success": False,
                "error": "Invalid test case: missing 'input' and 'output'/'expected_output'",
                "failed_case": case,
            }), 500

        raw_input_data = case["input"]
        expected_output = case.get("output", case.get("expected_output", "")).strip()

        try:
            parsed_input = ast.literal_eval(raw_input_data)
        except Exception:
            parsed_input = raw_input_data  # fallback to string

        try:
            result = func(parsed_input)
            result_str = str(result).strip()
        except Exception as e:
            error_msg = str(e)
            tb = traceback.format_exc()
            log_submission_error(
                question_number,
                user_code,
                error_type="RuntimeError",
                error_message=error_msg,
                failed_case=case,
                tb=tb
            )
            return jsonify({
                "success": False,
                "error": f"Code runtime error: {error_msg}",
                "traceback": tb,
                "failed_case": case
            }), 200

        if result_str != expected_output.strip():
            error_msg = f"Expected: {expected_output.strip()}, Got: {result_str}"
            log_submission_error(
                question_number,
                user_code,
                error_type="WrongOutput",
                error_message=error_msg,
                failed_case=case
            )
            return jsonify({
                "success": False,
                "message": "At least one test case failed.",
                "failed_case": case,
                "expected": expected_output.strip(),
                "got": result_str,
                "question_number": question_number
            }), 200

    # All test cases passed, update stats
    tags = (question.tags or "").split(",")
    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue
        stat = QuestionStat.query.filter_by(question_id=question.id, tag=tag).first()
        if not stat:
            stat = QuestionStat(question_id=question.id, tag=tag, data={})
            db.session.add(stat)
        stat.bump(passed=True)

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "All test cases passed!",
        "question_number": question_number
    }), 200

        
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
    Combines all tags found in `question.tags` and `question_stat`,
    then aggregates attempts/pass counts for each tag.
    Returns pass rates per tag, defaulting to 0 if no stats exist.
    """
    try:
        # Step 1: Get all tags from the `question_stat` table
        stat_rows = db.session.query(
            QuestionStat.tag,
            func.sum(cast(QuestionStat.data.op('->>')('attempts'), Integer)).label("total_attempts"),
            func.sum(cast(QuestionStat.data.op('->>')('passed'), Integer)).label("total_passed")
        ).group_by(QuestionStat.tag).all()

        stats_map = {}
        for tag, attempts, passed in stat_rows:
            attempts = attempts or 0
            passed = passed or 0
            stats_map[tag.lower()] = {
                "tag": tag,
                "total_attempts": int(attempts),
                "total_passed": int(passed),
                "pass_rate": round((passed / attempts * 100), 2) if attempts else 0.0
            }

        # Step 2: Extract all tags from `question.tags` (comma-separated)
        raw_tags = db.session.execute(text("SELECT tags FROM question WHERE tags IS NOT NULL AND TRIM(tags) != ''"))
        question_tags = set()

        for row in raw_tags:
            tag_list = [t.strip() for t in row[0].split(',') if t.strip()]
            for t in tag_list:
                question_tags.add(t)

        # Step 3: Ensure all tags are present in the output
        result = []
        for tag in sorted(question_tags, key=str.lower):
            lower_tag = tag.lower()
            if lower_tag in stats_map:
                result.append(stats_map[lower_tag])
            else:
                result.append({
                    "tag": tag,
                    "total_attempts": 0,
                    "total_passed": 0,
                    "pass_rate": 0.0
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
        

@bp.route('/delete-tag/<tag_name>', methods=['POST', 'DELETE'])
def delete_tag(tag_name):
    """
    Delete a tag using SQLAlchemy - handles both POST with _method=DELETE and actual DELETE requests
    """
    try:
        tag_name = urllib.parse.unquote(tag_name).lower()
        
        # Accept both actual DELETE requests and POST with _method=DELETE
        is_delete_request = (
            request.method == 'DELETE' or 
            request.form.get('_method') == 'DELETE'
        )
        
        if is_delete_request:
            
            try:
                # Use raw SQL with SQLAlchemy for better control
                # First, count affected questions
                result = db.session.execute(
                    text("SELECT COUNT(*) FROM question WHERE tags ILIKE :tag_pattern"),
                    {"tag_pattern": f'%{tag_name}%'}
                )
                affected_count = result.scalar()
                
                if affected_count == 0:
                    return jsonify({
                        'success': True,
                        'message': f'Tag "{tag_name}" was not found in any questions.'
                    })
                
                # For SQLite (if you're using SQLite instead of PostgreSQL)
                if 'sqlite' in str(db.engine.url):
                    # SQLite version - simpler approach
                    questions_result = db.session.execute(
                        text("SELECT id, tags FROM question WHERE tags ILIKE :tag_pattern"),
                        {"tag_pattern": f'%{tag_name}%'}
                    )
                    
                    for row in questions_result:
                        question_id, current_tags = row
                        if current_tags:
                            # Split tags, remove target tag, rejoin
                            tag_list = [tag.strip() for tag in current_tags.split(',') if tag.strip()]
                            updated_tags = [tag for tag in tag_list if tag.lower() != tag_name.lower()]
                            new_tags_string = ','.join(updated_tags) if updated_tags else ''
                            
                            db.session.execute(
                                text("UPDATE questions SET tags = :new_tags WHERE id = :question_id"),
                                {"new_tags": new_tags_string, "question_id": question_id}
                            )
                
                else:
                    # PostgreSQL version - use advanced string functions
                    db.session.execute(
                        text("""
                            UPDATE question
                            SET tags = TRIM(BOTH ',' FROM REGEXP_REPLACE(
                                tags,
                                :regex_pattern,
                                '',
                                'gi'
                            ))
                            WHERE tags ~* :regex_pattern
                        """),
                        {
                            "regex_pattern": fr"(^|,){re.escape(tag_name)}(?=,|$)"
                        }
                    )
                    
                    # Clean up trailing/leading commas (PostgreSQL)
                    db.session.execute(
                        text("UPDATE question SET tags = TRIM(BOTH ',' FROM tags) WHERE LOWER(tags) ILIKE ',%' OR tags ILIKE '%,'")
                    )
                
                # Clean up empty tags (works for both SQLite and PostgreSQL)
                db.session.execute(
                    text("UPDATE question SET tags = '' WHERE LOWER(tags) IS NULL OR TRIM(tags) = ''")
                )
                    
                db.session.query(QuestionStat).filter(
                    func.lower(QuestionStat.tag) == tag_name
                ).delete(synchronize_session=False)
                
                db.session.commit()
                
                return jsonify({
                    'success': True,
                    'message': f'Tag "{tag_name}" has been deleted and removed from {affected_count} questions.'
                })
                
            except Exception as e:
                db.session.rollback()
                raise e
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid request method'
            }), 405
                
    except Exception as e:
        print(f"Error deleting tag: {e}")
        return jsonify({
            'success': False,
            'message': f'Failed to delete tag: {str(e)}'
        }), 500
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
