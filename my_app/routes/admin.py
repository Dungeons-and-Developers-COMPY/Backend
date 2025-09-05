"""
Flask Blueprint for Admin and User Management

This module provides a comprehensive Flask blueprint for managing a coding question platform
with role-based access control, user authentication, question management, and statistics tracking.

Key Features:
- Role-based access control (admin, student)
- Code execution and evaluation system
- Question management (CRUD operations)
- User authentication and session management
- Statistics tracking for questions and tags
- Admin panel functionality

Authentication Methods:
- Username/password login
- Special login key for admin access

Access Control:
- Public endpoints (login, auth check, debug)
- Admin-only endpoints (user management, question management)
- Student+Admin endpoints (code submission, code execution)
"""

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
from functools import wraps

# =============================================================================
# BLUEPRINT INITIALIZATION AND UTILITY FUNCTIONS
# =============================================================================

bp = Blueprint('admin', __name__)
logger = logging.getLogger(__name__)

def log_submission_error(question_number, user_code, error_type, error_message, failed_case=None, tb=None):
    """
    Logs detailed error information for failed code submissions to file system.
    
    Creates individual log files per question to track common errors and debugging info.
    Used for analyzing student submission patterns and improving question quality.
    
    Args:
        question_number (int): The question number that failed
        user_code (str): The submitted code that caused the error
        error_type (str): Category of error (SyntaxError, RuntimeError, etc.)
        error_message (str): Specific error message
        failed_case (dict, optional): The test case that caused failure
        tb (str, optional): Full traceback string
    """
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"question_{question_number}_errors.txt")

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_file, "a", encoding="utf-8") as f:
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

# =============================================================================
# ACCESS CONTROL AND AUTHENTICATION DECORATORS
# =============================================================================

def role_required(roles):
    """
    Custom decorator to restrict access to specific user roles.
    
    This decorator works in conjunction with the global before_request handler
    to provide fine-grained access control. It checks that the current user
    has one of the specified roles before allowing access to the route.
    
    Args:
        roles (str or list): Single role string or list of allowed roles
        
    Returns:
        decorator: Function decorator that enforces role requirements
        
    Usage:
        @role_required(["admin", "student"])
        def some_route():
            pass
    """
    if not isinstance(roles, (list, tuple)):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "Authentication required"}), 401
            if not hasattr(current_user, 'role') or current_user.role not in roles:
                # Log this attempt to help debugging
                logger.warning(f"Access denied for user {current_user.username} (role: {current_user.role}) trying to access {request.endpoint}. Required roles: {roles}")
                return jsonify({"error": f"Access denied: Requires one of {', '.join(roles)} roles"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# =============================================================================
# GLOBAL ACCESS CONTROL HANDLER
# =============================================================================

@bp.before_request
def check_access_control():
    """
    Global request handler that manages access control for all routes in this blueprint.
    
    This handler implements a layered security approach:
    1. Allows public endpoints (login, auth check, debug) without restrictions
    2. Requires authentication for all other endpoints
    3. Enforces admin-only access for administrative endpoints
    4. Delegates specific role checking to individual route decorators
    
    The access control logic is:
    - Public endpoints: No restrictions
    - Admin-only endpoints: Must be authenticated admin user
    - Other endpoints: Must be authenticated (role checked by decorators)
    
    Returns:
        JSON response with error code if access denied, otherwise continues to route
    """
    logger.info(f"Request: {request.method} {request.path}")
    logger.info(f"Endpoint: {request.endpoint}")

    if request.method == 'OPTIONS':
        return

    # List of endpoints that are completely public (no login or role required)
    public_endpoints = [
        'admin.login',
        'admin.check_auth',
        'admin.debug_session',
        'admin.debug_full', 
        'admin.test_post', 
        'admin.logout' 
    ]

    if request.endpoint in public_endpoints:
        logger.info(f"Allowing public endpoint: {request.endpoint}")
        return

    if not current_user.is_authenticated:
        logger.warning("Authentication required for endpoint: %s", request.endpoint)
        return jsonify({"error": "Authentication required"}), 401

    admin_only_endpoints = [
        'admin.manage_users',
        'admin.get_question_page',
        'admin.create_question',
        'admin.add_admin',
        'admin.list_questions',
        'admin.delete_question_via_post',
        'admin.update_question',
        'admin.delete_tag',
        'admin.reset_all_stats'
        'admin.get_tag_overview',
        'admin.get_all_question_pass_stats'
    ]

    if request.endpoint in admin_only_endpoints:
        if not hasattr(current_user, 'role') or current_user.role != "admin":
            logger.warning(f"Access denied: User {current_user.username} (role: {current_user.role}) attempted to access admin-only endpoint: {request.endpoint}")
            return jsonify({"error": "Admin access required"}), 403
        logger.info(f"Admin access granted for endpoint: {request.endpoint}")
        return 

    logger.info(f"Proceeding to endpoint handler for {request.endpoint}. Specific decorators will handle roles.")

# =============================================================================
# DEBUG AND DEVELOPMENT ENDPOINTS
# =============================================================================

@bp.route("/debug-full", methods=["GET"])
def debug_full():
    """
    Comprehensive debug endpoint for development and troubleshooting.
    
    Returns detailed information about:
    - Current user authentication state
    - Request information (headers, path, method)
    - Flask-Login configuration
    - Session data and user ID storage
    
    This endpoint is public to allow debugging authentication issues.
    Should be disabled or restricted in production environments.
    
    Returns:
        JSON object containing comprehensive debug information
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

# =============================================================================
# CODE EXECUTION AND EVALUATION SYSTEM
# =============================================================================

@bp.route("/run-code", methods=["POST"])
@role_required(["admin", "student"])
def run_code():
    """
    Executes user-submitted code in a controlled environment.
    
    This endpoint allows both admins and students to test code execution
    without submitting against specific test cases. Useful for debugging
    and development of coding solutions.
    
    Security considerations:
    - Code execution is sandboxed to minimize security risks
    - Only accepts code with a 'func' function defined
    - Supports base64 encoded code to avoid Apache security restrictions
    - Input parsing attempts ast.literal_eval before falling back to string
    
    Request Body:
        code (str): Python code (can be base64 encoded)
        input (str, optional): Input parameter to pass to func()
        
    Returns:
        JSON response with execution result or error information
    """
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing 'code' in request body"}), 400

    # Decode base64 encoded code
    raw_code = data["code"]
    try:
        import base64
        # Try to decode as base64
        user_code = base64.b64decode(raw_code).decode('utf-8')
    except Exception:
        # If base64 decoding fails, use the raw code as-is
        user_code = raw_code

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

# =============================================================================
# STATISTICS TRACKING SYSTEM
# =============================================================================

def track_failed_attempt(question):
    """
    Records a failed submission attempt in the statistics system.
    
    This function updates the QuestionStat records for each tag associated
    with the question, incrementing the attempt count but not the pass count.
    Used to track question difficulty and student performance patterns.
    
    Args:
        question (Question): The Question model instance that had a failed attempt
        
    Side Effects:
        - Creates or updates QuestionStat records for each tag
        - Commits changes to the database
    """
    tags = (question.tags or "").split(",")
    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue
        stat = QuestionStat.query.filter_by(question_id=question.id, tag=tag).first()
        if not stat:
            stat = QuestionStat(question_id=question.id, tag=tag, data={})
            db.session.add(stat)
        stat.bump(passed=False)
    db.session.commit()

@bp.route("/submit/<int:question_number>", methods=["POST"])
@role_required(["admin", "student"])
def evaluate_and_record_stats(question_number):
    """
    Comprehensive code submission and evaluation endpoint.
    
    This is the core endpoint for student code submissions. It:
    1. Decodes and validates submitted code
    2. Compiles and executes code in isolated environment
    3. Runs code against all test cases for the question
    4. Records success/failure statistics by tag
    5. Logs detailed error information for failed submissions
    
    The evaluation process:
    - Supports base64 encoded code for Apache compatibility
    - Validates syntax before execution
    - Requires a 'func' function to be defined
    - Tests against all question test cases
    - Updates QuestionStat records for performance tracking
    
    Request Body:
        code (str): Python code (can be base64 encoded)
        
    Returns:
        JSON response indicating success/failure with detailed feedback
    """
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing JSON body or 'code' field"}), 400
    
    # Decode base64 encoded code
    raw_code = data["code"]
    try:
        import base64
        # Try to decode as base64
        user_code = base64.b64decode(raw_code).decode('utf-8')
    except Exception:
        # If base64 decoding fails, use the raw code as-is
        user_code = raw_code

    question = Question.query.filter_by(question_number=question_number).first()
    if not question:
        return jsonify({"error": f"Question {question_number} not found"}), 404

    try:
        test_cases = json.loads(question.test_cases or "[]")
    except json.JSONDecodeError as e:
        return jsonify({"error": "Invalid test case format", "details": str(e)}), 500

    exec_env = {}

    try:
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
        track_failed_attempt(question)  # Track failed attempt
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
        track_failed_attempt(question)  # Track failed attempt
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
        track_failed_attempt(question)  # Track failed attempt
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
        track_failed_attempt(question)  # Track failed attempt
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
            track_failed_attempt(question)  # Track failed attempt
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
            track_failed_attempt(question)  # Track failed attempt
            return jsonify({
                "success": False,
                "error": "At least one test case failed.",
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

# =============================================================================
# USER AUTHENTICATION AND SESSION MANAGEMENT
# =============================================================================

@bp.route("/check-auth", methods=["GET"])
def check_auth():
    """
    Authentication status check endpoint.
    
    This public endpoint allows the frontend to verify current user
    authentication status and retrieve user information without
    requiring a full login attempt.
    
    Returns:
        JSON object with username and role if authenticated,
        or error message if not authenticated
    """
    if current_user.is_authenticated:
        return jsonify({
            "username": current_user.username,
            "role": current_user.role
        })
    return jsonify({"error": "Not authenticated"}), 401

# =============================================================================
# ADMIN USER MANAGEMENT SYSTEM
# =============================================================================

@bp.route("/manage", methods=["GET", "POST"])
@login_required # Ensure user is logged in
def manage_users():
    """
    Admin user management interface.
    
    GET: Returns list of all users with their roles and IDs
    POST: Creates new user account with specified role
    
    This endpoint requires:
    1. ENABLE_ADMIN config setting to be True
    2. Current user to have admin role
    3. Valid username/password for user creation
    
    POST Request Body:
        username (str): Unique username for new account
        password (str): Password for new account
        role (str, optional): User role (defaults to "user")
        
    Returns:
        GET: List of all users
        POST: Success message with new user ID or error
    """
    if not current_app.config.get("ENABLE_ADMIN"):
        return jsonify({"error": "Admin panel is disabled"}), 403
    # The `check_access_control` before_request will handle the admin role check for this route.

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

# =============================================================================
# QUESTION MANAGEMENT SYSTEM
# =============================================================================

@bp.route("/questions/<int:question_id>", methods=["GET"])
@login_required # Ensure user is logged in
def get_question_page(question_id):
    """
    Retrieves complete question data by ID for admin editing.
    
    Returns all question fields including test cases, which should only
    be accessible to administrators for question management purposes.
    
    Args:
        question_id (int): Database ID of the question to retrieve
        
    Returns:
        JSON object with complete question data or error if not found
    """
    # The `check_access_control` before_request will handle the admin role check for this route.
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

@bp.route("/questions/", methods=["POST"])
@login_required # Ensure user is logged in
def create_question():
    """
    Creates a new coding question with auto-assigned question number.
    
    The system automatically assigns the next available question number
    by finding gaps in the existing sequence or appending to the end.
    This ensures consistent numbering without manual intervention.
    
    Request Body:
        title (str): Question title
        prompt_md (str): Markdown-formatted question prompt
        difficulty (str): Difficulty level
        tags (str, optional): Comma-separated tags
        test_cases (str, optional): JSON string of test cases
        
    Returns:
        JSON response with new question number and ID, or error
    """
    # The `check_access_control` before_request will handle the admin role check for this route.
    try:
        data = request.get_json()

        existing_numbers = {
            q.question_number
            for q in Question.query.with_entities(Question.question_number)
            if isinstance(q.question_number, int)
        }

        question_number = 1
        while question_number in existing_numbers:
            question_number += 1

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

@bp.route('/add-admin', methods=['POST'])
@login_required # Ensure user is logged in
def add_admin():
    """
    Special endpoint for creating admin user accounts.
    
    This endpoint has additional restrictions beyond normal admin access:
    only the user "Ibrahim" can create new admin accounts. This provides
    an additional layer of security.
    
    Request Body:
        username (str): Username for new admin account
        password (str): Password for new admin account
        
    Returns:
        JSON response with success/error message and new admin ID
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

@bp.route('/questionsAll/', methods=["POST"])
@login_required 
def list_questions():
    """
    Returns metadata for all questions in the system.
    
    Provides a summary view of all questions without sensitive information
    like test cases. Used for admin question management interfaces.
    
    Returns:
        JSON array of question objects with basic metadata
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

# =============================================================================
# STATISTICS AND ANALYTICS SYSTEM
# =============================================================================

@bp.route("/overview", methods=["GET"])
@login_required
def get_tag_overview():
    """
    Generates comprehensive statistics overview by question tags.
    
    This endpoint aggregates submission statistics across all questions,
    grouping by tags to provide insights into:
    - Total attempts per topic area
    - Success rates by tag
    - Performance trends across different question categories
    
    The system handles:
    - Case-insensitive tag matching
    - Missing or empty tag fields
    - Tags that exist in questions but have no submission data
    
    Returns:
        JSON array of tag statistics with attempt counts and pass rates
    """
    try:
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

        raw_tags = db.session.execute(text("SELECT tags FROM question WHERE tags IS NOT NULL AND TRIM(tags) != ''"))
        question_tags = set()

        for row in raw_tags:
            tag_list = [t.strip() for t in row[0].split(',') if t.strip()]
            for t in tag_list:
                question_tags.add(t)

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

# =============================================================================
# QUESTION AND TAG MANAGEMENT
# =============================================================================

@bp.route("/test-delete/<int:question_id>", methods=["DELETE","POST"])
@login_required # Ensure user is logged in
def delete_question_via_post(question_id):
    """
    Deletes a question from the system.
    
    Supports both DELETE requests and POST requests with method override
    for compatibility with HTML forms. When a question is deleted, all
    associated statistics and test cases are also removed.
    
    Args:
        question_id (int): Database ID of question to delete
        
    Returns:
        JSON response confirming deletion or error if question not found
    """
    # The `check_access_control` before_request will handle the admin role check for this route.
    if request.method == "POST" and request.form.get("_method", "").upper() != "DELETE":
        return jsonify({"error": "Invalid method override"}), 400

    print(f"Attempting to delete question {question_id}")

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"message": f"Question {question_id} deleted"}), 200

# =============================================================================
# TAG SYSTEM AND METADATA QUERIES
# =============================================================================

@bp.route("/all-tags", methods=["GET"])
def get_all_tags():
    """
    Returns comprehensive list of all unique tags across all questions.
    
    This endpoint analyzes all questions in the database to extract and
    normalize tags, providing a complete vocabulary of available tags.
    Used for tag management interfaces and validation.
    
    Processing includes:
    - Comma-separated tag parsing
    - Whitespace trimming and normalization
    - Case normalization (lowercase for comparison, capitalized for display)
    - Duplicate removal and alphabetical sorting
    
    Returns:
        JSON array of unique, sorted tag names
    """
    # Fetch only the tags column
    questions = Question.query.with_entities(Question.tags).all()

    tag_set = set()
    for q in questions:
        if q.tags:
            # Split by comma, strip spaces, normalize to lowercase
            tag_list = [tag.strip().lower() for tag in q.tags.split(",") if tag.strip()]
            tag_set.update(tag_list)

    # Optional: capitalize first letter of each tag for display
    unique_tags = [tag.capitalize() for tag in tag_set]

    # Return sorted list
    return jsonify(sorted(unique_tags))

@bp.route("/question/<int:question_id>/difficulty", methods=["GET"])
def get_question_difficulty(question_id):
    """
    Retrieves difficulty level for a specific question.
    
    This lightweight endpoint returns only the difficulty rating
    without other question details. Used for filtering and
    display purposes in student interfaces.
    
    Args:
        question_id (int): Database ID of the question
        
    Returns:
        JSON object with difficulty level or error if not found
    """
    question = Question.query.get(question_id)

    if not question:
        return jsonify({"error": "Question not found"}), 404

    return jsonify({"difficulty": question.difficulty.lower().strip() if question.difficulty else None})

# =============================================================================
# QUESTION UPDATE AND MODIFICATION SYSTEM
# =============================================================================

@bp.route("/questions/<int:question_id>", methods=["POST", "PUT"])
@login_required # Ensure user is logged in
def update_question(question_id):
    """
    Updates existing question with new data.
    
    Supports both PUT requests and POST requests with method override
    for HTML form compatibility. Allows partial updates - only provided
    fields are modified, others remain unchanged.
    
    Request formats supported:
    1. JSON PUT request with data in body
    2. POST request with _method=PUT and JSON data in form field
    
    Args:
        question_id (int): Database ID of question to update
        
    Request Body:
        title (str, optional): New question title
        prompt_md (str, optional): New markdown prompt
        difficulty (str, optional): New difficulty level
        tags (str, optional): New comma-separated tags
        question_number (int, optional): New question number
        test_cases (str, optional): New JSON test cases
        
    Returns:
        JSON response confirming update or error
    """
    # The `check_access_control` before_request will handle the admin role check for this route.
    if request.method == "POST":
        override = request.form.get("_method", "").upper()
        if override != "PUT":
            return jsonify({"error": "Invalid method override"}), 400
        data_json = request.form.get("data")
        if not data_json:
            return jsonify({"error": "Missing data parameter"}), 400
        try:
            data = json.loads(data_json)
        except Exception as e:
            return jsonify({"error": f"Invalid JSON in data parameter: {str(e)}"}), 400
    else:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    question.title = data.get("title", question.title)
    question.prompt_md = data.get("prompt_md", question.prompt_md)
    question.difficulty = data.get("difficulty", question.difficulty)
    question.tags = data.get("tags", question.tags)
    question.question_number = data.get("question_number", question.question_number)
    question.test_cases = data.get("test_cases", question.test_cases)

    db.session.commit()
    return jsonify({"message": "Question updated"})

# =============================================================================
# TAG DELETION AND CLEANUP SYSTEM
# =============================================================================

@bp.route('/delete-tag/<tag_name>', methods=['POST', 'DELETE'])
@login_required 
def delete_tag(tag_name):
    """
    Removes a tag from all questions and associated statistics.
    
    This powerful admin function performs comprehensive tag cleanup:
    1. Removes tag from all question tag lists
    2. Cleans up comma formatting in remaining tags
    3. Deletes associated QuestionStat records for the tag
    4. Handles both SQLite and PostgreSQL regex operations
    
    The deletion process:
    - URL-decodes tag name for special characters
    - Uses case-insensitive matching to find all instances
    - Updates all affected questions atomically
    - Removes orphaned statistics records
    - Provides detailed feedback on affected questions
    
    Args:
        tag_name (str): URL-encoded tag name to delete
        
    Returns:
        JSON response with deletion results and affected question count
    """
    # The `check_access_control` before_request will handle the admin role check for this route.
    try:
        tag_name = urllib.parse.unquote(tag_name).lower()

        is_delete_request = (
            request.method == 'DELETE' or
            request.form.get('_method') == 'DELETE'
        )

        if is_delete_request:
            try:
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

                if 'sqlite' in str(db.engine.url):
                    questions_result = db.session.execute(
                        text("SELECT id, tags FROM question WHERE tags ILIKE :tag_pattern"),
                        {"tag_pattern": f'%{tag_name}%'}
                    )

                    for row in questions_result:
                        question_id, current_tags = row
                        if current_tags:
                            tag_list = [tag.strip() for tag in current_tags.split(',') if tag.strip()]
                            updated_tags = [tag for tag in tag_list if tag.lower() != tag_name.lower()]
                            new_tags_string = ','.join(updated_tags) if updated_tags else ''

                            db.session.execute(
                                text("UPDATE questions SET tags = :new_tags WHERE id = :question_id"),
                                {"new_tags": new_tags_string, "question_id": question_id}
                            )

                else:
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

                    db.session.execute(
                        text("UPDATE question SET tags = TRIM(BOTH ',' FROM tags) WHERE LOWER(tags) ILIKE ',%' OR tags ILIKE '%,'")
                    )

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

# =============================================================================
# STATISTICS MANAGEMENT AND RESET FUNCTIONALITY
# =============================================================================

@bp.route("/questions/stats/reset", methods=["DELETE", "POST"])
@login_required # Ensure user is logged in
def reset_all_stats():
    """
    Resets all question submission statistics to zero.
    
    This admin function clears all performance data across
    the entire system, returning all statistics to initial state.
    Used for:
    - Clearing test data during development
    - Resetting stats at start of new semester/course
    - Recovering from corrupted statistics data
    
    The reset process:
    - Finds all QuestionStat records
    - Sets attempts and passed counts to zero
    - Preserves the record structure for future submissions
    - Commits changes atomically
    
    Returns:
        JSON confirmation message
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

# =============================================================================
# DETAILED ANALYTICS AND REPORTING
# =============================================================================

@bp.route("/question-pass-stats", methods=["GET"])
@login_required 
def get_all_question_pass_stats():
    """
    Generates detailed pass/fail statistics for individual questions.
    
    This analytics endpoint provides comprehensive performance metrics
    for each question, enabling identification of:
    - Questions that are too difficult (low pass rates)
    - Questions that need better test cases
    - Overall course performance patterns
    - Content areas requiring attention
    
    Statistics calculated:
    - Total submission attempts per question
    - Successful completions (passed all test cases)
    - Failed attempts and failure rate
    - Pass rate percentage with rounding
    
    Returns:
        JSON array of question statistics with comprehensive metrics
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

        total_failed = total_attempts - total_passed
        pass_rate = (total_passed / total_attempts * 100) if total_attempts > 0 else 0

        results.append({
            "id": q.id,
            "title": q.title,
            "total_attempts": total_attempts,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "pass_rate": round(pass_rate, 2)
        })

    return jsonify(results)

# =============================================================================
# AUTHENTICATION SYSTEM WITH MULTIPLE LOGIN METHODS
# =============================================================================

@bp.route("/login", methods=["POST"])
def login():
    """
    Multi-method user authentication endpoint.
    
    This endpoint supports two authentication methods:
    1. Traditional username/password authentication
    2. Special admin login key for backdoor access
    
    Username/Password Flow:
    - Validates user exists in database
    - Checks password hash against stored value
    - Creates authenticated session with user info
    
    Login Key Flow:
    - Accepts 32-character special key
    - Automatically logs in as designated admin account
    - Bypasses normal password validation
    - Used for emergency admin access
    
    Both methods result in:
    - Flask-Login session establishment
    - Session cookie generation
    - User role and permissions activation
    
    Request Body:
        username (str, optional): Username for normal login
        password (str, optional): Password for normal login  
        login_key (str, optional): Special 32-char admin key
        
    Returns:
        JSON response with success message or authentication error
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    login_key = data.get("login_key")  # The special key

    logger.info(f"Login attempt: username={username}, key_provided={bool(login_key)}")

    # --- 1. KEY-BASED LOGIN ---
    if login_key:
            if login_key == "4fIEjhIwkfIIPcU2m4vYDdLe0ZFkDgzh":
                logger.info("Special login key matched — logging in as admin user")

                # Choose which account this key logs into
                user = User.query.filter_by(username="BackendAdmin").first()

                if not user:
                    logger.error("Admin user not found for key-based login")
                    return jsonify({"error": "Admin account missing"}), 500
            else:
                logger.warning("Invalid special login key attempt")
                return jsonify({"error": "Invalid key"}), 401

    else:
        # --- 2. USERNAME/PASSWORD LOGIN ---
        if not username or not password:
            return jsonify({"error": "Missing username or password"}), 400

        user = User.query.filter_by(username=username).first()

        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({"error": "Invalid credentials"}), 401

        if not check_password_hash(user.password_hash, password):
            logger.warning(f"Invalid password for user: {username}")
            return jsonify({"error": "Invalid credentials"}), 401

        logger.info(f"User authenticated via password: {user.username}")

    # --- Common login success flow ---
    session.clear()
    login_user(user, remember=True)

    session['user_id'] = user.id
    session['username'] = user.username
    session['role'] = user.role
    session.permanent = True

    logger.info(f"Successfully logged in user: {user.username}")
    logger.info(f"Session after login: {dict(session)}")

    # Generate session cookie
    session_interface = current_app.session_interface
    session_cookie = session_interface.get_signing_serializer(current_app).dumps(dict(session))

    cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')

    return jsonify({
        "message": "Logged in successfully",
        #"username": user.username,
        #"role": user.role,
        #"user_id": user.id,
        #"session_cookie": session_cookie,
        #"cookie_name": cookie_name
    })

@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """
    User logout endpoint.
    
    Terminates the current user session and clears authentication state.
    Available to any authenticated user regardless of role.
    
    Returns:
        JSON confirmation of logout completion
    """
    logout_user()
    return jsonify({"message": "Logged out"})

# =============================================================================
# MANUAL STATISTICS ADJUSTMENT SYSTEM
# =============================================================================

@bp.route("/tags/<tag_name>/submissions", methods=["POST"])
@role_required(["admin"])
def add_submission_to_tag(tag_name):
    """
    Manual statistics adjustment for specific tags.
    
    This specialized admin endpoint allows direct manipulation of tag-level
    statistics without requiring actual code submissions. Used for:
    - Correcting statistical errors
    - Importing data from external systems  
    - Testing statistical displays
    - Manual adjustments for special circumstances
    
    IMPORTANT: This only affects tag-level statistics, not individual
    question submission counts. The statistics are maintained at the
    tag level to provide aggregate performance metrics.
    
    Process:
    1. Validates tag exists in question database
    2. Finds or creates QuestionStat record for tag
    3. Updates attempt and pass counters based on submission type
    4. Preserves existing question-level submission data
    
    Args:
        tag_name (str): URL-encoded tag name to update
        
    Request Body:
        passed (bool): Whether this submission should count as passed
        
    Returns:
        JSON response with updated statistics and confirmation
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
        
        passed = data.get("passed")
        if passed is None:
            return jsonify({"error": "Missing 'passed' field (true/false)"}), 400

        tag_name = urllib.parse.unquote(tag_name).strip()

        questions = Question.query.all()
        tag_exists = False
        reference_question_id = None
        
        for q in questions:
            if q.tags:
                question_tags = [tag.strip().lower() for tag in q.tags.split(",") if tag.strip()]
                if tag_name.lower() in question_tags:
                    tag_exists = True
                    reference_question_id = q.id
                    break
        
        if not tag_exists:
            return jsonify({"error": f"Tag '{tag_name}' not found in any questions"}), 404
        
        stat = QuestionStat.query.filter_by(tag=tag_name).first()
        
        if not stat:
            stat = QuestionStat(
                question_id=reference_question_id, 
                tag=tag_name, 
                data={"attempts": 0, "passed": 0}
            )
            db.session.add(stat)
        

        current_attempts = stat.data.get("attempts", 0)
        current_passed = stat.data.get("passed", 0)
        
        stat.data = {
            "attempts": current_attempts + 1,
            "passed": current_passed + (1 if bool(passed) else 0)
        }
        
        # Force SQLAlchemy to detect the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(stat, 'data')
        
        db.session.commit()
        
        # Calculate response stats
        new_attempts = stat.data["attempts"]
        new_passed = stat.data["passed"]
        new_failed = new_attempts - new_passed
        pass_rate = round((new_passed / new_attempts * 100), 2) if new_attempts > 0 else 0.0
        
        return jsonify({
            "success": True,
            "message": f"Tag-only submission recorded for '{tag_name}'",
            "tag": tag_name,
            "submission_passed": bool(passed),
            "note": "Only tag statistics were updated, not question submission counts",
            "updated_stats": {
                "total_attempts": new_attempts,
                "total_passed": new_passed,
                "total_failed": new_failed,
                "pass_rate": pass_rate
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error adding tag-only submission to {tag_name}: {str(e)}")
        logger.debug(traceback.format_exc())
        return jsonify({"error": f"Failed to add tag submission: {str(e)}"}), 500