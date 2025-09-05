"""
    Creates and configures the Flask application.

    This function initializes the Flask app with extensions, blueprints,
    login manager, static file serving, and session configuration.

    Use Cases:
    - Central application factory for running the Flask server
    - Ensures all blueprints are registered and extensions initialized
    - Configures secure session cookies and login management
    - Serves frontend pages and static assets

    Process:
    1. Initializes Flask app with custom static folder.
    2. Sets up method override for form _method POST tunneling.
    3. Configures secret key and session settings.
    4. Initializes database and migration extensions.
    5. Configures Flask-Login manager, user loader, and session protection.
    6. Registers all blueprints for admin, questions, student, and server routes.
    7. Defines routes to serve frontend pages (login, dashboards, game pages).
    8. Adds catch-all route to serve static assets.

    Returns:
        Flask app instance, fully configured
"""
import os
from flask import Flask, send_from_directory, current_app, request, redirect
from flask_migrate import Migrate
from models import db, User
from flask_login import LoginManager, login_required, current_user
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv() 

migrate = Migrate()
login_manager = LoginManager()

def create_app():
    # ------------------ Flask App Setup ------------------
    app = Flask(__name__, static_folder="static/out", static_url_path="")
    
    @app.before_request
    def method_override():
        if request.method == "POST":
            override = request.form.get("_method")
            if override:
                request.environ["REQUEST_METHOD"] = override.upper()

    # Unified secret key configuration
    secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-fallback') 
    app.config['SECRET_KEY'] = secret_key
    app.secret_key = secret_key 
    
    # Session cookie configuration
    app.config['SESSION_COOKIE_SECURE'] = True  
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
    
    # Load other config
    app.config.from_object("config.Config")

    # Initialize database and migration
    db.init_app(app)
    migrate.init_app(app, db)

    # ------------------ Login Manager Setup ------------------
    login_manager.init_app(app)
    login_manager.login_view = 'admin.login'
    login_manager.session_protection = None 
    
    @login_manager.user_loader
    def load_user(user_id):
        """
        User loader callback for Flask-Login.

        Reloads a user from the database using the user ID stored in the session.

        Args:
            user_id (str or int): ID of the user stored in session

        Returns:
            User instance or None if user not found
        """
        return User.query.get(int(user_id))

    # ------------------ Register Blueprints ------------------
    
    from my_app.routes.admin import bp as admin_api_bp
    app.register_blueprint(admin_api_bp, url_prefix="/admin")
    
    from my_app.routes.questions import qbp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")

    from my_app.routes.student import student_bp
    app.register_blueprint(student_bp, url_prefix="/student")

    from my_app.routes.server import server_bp
    app.register_blueprint(server_bp, url_prefix="/server")
    
    # ------------------ Frontend Entry Points ------------------

    @app.route("/")
    def root_login():
        """
        Root login page route.

        Serves the main login page for the application.

        Returns:
            index.html from the static folder
        """
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/go-home", methods=["GET", "POST"])
    @login_required
    def go_home():
        """
        Go-home redirect route.

        Used for form submissions or navigation that should redirect the user
        to the root login page. Requires authentication.

        Returns:
            302 redirect to '/'
        """
        return redirect("/", code=302)
    
    @app.route("/admin")
    @app.route("/admin/")
    def serve_admin():
        """
        Admin dashboard page route.

        Serves the admin interface for managing questions, users, and statistics.

        Returns:
            admin.html from the static folder
        """
        return send_from_directory(app.static_folder, "admin.html")


    @app.route("/student")
    @login_required
    def serve_student():
        """
        Student dashboard page route.

        Serves the main student interface. Requires authentication and
        ensures the logged-in user has the 'student' role.

        Returns:
            student.html from the static folder
            or 403 if user is not a student
        """
        if current_user.role != "student":
            return "Unauthorized", 403
        return send_from_directory(app.static_folder, "student.html") 

    @app.route("/student/1v1")
    @login_required
    def serve_student_1v1():
        """
        1v1 game page route for students.

        Serves the 1v1 game interface. Requires authentication and
        student role.

        Returns:
            student/1v1.html from the static folder
            or 403 if user is not a student
        """
        if current_user.role != "student":
            return "Unauthorized", 403
        return send_from_directory(os.path.join(app.static_folder, "student"), "1v1.html")

    @app.route("/student/2v2")
    @login_required
    def serve_student_2v2():
        """
        2v2 game page route for students.

        Serves the 2v2 game interface. Requires authentication and
        student role.

        Returns:
            student/2v2.html from the static folder
            or 403 if user is not a student
        """
        if current_user.role != "student":
            return "Unauthorized", 403
        return send_from_directory(os.path.join(app.static_folder, "student"), "2v2.html")

    # ------------------ Static Assets Catch-All ------------------

    @app.route("/<path:path>")
    def catch_all(path):
        """
        Catch-all route for static assets.

        Serves JS bundles, CSS files, fonts, images, and other static content.
        If the requested asset does not exist, returns 404.

        Args:
            path (str): Path of the requested static asset

        Returns:
            File from the static folder or 404 if not found
        """
        full_path = os.path.join(app.static_folder, path)
        if os.path.exists(full_path):
            return send_from_directory(app.static_folder, path)
        return "Not Found", 404

    return app