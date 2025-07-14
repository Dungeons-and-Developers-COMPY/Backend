import os
from flask import Flask, send_from_directory, current_app
from flask_migrate import Migrate
from models import db, User
from flask_login import LoginManager, login_required, current_user
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv() 

# Initialize extensions
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    # ------------------ Flask App Setup ------------------
    app = Flask(__name__, static_folder="static/out", static_url_path="")

    # Load secret key and config
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
    app.config.from_object("config.Config")

    # Initialize database and migration
    db.init_app(app)
    migrate.init_app(app, db)

    # ------------------ Login Manager Setup ------------------
    login_manager.init_app(app)
    login_manager.login_view = 'admin.login' 

    @login_manager.user_loader
    def load_user(user_id):
        """
        Callback to reload the user object from the user ID stored in the session.
        """
        return User.query.get(int(user_id))

    # ------------------ Register Blueprints ------------------
    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")

    from my_app.routes.admin import bp as admin_api_bp
    app.register_blueprint(admin_api_bp, url_prefix="/admin")

    from my_app.routes.student import student_bp
    app.register_blueprint(student_bp, url_prefix="/student")

    # ------------------ Frontend Entry Points ------------------

    @app.route("/")
    def root_login():
        """
        Serves the main login page.
        """
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/admin")
    @app.route("/admin/")
    def serve_admin():
        """
        Serves the admin dashboard page.
        """
        return send_from_directory(app.static_folder, "admin.html")

    @app.route("/student")
    @login_required
    def serve_student():
        """
        Serves the student dashboard page.
        Ensures the logged-in user has the 'user' role.
        """
        if current_user.role != "student":
            return "Unauthorized", 403
        return send_from_directory(os.path.join(app.static_folder, "student"), "student.html")

    # ------------------ Static Assets Catch-All ------------------

    @app.route("/<path:path>")
    def catch_all(path):
        """
        Serves static assets such as JS bundles, CSS, fonts, etc.
        """
        full_path = os.path.join(app.static_folder, path)
        if os.path.exists(full_path):
            return send_from_directory(app.static_folder, path)
        return "Not Found", 404

    return app
