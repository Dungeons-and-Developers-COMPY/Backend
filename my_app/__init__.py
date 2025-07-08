import os
from flask import Flask, send_from_directory
from flask_migrate import Migrate
from models import db, User
from flask_login import LoginManager
from flask_login import login_required, current_user
from flask import current_app

from dotenv import load_dotenv
load_dotenv() 

migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, static_folder="static/out", static_url_path="")

    app.config.from_object("config.Config")
    db.init_app(app)
    migrate.init_app(app, db)

    login_manager.init_app(app)
    login_manager.login_view = 'admin.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- API Blueprints ---
    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")

    from my_app.routes.submissions import bp as submission_bp
    app.register_blueprint(submission_bp, url_prefix="/submissions")

    from my_app.routes.admin import bp as admin_api_bp
    app.register_blueprint(admin_api_bp, url_prefix="/admin")
    
    from my_app.routes.student import student_bp
    app.register_blueprint(student_bp, url_prefix="/student")


    # --- Serve Different Frontend Entrypoints ---

    @app.route("/")
    def root_login():
        return send_from_directory(app.static_folder, "index.html")  # login page

    @app.route("/admin")
    @app.route("/admin/")
    @login_required
    def serve_admin():
        return send_from_directory(app.static_folder, "admin.html")
    
    @app.route("/student")
    @login_required
    def serve_student():
        if current_user.role != "user":
            return "Unauthorized", 403
        return send_from_directory(os.path.join(app.static_folder, "student"), "student.html")

    # Static assets (e.g. /_next, CSS, fonts, etc.)
    @app.route("/<path:path>")
    def catch_all(path):
        full_path = os.path.join(app.static_folder, path)
        if os.path.exists(full_path):
            return send_from_directory(app.static_folder, path)
        return "Not Found", 404

    return app
