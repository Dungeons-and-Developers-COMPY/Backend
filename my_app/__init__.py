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
    # The root of the compiled Next.js export
    app = Flask(__name__, static_folder="static/out", static_url_path="")

    # ——— app / DB setup ———
    app.config.from_object("config.Config")
    db.init_app(app)
    migrate.init_app(app, db)

    login_manager.init_app(app)
    login_manager.login_view = 'admin.login'  # your login route

    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    app.config["ENABLE_ADMIN"] = os.getenv("ENABLE_ADMIN", "False").lower() == "true"

    # ——— API blueprints (keep them outside /admin UI) ———

    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")
    
    from my_app.routes.submissions import bp as submission_bp
    app.register_blueprint(submission_bp, url_prefix="/submissions")

    from my_app.routes.admin import bp as admin_api_bp
    app.register_blueprint(admin_api_bp, url_prefix="/admin")
    
    # ------------------------------------------------------------------
    #  FRONTEND  — everything lives under /admin
    # ------------------------------------------------------------------

    # 1)  /admin            → serve SPA entry
    @app.route("/admin")
    @login_required
    def admin_index():
        return send_from_directory(os.path.join(app.static_folder, "admin"), "index.html")

    # 2)  /admin/_next/...  → Next.js JS / CSS / fonts
    @app.route("/admin/<path:path>")
    def admin_catchall(path):
        full_path = os.path.join(app.static_folder, "admin", path)

        if os.path.exists(full_path):
            return send_from_directory(os.path.join(app.static_folder, "admin"), path)
        return send_from_directory(os.path.join(app.static_folder, "admin"), "index.html")

    return app
