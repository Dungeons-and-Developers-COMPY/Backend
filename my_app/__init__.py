import os
from flask import Flask, send_from_directory
from flask_migrate import Migrate
from models import db

migrate = Migrate()

def create_app():
    # The root of the compiled Next.js export
    app = Flask(__name__, static_folder="static/out", static_url_path="")

    # ——— app / DB setup ———
    app.config.from_object("config.Config")
    db.init_app(app)
    migrate.init_app(app, db)

    # ——— API blueprints (keep them outside /admin UI) ———
    from my_app.routes.admin import bp as admin_api_bp
    app.register_blueprint(admin_api_bp, url_prefix="/admin")
    
    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")
    
    from my_app.routes.submissions import bp as submission_bp
    app.register_blueprint(submission_bp, url_prefix="/submissions")

    # ------------------------------------------------------------------
    #  FRONTEND  — everything lives under /admin
    # ------------------------------------------------------------------

    # 1)  /admin            → serve SPA entry
    @app.route("/admin")
    def admin_index():
        return send_from_directory(os.path.join(app.static_folder, "admin"), "index.html")

    # 2)  /admin/_next/...  → Next.js JS / CSS / fonts
    @app.route("/admin/_next/<path:filename>")
    def next_static(filename):
        print(os.path.join(app.static_folder, "admin", "_next", filename))
        return send_from_directory(
            os.path.join(app.static_folder, "admin", "_next"), filename
        )
        

    # 3)  /admin/<anything‑else> 
    #     → if the file exists, serve it (e.g. /admin/logo.png);
    #       otherwise fall back to index.html so Next Router can handle
    @app.route("/admin/<path:path>")
    def admin_catchall(path):
        full_path = os.path.join(app.static_folder, "admin", path)
        
        # If the requested file exists (e.g. CSS, JS, image)
        if os.path.exists(full_path):
            return send_from_directory(os.path.join(app.static_folder, "admin"), path)
        
        # Fallback to SPA routing (React/Next)
        return send_from_directory(os.path.join(app.static_folder, "admin"), "index.html")


    return app
