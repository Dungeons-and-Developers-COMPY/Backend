import os
from flask import Flask, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import db

migrate = Migrate()

def create_app():
    app = Flask(__name__, static_folder='static/out', static_url_path='')

    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)  

    from my_app.routes.admin import bp as admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")

    from my_app.routes.submissions import bp as submission_bp
    app.register_blueprint(submission_bp, url_prefix="/submissions")

    # Serve React frontend
    @app.route('/')
    def serve_react():
        return send_from_directory(app.static_folder, 'index.html')

    # Catch-all route for frontend routing (React Router)
    @app.route('/<path:path>')
    def catch_all(path):
        if os.path.exists(os.path.join(app.static_folder, path)):
            return send_from_directory(app.static_folder, path)
        else:
            return send_from_directory(app.static_folder, 'index.html')

    @app.route('/list-files')
    def list_files():
        files = os.listdir(app.static_folder)
        return '<br>'.join(files)

    return app
