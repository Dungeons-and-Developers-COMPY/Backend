# your create_app (fix Migrate usage and imports)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import render_template

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)  # use the Migrate instance here!

    # Blueprints

    from my_app.routes.admin import bp as admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    from my_app.routes.questions import bp as question_bp
    app.register_blueprint(question_bp, url_prefix="/questions")

    from my_app.routes.submissions import bp as submission_bp
    app.register_blueprint(submission_bp, url_prefix="/submissions")

    @app.route('/')
    def index():
        return render_template('index.html')

    return app
