from flask_sqlalchemy import SQLAlchemy
from my_app import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20))  # student / admin

class Question(db.Model):
    __tablename__ = 'question'    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    prompt_md = db.Column(db.Text)
    difficulty = db.Column(db.String(20))
    tags = db.Column(db.String(255))
    test_cases = db.Column(db.Text)
    created_at = db.Column(db.DateTime)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    code = db.Column(db.Text)
    language = db.Column(db.String(20))
    status = db.Column(db.String(20))
    score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
