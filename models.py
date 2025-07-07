import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import JSON
from dotenv import load_dotenv
from sqlalchemy.ext.mutable import MutableDict
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

load_dotenv()
db = SQLAlchemy()

# ────────────────────────────────────────────────────────────────────────────────
#  Core tables 
# ────────────────────────────────────────────────────────────────────────────────

class User(db.Model,UserMixin):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role          = db.Column(db.String(20), default="user")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Question(db.Model):
    __tablename__   = "question"
    id              = db.Column(db.Integer, primary_key=True)
    title           = db.Column(db.String(128), nullable=False)
    prompt_md       = db.Column(db.Text)
    question_number = db.Column(db.Integer, nullable=False, unique=True)  # unique recommended
    difficulty      = db.Column(db.String(20))
    tags            = db.Column(db.String(255))
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)
    test_cases      = db.Column(db.Text)

class Submission(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"))
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"))
    code        = db.Column(db.Text)
    language    = db.Column(db.String(20))
    status      = db.Column(db.String(20))
    score       = db.Column(db.Float)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class QuestionStat(db.Model):
    __tablename__ = "question_stat"

    id          = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer,
                            db.ForeignKey('question.id', ondelete='CASCADE'),
                            nullable=False)
    tag  = db.Column(db.String(100), nullable=False)

    # make JSON mutable so in‑place changes are tracked
    data = db.Column(MutableDict.as_mutable(JSON), nullable=False, default=lambda: {})

    __table_args__ = (db.UniqueConstraint('question_id', 'tag',
                                          name='uq_stat_qid_tag'),)

    def bump(self, passed=False):
        if self.data is None:
            self.data = {"attempts": 0, "passed": 0}

        self.data["attempts"] = self.data.get("attempts", 0) + 1
        if passed:
            self.data["passed"] = self.data.get("passed", 0) + 1

