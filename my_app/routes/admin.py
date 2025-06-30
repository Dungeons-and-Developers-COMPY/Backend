from flask import Blueprint, jsonify
from models import Question

bp = Blueprint('admin', __name__)

@bp.route('/questions')
def list_questions():
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
