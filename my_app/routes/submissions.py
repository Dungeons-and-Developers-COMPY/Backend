from flask import Blueprint, request, jsonify
from ..services.grader import grade_python
from models import db, Submission, Question

bp = Blueprint('submissions', __name__)

@bp.route("/", methods=["POST"])
def submit():
    data = request.get_json()
    question = Question.query.get(data["question_id"])
    code = data["code"]

    passed = grade_python(code, question.test_cases)
    
    submission = Submission(
        question_id=question.id,
        user_id=data["user_id"],
        code=code,
        language="python",
        status="pass" if passed else "fail",
        score=1.0 if passed else 0.0
    )
    db.session.add(submission)
    db.session.commit()
    
    return jsonify({"status": submission.status})
