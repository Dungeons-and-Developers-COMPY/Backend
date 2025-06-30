from flask import Blueprint, request, jsonify
from models import db, Question

bp = Blueprint('questions', __name__)

@bp.route("/", methods=["POST"])
def create_question():
    try:
        data = request.get_json()
        # Log received data for debugging
        print("Received data:", data)

        question = Question(
            title=data["title"],
            prompt_md=data["prompt"],
            difficulty=data["difficulty"],
            tags=data.get("tags", ""),
            test_cases=data.get("test_cases", "")
        )
        db.session.add(question)
        db.session.commit()
        return jsonify({"message": "Question added"}), 201
    except Exception as e:
        print("Error creating question:", e)
        return jsonify({"error": str(e)}), 400

@bp.route("/", methods=["GET"])
def get_questions():
    questions = Question.query.all()
    questions_list = [{
        "id": q.id,
        "title": q.title,
        "prompt_md": q.prompt_md,
        "difficulty": q.difficulty,
        "tags": q.tags,
        "test_cases": q.test_cases
    } for q in questions]
    return jsonify(questions_list)

# Delete a question by ID
@bp.route("/<int:question_id>", methods=["DELETE"])
def delete_question(question_id):
    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"message": "Question deleted"})


# Update a question
@bp.route("/<int:question_id>", methods=["PUT"])
def update_question(question_id):
    data = request.get_json()
    question = Question.query.get(question_id)
    
    if not question:
        return jsonify({"error": "Question not found"}), 404

    question.title = data.get("title", question.title)
    question.prompt_md = data.get("prompt", question.prompt_md)
    question.difficulty = data.get("difficulty", question.difficulty)
    question.tags = data.get("tags", question.tags)
    question.test_cases = data.get("test_cases", question.test_cases)

    db.session.commit()
    return jsonify({"message": "Question updated"})
