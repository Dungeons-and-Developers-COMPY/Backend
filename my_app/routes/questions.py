from flask import Blueprint, request, jsonify
from models import db, Question
import io
import contextlib
import json

bp = Blueprint('questions', __name__)

@bp.route("/", methods=["POST"])
def create_question():
    try:
        data = request.get_json()
        print("Received data:", data)

        question = Question(
            title=data["title"],
            prompt_md=data["prompt"],
            difficulty=data["difficulty"],
            tags=data.get("tags", ""),
            question_number=data["question_number"],
            test_cases=data.get("test_cases", "[]") 
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
        "question_number": q.question_number,
        "test_cases": q.test_cases
    } for q in questions]
    return jsonify(questions_list)

@bp.route("/<int:question_id>", methods=["DELETE"])
def delete_question(question_id):
    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"message": "Question deleted"})

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
    question.question_number = data.get("question_number", question.question_number)

    db.session.commit()
    return jsonify({"message": "Question updated"})


@bp.route("/evaluate/<int:question_id>", methods=["POST"])
def evaluate_code(question_id):
    data = request.get_json()
    user_code = data.get("code")

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    try:
        test_cases = json.loads(question.test_cases)
    except Exception as e:
        print("Failed to parse test_cases:", question.test_cases)
        print("Error:", e)
        return jsonify({"error": "Invalid test case format", "details": str(e)}), 500


    # Test each case
    for case in test_cases:
        input_data = case["input"]
        expected_output = case["output"]

        # Capture output
        f = io.StringIO()
        try:
            with contextlib.redirect_stdout(f):
                exec(user_code, {"input": lambda: input_data})
            output = f.getvalue().strip()
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Code error: {str(e)}",
                "failed_case": case
            })

        if output != expected_output:
            return jsonify({
                "success": False,
                "message": "Test case failed",
                "input": input_data,
                "expected": expected_output,
                "got": output
            })

    return jsonify({"success": True, "message": "All test cases passed!"})