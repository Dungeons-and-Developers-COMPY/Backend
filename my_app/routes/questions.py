from flask import Blueprint, request, jsonify
from models import db, Question, QuestionStat
import io
import contextlib
import json

bp = Blueprint('questions', __name__)

@bp.route("/", methods=["POST"])
def create_question():
    try:
        data = request.get_json()
        print("Received data:", data)

        # Get existing question_numbers directly as integers
        existing_numbers = {
            q.question_number
            for q in Question.query.with_entities(Question.question_number)
            if isinstance(q.question_number, int)
        }

        # Find the first available number starting from 1
        question_number = 1
        while question_number in existing_numbers:
            question_number += 1

        # Create the question
        question = Question(
            title=data["title"],
            prompt_md=data["prompt_md"],
            difficulty=data["difficulty"],
            tags=data.get("tags", ""),
            question_number=question_number,
            test_cases=data.get("test_cases", "[]")
        )

        db.session.add(question)
        db.session.commit()

        return jsonify({
            "message": "Question added",
            "question_number": question.question_number,
            "id": question.id
        }), 201

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
    question =  Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    db.session.delete(question)
    db.session.commit()
    return jsonify({"message": "Question deleted"})

@bp.route("/<int:question_id>", methods=["PUT"])
def update_question(question_id):
    data = request.get_json()
    question =  Question.query.get(question_id)

    if not question:
        return jsonify({"error": "Question not found"}), 404

    question.title = data.get("title", question.title)
    question.prompt_md = data.get("prompt", question.prompt_md)
    question.difficulty = data.get("difficulty", question.difficulty)
    question.tags = data.get("tags", question.tags)
    question.question_number = data.get("question_number", question.question_number)

    db.session.commit()
    return jsonify({"message": "Question updated"})

@bp.route("/stats/<int:question_id>", methods=["POST"])
def evaluate_and_record_stats(question_id):
    data = request.get_json()
    user_code = data.get("code")
    
    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    try:
        test_cases = json.loads(question.test_cases or "[]")
    except Exception as e:
        return jsonify({"error": "Invalid test case format", "details": str(e)}), 500

    all_passed = True
    failed_case = None
    error_occurred = False
    output = None
    expected_output = None

    for case in test_cases:
        input_data = case["input"]
        expected_output = case["output"]

        f = io.StringIO()
        try:
            with contextlib.redirect_stdout(f):
                exec(user_code, {"input": lambda: input_data})
            output = f.getvalue().strip()
        except Exception as e:
            all_passed = False
            error_occurred = True
            failed_case = case
            error_msg = str(e)
            break

        if output != expected_output:
            all_passed = False
            failed_case = case
            break

    tags = [t.strip() for t in (question.tags or "").split(",") if t.strip()] or ["_UNTAGGED_"]

    for tag in tags:
        stat = QuestionStat.query.filter_by(question_id=question.id, tag=tag).one_or_none()
        if not stat:
            stat = QuestionStat(question_id=question.id, tag=tag)
            db.session.add(stat)

        stat.bump(passed=all_passed and not error_occurred)

    db.session.commit()

    if error_occurred:
        return jsonify({
            "success": False,
            "error": f"Code error: {error_msg}",
            "failed_case": failed_case
        })

    if all_passed:
        return jsonify({"success": True, "message": "All test cases passed!"})
    else:
        return jsonify({
            "success": False,
            "message": "At least one test case failed.",
            "failed_case": failed_case,
            "expected": expected_output,
            "got": output
        })


@bp.route("/stats/<int:question_id>", methods=["GET"])
def get_question_stats(question_id):
    question = Question.query.get(question_id)

    if not question:
        return jsonify({"error": "Question not found"}), 404

    stats = QuestionStat.query.filter_by(question_id=question.id).all()

    if not stats:
        return jsonify({"message": "No stats found for this question."}), 404

    result = []
    for stat in stats:
        result.append({
            "tag": stat.tag,
            "total_attempts": stat.data.get("attempts", 0),
            "total_passed": stat.data.get("passed", 0)
        })

    return jsonify(result)


@bp.route("/stats/reset", methods=["DELETE"])
def reset_all_stats():
    stats = QuestionStat.query.all()
    for stat in stats:
        stat.data = {"attempts": 0, "passed": 0}
    db.session.commit()
    return jsonify({"message": "All question stats have been reset."})
