from flask import Blueprint, request, jsonify
from models import db, Question, QuestionStat, User
import io
import contextlib
import json
import random
import ast, builtins, sys
from flask import request, session
from werkzeug.security import check_password_hash

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
    question.prompt_md = data.get("prompt_md", question.prompt_md)
    question.difficulty = data.get("difficulty", question.difficulty)
    question.tags = data.get("tags", question.tags)
    question.question_number = data.get("question_number", question.question_number)
    question.test_cases = data.get("test_cases", question.test_cases)

    db.session.commit()
    return jsonify({"message": "Question updated"})

@bp.route("/stats/<int:question_number>", methods=["POST"])
def evaluate_and_record_stats(question_number):
    data = request.get_json(silent=True)
    if not data or "code" not in data:
        return jsonify({"error": "Missing JSON body or 'code' field"}), 400
    user_code = data["code"]

    question = Question.query.filter_by(question_number=question_number).first()
    if not question:
        return jsonify({"error": f"Question {question_number} not found"}), 404

    try:
        test_cases = json.loads(question.test_cases or "[]")
    except json.JSONDecodeError as e:
        return jsonify({"error": "Invalid test case format", "details": str(e)}), 500

    all_passed = True
    failed_case = None
    error_occurred = False
    error_msg = ""

    # Prepare an exec environment dictionary to capture the function
    exec_env = {}

    try:
        exec(user_code, exec_env)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Code compilation error: {str(e)}"
        }), 200

    func = exec_env.get("func")
    if not callable(func):
        return jsonify({
            "success": False,
            "error": "Function 'func' not found in submitted code."
        }), 200

    for case in test_cases:
        raw_input_data = case["input"]
        expected_output = case["output"]

        try:
            # Parse input to Python object
            parsed_input = ast.literal_eval(raw_input_data)
        except Exception:
            parsed_input = raw_input_data  

        try:
            # Call student function with the parsed input
            result = func(parsed_input)

            # Convert result to string for comparison (adjust if output format differs)
            result_str = str(result).strip()

            if result_str != expected_output.strip():
                all_passed = False
                failed_case = case
                break
        except Exception as e:
            error_occurred = True
            error_msg = str(e)
            failed_case = case
            all_passed = False
            break

    # Update stats, commit, and respond as before...

    # Record stats
    tags = (question.tags or "").split(",")  # assume comma-separated tags
    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue
        stat = QuestionStat.query.filter_by(question_id=question.id, tag=tag).first()
        if not stat:
            stat = QuestionStat(question_id=question.id, tag=tag, data={})
            db.session.add(stat)
        stat.bump(passed=all_passed)

    db.session.commit()

    if error_occurred:
        return jsonify({
            "success": False,
            "error": f"Code runtime error: {error_msg}",
            "failed_case": failed_case
        }), 200

    if all_passed:
        return jsonify({
            "success": True,
            "message": "All test cases passed!",
            "question_number": question_number
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "At least one test case failed.",
            "failed_case": failed_case,
            "expected": expected_output,
            "got": result_str,
            "question_number": question_number
        }), 200



@bp.route("/stats/<int:question_number>", methods=["GET"])
def get_question_stats(question_number):
    question = Question.query.filter_by(question_number=question_number).first()
    if not question:
        return jsonify({"error": f"Question {question_number} not found"}), 404

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

@bp.route("/random/<difficulty>", methods=["GET"])
def get_random_question_by_difficulty(difficulty):
    try:
        # Query questions matching difficulty (case-insensitive)
        questions = Question.query.filter(
            db.func.lower(Question.difficulty) == difficulty.lower()
        ).all()

        if not questions:
            return jsonify({"error": f"No questions found for difficulty '{difficulty}'."}), 404

        # Choose a random question
        question = random.choice(questions)

        # Return the question data
        return jsonify({
            "id": question.id,
            "title": question.title,
            "prompt_md": question.prompt_md,
            "difficulty": question.difficulty,
            "tags": question.tags,
            "question_number": question.question_number,
            "test_cases": question.test_cases
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500