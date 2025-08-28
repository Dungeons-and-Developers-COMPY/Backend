from flask import Blueprint, request, jsonify, session, send_from_directory, g
from models import db, Question, QuestionStat, User
from werkzeug.security import check_password_hash
import io
import contextlib
import ast, builtins, sys, json, random
import os
from base64 import b64decode
from flask_login import current_user, login_required

qbp = Blueprint('questions', __name__)
        
# ------------------ Get All Questions ------------------
@qbp.route("/", methods=["GET"])
def get_questions():
    """
    Returns a list of all coding questions.
    """
    questions = Question.query.all()
    return jsonify([{
        "id": q.id,
        "title": q.title,
        "prompt_md": q.prompt_md,
        "difficulty": q.difficulty,
        "tags": q.tags,
        "question_number": q.question_number,
        "test_cases": q.test_cases
    } for q in questions])


# ------------------ Get Question Stats ------------------
@qbp.route("/stats/<int:question_number>", methods=["GET"])
def get_question_stats(question_number):
    """
    Retrieves attempt and pass stats for a given question.
    """
    question = Question.query.filter_by(question_number=question_number).first()
    if not question:
        return jsonify({"error": f"Question {question_number} not found"}), 404

    stats = QuestionStat.query.filter_by(question_id=question.id).all()
    if not stats:
        return jsonify({"message": "No stats found for this question."}), 404

    result = [{
        "tag": stat.tag,
        "total_attempts": stat.data.get("attempts", 0),
        "total_passed": stat.data.get("passed", 0)
    } for stat in stats]

    return jsonify(result)

# ------------------ Get Random Question by Difficulty ------------------
@qbp.route("/random/<difficulty>", methods=["GET"])
def get_random_question_by_difficulty(difficulty):
    """
    Returns a random question with the given difficulty level.
    Ensures all questions are cycled through before repeating.
    """
    try:
        # Fetch all questions of this difficulty
        questions = Question.query.filter(
            db.func.lower(Question.difficulty) == difficulty.lower()
        ).all()

        if not questions:
            return jsonify({"error": f"No questions found for difficulty '{difficulty}'."}), 404

        # Session key specific to this difficulty
        session_key = f"shuffled_questions_{difficulty.lower()}"

        # Initialize shuffled order if not in session or empty
        if session_key not in session or not session[session_key]:
            q_ids = [q.id for q in questions]
            random.shuffle(q_ids)
            session[session_key] = q_ids

        # Pop the next question ID
        qid = session[session_key].pop()
        session.modified = True  # ensure Flask saves session changes

        # Retrieve the actual question
        question = Question.query.get(qid)

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
