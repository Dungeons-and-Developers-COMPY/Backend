from flask import Blueprint, request, jsonify, current_app, redirect
from flask_login import current_user
from functools import wraps
import datetime
import logging
from models import User, db
from functools import wraps

server_bp = Blueprint('server', __name__)

logger = logging.getLogger(__name__)

active_servers = []

def role_required(roles):
    """
    Decorator to restrict access to certain user roles or allow server key authentication.

    This decorator is applied to Flask routes to enforce role-based access control
    while optionally allowing a special server key to bypass normal authentication.

    Use Cases:
    - Restricting endpoints to specific roles (e.g., admin, student)
    - Allowing trusted servers to access endpoints via a secret key
    - Logging unauthorized access attempts for auditing purposes

    Process:
    1. Converts a single role string into a list if needed.
    2. Wraps the route function.
    3. Checks for a valid 'ServerKey' in request headers.
    - If the key matches, bypasses normal authentication.
    4. If no server key, checks if the user is authenticated.
    - Returns 401 error if not authenticated.
    5. Verifies that the user has one of the required roles.
    - Returns 403 error and logs a warning if access is denied.
    6. If all checks pass, executes the original route function.

    Args:
        roles (str or list[str]): Allowed roles for accessing the endpoint.

    Returns:
        Decorated function that enforces role-based access control.
    """

    if not isinstance(roles, (list, tuple)):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            server_key = request.headers.get("ServerKey")
            if server_key == "4fIEjhIwkfIIPcU2m4vYDdLe0ZFkDgzh":
                # Allow bypass with server key
                return f(*args, **kwargs)

            if not current_user.is_authenticated:
                return jsonify({"error": "Authentication required"}), 401

            if not hasattr(current_user, "role") or current_user.role not in roles:
                logger.warning(
                    f"Access denied for user {getattr(current_user, 'username', 'UNKNOWN')} "
                    f"(role: {getattr(current_user, 'role', 'NONE')}) trying to access {request.endpoint}. "
                    f"Required roles: {roles}"
                )
                return jsonify({"error": f"Access denied: Requires one of {', '.join(roles)} roles"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@server_bp.route("/register", methods=["POST"])
@role_required(["admin", "student"])
def register_server():
    """
    Registers a new game server.

    Allows admins or students with proper roles to add a server to the active
    server pool for 1v1 or 2v2 matches. Ensures no duplicates and validates
    required fields.

    Process:
    1. Validates JSON body exists.
    2. Checks required fields: ip, port, type, max_players.
    3. Validates server type ('1v1' or '2v2').
    4. Checks if server is already registered.
    5. Adds server to active_servers list with registration timestamp.

    Request Body:
        ip (str): Server IP address
        port (int): Server port
        type (str): Match type ('1v1' or '2v2')
        max_players (int): Maximum number of players
        current_players (int, optional): Current player count (default 0)

    Returns:
        JSON with confirmation and server info
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    required_fields = ["ip", "port", "type", "max_players"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate server type
    if data["type"] not in ["1v1", "2v2"]:
        return jsonify({"error": "Server type must be '1v1' or '2v2'"}), 400
    
    # Check if server already exists
    server_key = f"{data['ip']}:{data['port']}"
    for server in active_servers:
        if f"{server['ip']}:{server['port']}" == server_key:
            return jsonify({"error": "Server already registered"}), 409
    
    # Add server to active list
    server_info = {
        "ip": data["ip"],
        "port": int(data["port"]),
        "type": data["type"],
        "max_players": int(data["max_players"]),
        "current_players": int(data.get("current_players", 0)),
        "registered_at": datetime.datetime.now().isoformat()
    }
    
    active_servers.append(server_info)
    
    logger.info(f"Server registered: {server_key} ({data['type']})")
    
    return jsonify({
        "message": "Server registered successfully",
        "server_info": server_info
    }), 201


@server_bp.route("/deregister", methods=["POST"])
@role_required(["admin", "student"])
def deregister_server():
    """
    Deregisters an active game server.

    Removes a server from the active server pool for maintenance,
    shutdown, or cleanup purposes.

    Process:
    1. Validates JSON body exists.
    2. Checks required fields: ip, port.
    3. Searches active_servers for matching server.
    4. Removes server if found.

    Request Body:
        ip (str): Server IP address
        port (int): Server port

    Returns:
        JSON with confirmation and removed server info
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    if "ip" not in data or "port" not in data:
        return jsonify({"error": "Missing required fields: ip, port"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    for i, server in enumerate(active_servers):
        if f"{server['ip']}:{server['port']}" == server_key:
            removed_server = active_servers.pop(i)
            logger.info(f"Server deregistered: {server_key}")
            return jsonify({
                "message": "Server deregistered successfully",
                "server_info": removed_server
            }), 200
    
    return jsonify({"error": "Server not found"}), 404


@server_bp.route("/update-players", methods=["POST"])
@role_required(["admin", "student"])
def update_player_count():
    """
    Updates the current player count for a server.

    Ensures accurate tracking of player numbers on each server.

    Process:
    1. Validates JSON body exists.
    2. Checks required fields: ip, port, current_players.
    3. Searches active_servers for matching server.
    4. Updates current_players count.

    Request Body:
        ip (str): Server IP address
        port (int): Server port
        current_players (int): Number of players currently on the server

    Returns:
        JSON with confirmation and updated server info
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    required_fields = ["ip", "port", "current_players"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    for server in active_servers:
        if f"{server['ip']}:{server['port']}" == server_key:
            old_count = server["current_players"]
            server["current_players"] = int(data["current_players"])
            
            logger.info(f"Server {server_key} player count updated: {old_count} -> {server['current_players']}")
            
            return jsonify({
                "message": "Player count updated successfully",
                "server_info": server
            }), 200
    
    return jsonify({"error": "Server not found"}), 404


@server_bp.route("/find-available", methods=["GET"])
@role_required(["admin", "student"])
def find_available_server():
    """
    Finds an available server that isn't full.

    Helps clients locate a server with free slots for a match.

    Process:
    1. Reads optional 'type' query parameter ('1v1' or '2v2').
    2. Filters active_servers by availability and type.
    3. Returns the first available server.

    Query Parameters:
        type (str, optional): Server type to filter ('1v1' or '2v2')

    Returns:
        JSON with available server info or error if none found
    """
    server_type = request.args.get("type")
    
    available_servers_list = []
    for server in active_servers:
        if server["current_players"] < server["max_players"]:
            if server_type is None or server["type"] == server_type:
                available_servers_list.append(server)
    
    if not available_servers_list:
        error_msg = f"No available servers found"
        if server_type:
            error_msg += f" for type '{server_type}'"
        return jsonify({"error": error_msg}), 404

    selected_server = available_servers_list[0]
    
    return jsonify({
        "message": "Available server found",
        "server": {
            "ip": selected_server["ip"],
            "port": selected_server["port"],
            "type": selected_server["type"],
            "current_players": selected_server["current_players"],
            "max_players": selected_server["max_players"]
        }
    }), 200


@server_bp.route("/list", methods=["GET"])
@role_required(["admin", "student"])
def list_servers():
    """
    Lists all active servers with their current status.

    Provides a full overview of servers, including player counts and types.

    Process:
    1. Reads active_servers list.
    2. Returns the list with counts and metadata.

    Returns:
        JSON with count of active servers and their details
    """
    return jsonify({
        "message": f"Found {len(active_servers)} active servers",
        "servers": active_servers
    }), 200


@server_bp.route("/status/<server_ip>/<int:server_port>", methods=["GET"])
@role_required(["admin", "student"])
def get_server_status(server_ip, server_port):
    """
    Gets the status of a specific server.

    Fetches server information based on IP and port.

    Process:
    1. Extracts server_ip and server_port from URL.
    2. Searches active_servers for a match.
    3. Returns server info if found.

    URL Parameters:
        server_ip (str): IP of the server
        server_port (int): Port of the server

    Returns:
        JSON with server info or error if not found
    """
    server_key = f"{server_ip}:{server_port}"
    
    for server in active_servers:
        if f"{server['ip']}:{server['port']}" == server_key:
            return jsonify({
                "message": "Server found",
                "server": server
            }), 200
    
    return jsonify({"error": "Server not found"}), 404


@server_bp.route("/health", methods=["GET"])
@role_required(["admin", "student"])
def health_check():
    """
    Health check endpoint for server management system.

    Provides basic operational status and number of active servers.

    Process:
    1. Counts active_servers.
    2. Returns system health and timestamp.

    Returns:
        JSON with 'healthy' status, active server count, and timestamp
    """
    return jsonify({
        "status": "healthy",
        "active_servers_count": len(active_servers),
        "timestamp": datetime.datetime.now().isoformat()
    }), 200
    
@server_bp.route("/decrement-players", methods=["POST"])
@role_required(["admin", "student"])
def decrement_player_count():
    """
    Decrements the player count for a specific server by 1.

    This endpoint allows admins or students to update server availability
    when a player leaves. It ensures that the current player count does not
    drop below zero and maintains accurate tracking of active server slots.

    Use Cases:
    - Player disconnects or leaves a match
    - Keeping server availability information accurate
    - Managing server load dynamically

    Process:
    1. Validates that the JSON body exists.
    2. Checks required fields: ip and port.
    3. Searches active_servers for the server with matching IP and port.
    4. Decrements current_players by 1, ensuring it doesn't go below 0.
    5. Logs the change and returns updated server information.

    Request Body:
        ip (str): Server IP address
        port (int): Server port

    Returns:
        JSON response containing:
            - message (str): Confirmation message
            - server_info (dict): Updated server information
        Or error JSON if server not found or missing fields.
    """

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    if "ip" not in data or "port" not in data:
        return jsonify({"error": "Missing required fields: ip, port"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    for server in active_servers:
        if f"{server['ip']}:{server['port']}" == server_key:
            old_count = server["current_players"]
            if old_count > 0:
                server["current_players"] -= 1
            
            logger.info(f"Server {server_key} player count decremented: {old_count} -> {server['current_players']}")
            
            return jsonify({
                "message": "Player count decremented successfully",
                "server_info": server
            }), 200
    
    return jsonify({"error": "Server not found"}), 404



# ------------------ Time Routes ------------------

@server_bp.route("/leaderboard", methods=["GET"])
@role_required(["admin", "student"])
def leaderboard():
    """
    Returns leaderboard of users sorted by time_taken.

    Provides an ordered list of users with non-zero completion times.

    Process:
    1. Queries User database for time_taken > 0.
    2. Orders by ascending time_taken.
    3. Returns username and time for each user.

    Returns:
        JSON list of users and their times
    """
    users = User.query.filter(User.time_taken > 0).order_by(User.time_taken.asc()).all()
    result = [
        {"username": u.username, "time_taken": u.time_taken}
        for u in users
    ]
    return jsonify(result), 200


@server_bp.route("/update-time", methods=["POST"])
@role_required(["admin", "student"])
def update_time():
    """
    Updates a user's time_taken if the new time is faster.

    Ensures leaderboard only keeps fastest completion times.

    Process:
    1. Validates JSON body exists with username and time.
    2. Converts time to float.
    3. Fetches user from database.
    4. Updates time_taken if new time is faster or previous is 0.

    Request Body:
        username (str): Username of the user
        time (float): New completion time

    Returns:
        JSON with success status, message, and updated time
    """
    data = request.get_json(silent=True)
    if not data or "username" not in data or "time" not in data:
        return jsonify({"success": False, "error": "Missing username or time"}), 400

    username = data["username"]
    try:
        new_time = float(data["time"])
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid time value"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"success": False, "error": "User not found"}), 404

    # Ensure user.time_taken is never None
    if user.time_taken is None:
        user.time_taken = 0.0

    # Only update if new time is faster or previous time is 0
    if user.time_taken == 0.0 or new_time < user.time_taken:
        user.time_taken = new_time
        db.session.commit()
        return jsonify({
            "success": True,
            "message": f"Time updated for {username}",
            "time_taken": user.time_taken
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": f"No update needed. Existing time ({user.time_taken}) is faster."
        }), 200


@server_bp.route("/reset-times", methods=["POST"])
@role_required(["admin"])
def reset_times():
    """
    Resets all users' time_taken to 0.0.

    Only accessible by admins. Useful for starting new competitions or
    clearing the leaderboard.

    Process:
    1. Fetches all users.
    2. Sets time_taken to 0.0 for each.
    3. Commits changes.

    Returns:
        JSON with confirmation message or error if failed
    """
    try:
        users = User.query.all()
        for user in users:
            user.time_taken = 0.0
        db.session.commit()
        return jsonify({"message": "All user times have been reset to 0.0"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to reset times: {str(e)}"}), 500


@server_bp.route("/remove-from-leaderboard", methods=["POST"])
@role_required(["admin"])
def remove_from_leaderboard():
    """
    Removes a user from the leaderboard.

    Admin endpoint to reset a user's time_taken to 0.0.

    Process:
    1. Validates JSON body exists with username.
    2. Fetches user from database.
    3. Sets time_taken to 0.0 and commits changes.

    Request Body:
        username (str): Username of the user to remove

    Returns:
        JSON with confirmation or error message
    """
    data = request.get_json(silent=True)
    if not data or "username" not in data:
        return jsonify({"error": "Missing username"}), 400

    username = data["username"]
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        user.time_taken = 0.0
        db.session.commit()
        return jsonify({
            "message": f"{username} has been removed from the leaderboard"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to remove user: {str(e)}"}), 500
