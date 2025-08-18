# server.py - New blueprint file
from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from functools import wraps
import datetime
import logging

# Create the blueprint
server_bp = Blueprint('server', __name__)

logger = logging.getLogger(__name__)

active_servers = []

# ------------------ Custom Role Required Decorator ------------------
def role_required(roles):
    """
    Decorator to restrict access to certain roles or allow server key auth.
    """
    if not isinstance(roles, (list, tuple)):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # --- Check for server key in headers first ---
            server_key = request.headers.get("ServerKey")
            if server_key == "4fIEjhIwkfIIPcU2m4vYDdLe0ZFkDgzh":
                # Allow bypass with server key
                return f(*args, **kwargs)

            # --- Fall back to normal user auth ---
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


# ------------------ Server Registration ------------------
@server_bp.route("/register", methods=["POST"])
@role_required(["admin", "student"])
def register_server():
    """
    Registers a new game server.
    Expected JSON body:
    {
        "ip": "192.168.1.100",
        "port": 8080,
        "type": "1v1",  # or "2v2"
        "max_players": 2,
        "current_players": 0
    }
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
    Deregisters a game server.
    Expected JSON body:
    {
        "ip": "192.168.1.100",
        "port": 8080
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    if "ip" not in data or "port" not in data:
        return jsonify({"error": "Missing required fields: ip, port"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    # Find and remove server
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
    Updates the player count for a specific server.
    Expected JSON body:
    {
        "ip": "192.168.1.100",
        "port": 8080,
        "current_players": 1
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    required_fields = ["ip", "port", "current_players"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    # Find and update server
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
    Query parameters:
    - type: "1v1" or "2v2" (optional, returns any type if not specified)
    
    Returns the IP and port of an available server.
    """
    server_type = request.args.get("type")
    
    # Filter servers by type if specified
    available_servers_list = []
    for server in active_servers:
        # Check if server has available slots
        if server["current_players"] < server["max_players"]:
            # If type is specified, filter by type
            if server_type is None or server["type"] == server_type:
                available_servers_list.append(server)
    
    if not available_servers_list:
        error_msg = f"No available servers found"
        if server_type:
            error_msg += f" for type '{server_type}'"
        return jsonify({"error": error_msg}), 404
    
    # Return the first available server (you could implement load balancing here)
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
    Health check endpoint for the server management system.
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
    Expected JSON body:
    {
        "ip": "192.168.1.100",
        "port": 8080
    }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400
    
    if "ip" not in data or "port" not in data:
        return jsonify({"error": "Missing required fields: ip, port"}), 400
    
    server_key = f"{data['ip']}:{data['port']}"
    
    # Find and update server
    for server in active_servers:
        if f"{server['ip']}:{server['port']}" == server_key:
            old_count = server["current_players"]
            # Ensure the count doesn't go below 0
            if old_count > 0:
                server["current_players"] -= 1
            
            logger.info(f"Server {server_key} player count decremented: {old_count} -> {server['current_players']}")
            
            return jsonify({
                "message": "Player count decremented successfully",
                "server_info": server
            }), 200
    
    return jsonify({"error": "Server not found"}), 404