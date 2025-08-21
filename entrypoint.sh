#!/bin/bash
# entrypoint.sh — run a single Godot console server

PORT=${SERVER_PORT:-12341}
EXE_NAME=${SERVER_EXE:-server.console.exe}

echo "Starting Godot server $EXE_NAME on port $PORT..."

# Run Wine in foreground, pipe output to Docker logs
wine /app/$EXE_NAME --headless --port=$PORT --server > /proc/1/fd/1 2>/proc/1/fd/2
