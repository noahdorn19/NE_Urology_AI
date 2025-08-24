#!/bin/bash
# restart_ai.sh

# Kill any old uvicorn/watchfiles
pkill -9 -f "uvicorn.*chatbot_app" || true
pkill -9 -f "watchfiles" || true

# Double-check port 8003 is free
if lsof -tiTCP:8003 -sTCP:LISTEN >/dev/null; then
  echo "Port 8003 still in use, killing..."
  kill -9 $(lsof -tiTCP:8003 -sTCP:LISTEN)
fi

# Start fresh
exec uvicorn chatbot_app:app \
  --host 127.0.0.1 --port 8003 --reload