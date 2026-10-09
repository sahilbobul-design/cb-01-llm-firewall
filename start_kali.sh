#!/bin/bash
cd /home/kali/llm_platform
export PYTHONPATH=.
export DATABASE_URL="sqlite:////home/kali/llm_platform/dataset/security_research.db"
export API_PORT=8000
pkill -9 -f uvicorn || true
sleep 1
nohup python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > /home/kali/llm_platform/server.log 2>&1 &
echo "Uvicorn process started."
