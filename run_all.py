#!/usr/bin/env python3
import os
import subprocess
import sys
from db.models import init_all
from seed_providers import run as seed_run

def main():
    # 1) init dbs
    init_all()
    # 2) seed providers
    seed_run()
    # 3) import rules JSON into ai_ref.db
    rules_json = os.environ.get("RULES_JSON", "scheduling_rules.all_categories.json")
    subprocess.run([sys.executable, "ingest/import_rules_from_json.py", rules_json], check=True)
    # 4) (optional) ingest files directory
    ai_ref_dir = os.environ.get("AI_REF_DIR", "ai_reference")
    if os.path.isdir(ai_ref_dir):
        subprocess.run([sys.executable, "ingest/ocr_ingest.py", "--in-dir", ai_ref_dir], check=False)
    # 5) boot API
    host = os.environ.get("HOST", "127.0.0.1")
    port = os.environ.get("PORT", "8003")
    reload_flag = os.environ.get("RELOAD", "1")
    cmd = [sys.executable, "-m", "uvicorn", "app.chatbot_app:app", "--host", host, "--port", port]
    if reload_flag == "1":
        cmd.append("--reload")
    subprocess.run(cmd, check=False)

if __name__ == "__main__":
    main()