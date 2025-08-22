# --- watch_ai_reference.py ---
import time, threading, os

from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from organizer_client import AI_REF_ROOT, build_simple_index, ref_paths_for_user

DEBOUNCE_SEC = float(os.getenv("WATCH_DEBOUNCE_SEC", "1.5"))

class Debounce:
    def __init__(self, sec, fn):
        self.sec = sec
        self.fn = fn
        self._t = None
        self._lock = threading.Lock()

    def ping(self):
        with self._lock:
            if self._t:
                self._t.cancel()
            self._t = threading.Timer(self.sec, self.fn)
            self._t.daemon = True
            self._t.start()

class Handler(FileSystemEventHandler):
    def __init__(self, trigger):
        self.trigger = trigger
    def on_any_event(self, event):
        # Ignore temp files
        name = Path(event.src_path).name
        if name.startswith(".") or name.endswith("~"):
            return
        self.trigger.ping()

def rebuild_all():
    # Rebuild index for *all* known roots (global + all departments present)
    roots = []
    g = AI_REF_ROOT / "global"
    if g.exists():
        roots.append(g)
    # every subfolder under ai_reference is a possible dept
    for d in AI_REF_ROOT.iterdir():
        if d.is_dir() and d.name != "global":
            roots.append(d)
    if not roots:
        print("[watch] no roots found under ai_reference")
        return
    print("[watch] rebuilding simple index…")
    build_simple_index(roots)
    print("[watch] done.")

if __name__ == "__main__":
    AI_REF_ROOT.mkdir(exist_ok=True, parents=True)
    # initial full build
    rebuild_all()

    handler = Handler(Debounce(DEBOUNCE_SEC, rebuild_all))
    obs = Observer()
    obs.schedule(handler, str(AI_REF_ROOT), recursive=True)
    obs.start()
    print(f"[watch] watching {AI_REF_ROOT}")
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()