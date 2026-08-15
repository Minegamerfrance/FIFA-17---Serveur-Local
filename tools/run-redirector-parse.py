"""Attach Redirector XML parse autopsy (v74) to FIFA17.exe."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
SCRIPT = (HERE / "frida-redirector-parse.js").read_text(encoding="utf-8")
LOG_DIR = HERE / "versions" / "v74-REDIR"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = LOG_DIR / "frida.log"


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass
        return len(data)

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass


def main() -> int:
    log_f = open(LOG_PATH, "w", encoding="utf-8", newline="\n")
    sys.stdout = Tee(sys.__stdout__, log_f)
    sys.stderr = Tee(sys.__stderr__, log_f)

    print(f"=== redirector-parse log → {LOG_PATH} ===")
    print(f"=== {datetime.now(timezone.utc).isoformat()} ===")

    device = frida.get_local_device()
    while True:
        procs = [p for p in device.enumerate_processes() if p.name.lower() == "fifa17.exe"]
        if procs:
            break
        print("Waiting for FIFA17.exe … (lance le jeu)")
        time.sleep(2)

    pid = procs[0].pid
    print(f"Attaching to FIFA17.exe pid={pid}")
    session = device.attach(pid)

    def on_msg(message, _data):
        t = message.get("type")
        if t == "send":
            print(message["payload"])
        elif t == "error":
            print(message.get("stack") or message)
        else:
            print(message)

    script = session.create_script(SCRIPT)
    script.on("message", on_msg)
    script.load()

    print("v74-REDIR chargé.")
    print("Ordre: npm start → FIFA → ce script → essaie UT")
    print("Cherche: ★★★ BLAZE PORT 10041  OU  CALL/RET/CRT autour du XML")
    print("NE PAS Ctrl+C avant la fin du test.")
    try:
        sys.__stdin__.read()
    except KeyboardInterrupt:
        print("\n=== fin session ===")
    finally:
        print(f"=== log sauvé: {LOG_PATH} ===")
        log_f.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
