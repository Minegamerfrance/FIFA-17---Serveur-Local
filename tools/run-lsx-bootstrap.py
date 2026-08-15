#!/usr/bin/env python3
"""Attach LSX bootstrap discovery Frida script to FIFA17.exe (obs-only, no pokes)."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT_PATH = HERE / "frida-lsx-bootstrap.js"
LOG_DIR = HERE / "versions" / "lsx-bootstrap"


def find_fifa_pid() -> int:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("fifa17.exe", "fifa17"):
            return int(p.pid)
    raise SystemExit("FIFA17.exe not running — open the game first.")


def default_fifa_path() -> Path:
    env = os.environ.get("FIFA17_EXE", "").strip()
    if env:
        return Path(env)
    # workspace sibling: .../serveur fifa 17/FIFA 17/FIFA17.exe
    cand = ROOT.parent / "FIFA 17" / "FIFA17.exe"
    if cand.is_file():
        return cand
    raise SystemExit("FIFA17.exe path unknown — set FIFA17_EXE=")


def main() -> None:
    mode = os.environ.get("LSX_BOOT_MODE", "UNKNOWN").strip() or "UNKNOWN"
    spawn = os.environ.get("LSX_BOOT_SPAWN", "0").strip() in ("1", "true", "True", "yes")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"boot-{mode}-{stamp}.log"
    latest = LOG_DIR / f"latest-{mode}.log"

    src = SCRIPT_PATH.read_text(encoding="utf-8")
    src = (
        f"var LSX_BOOT_MODE = {mode!r};\n"
        f"var LSX_BOOT_LOG = null;\n"
        + src
    )

    device = frida.get_local_device()
    session = None
    pid = None

    if spawn:
        exe = default_fifa_path()
        print(f"[lsx-boot] SPAWN {exe} mode={mode}")
        print(f"[lsx-boot] log → {log_path}")
        print("[lsx-boot] NO pokes. Hooks before resume — cold Origin discovery.")
        pid = device.spawn([str(exe)], cwd=str(exe.parent))
        session = device.attach(pid)
    else:
        pid = find_fifa_pid()
        print(f"[lsx-boot] attach pid={pid} mode={mode}")
        print(f"[lsx-boot] log → {log_path}")
        print("[lsx-boot] NO pokes. Prefer LSX_BOOT_SPAWN=1 for cold start.")
        session = device.attach(pid)

    script = session.create_script(src)
    lines: list[str] = []

    def on_message(message, data):  # noqa: ANN001
        if message.get("type") == "send":
            text = str(message.get("payload"))
        elif message.get("type") == "error":
            text = "[lsx-boot] ERROR " + str(message)
        else:
            text = str(message)
        print(text)
        lines.append(text)
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass

    script.on("message", on_message)

    def on_log(level, text):  # noqa: ANN001
        line = text if text.endswith("\n") else text
        print(line.rstrip("\n"))
        lines.append(line.rstrip("\n"))
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(line.rstrip("\n") + "\n")
        except OSError:
            pass

    try:
        script.set_log_handler(on_log)
    except Exception:
        pass

    script.load()
    if spawn:
        device.resume(pid)
        print(f"[lsx-boot] resumed pid={pid} — wait ~90s for VERDICT / Ctrl+C")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[lsx-boot] detach")
    finally:
        try:
            latest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass
        try:
            session.detach()
        except Exception:
            pass
        print(f"[lsx-boot] wrote {log_path}")
        print(f"[lsx-boot] latest → {latest}")


if __name__ == "__main__":
    main()
