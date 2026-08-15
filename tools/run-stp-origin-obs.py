#!/usr/bin/env python3
"""Spawn/attach FIFA with stp-origin_emu.dll observation (no pokes)."""
from __future__ import annotations

import os
import time
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT_PATH = HERE / "frida-stp-origin-obs.js"
LOG_DIR = HERE / "versions" / "stp-origin-obs"


def find_fifa_pid() -> int:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("fifa17.exe", "fifa17"):
            return int(p.pid)
    raise SystemExit("FIFA17.exe not running")


def default_fifa_path() -> Path:
    env = os.environ.get("FIFA17_EXE", "").strip()
    if env:
        return Path(env)
    cand = ROOT.parent / "FIFA 17" / "FIFA17.exe"
    if cand.is_file():
        return cand
    raise SystemExit("set FIFA17_EXE=")


def main() -> None:
    mode = os.environ.get("STP_OBS_MODE", "OBS").strip() or "OBS"
    spawn = os.environ.get("STP_OBS_SPAWN", "1").strip() in ("1", "true", "True", "yes")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"stp-{mode}-{stamp}.log"
    latest = LOG_DIR / f"latest-{mode}.log"

    src = (
        f"var STP_OBS_MODE = {mode!r};\n"
        + SCRIPT_PATH.read_text(encoding="utf-8")
    )

    device = frida.get_local_device()
    if spawn:
        exe = default_fifa_path()
        print(f"[stp] SPAWN {exe} mode={mode}")
        print(f"[stp] log → {log_path}")
        print("[stp] NO pokes. Watch STP_* tags (~90s).")
        pid = device.spawn([str(exe)], cwd=str(exe.parent))
        session = device.attach(pid)
    else:
        pid = find_fifa_pid()
        print(f"[stp] attach pid={pid} mode={mode}")
        print(f"[stp] log → {log_path}")
        session = device.attach(pid)

    script = session.create_script(src)
    lines: list[str] = []

    def on_message(message, data):  # noqa: ANN001
        if message.get("type") == "error":
            text = "[stp] ERROR " + str(message)
        else:
            text = str(message.get("payload", message))
        print(text)
        lines.append(text)
        try:
            log_path.open("a", encoding="utf-8").write(text + "\n")
        except OSError:
            pass

    def on_log(level, text):  # noqa: ANN001
        line = text.rstrip("\n")
        print(line)
        lines.append(line)
        try:
            log_path.open("a", encoding="utf-8").write(line + "\n")
        except OSError:
            pass

    script.on("message", on_message)
    try:
        script.set_log_handler(on_log)
    except Exception:
        pass

    script.load()
    if spawn:
        device.resume(pid)
        print(f"[stp] resumed pid={pid}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[stp] detach")
    finally:
        try:
            latest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            pass
        try:
            session.detach()
        except Exception:
            pass
        print(f"[stp] wrote {log_path}")
        print(f"[stp] latest → {latest}")


if __name__ == "__main__":
    main()
