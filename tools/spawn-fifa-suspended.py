"""Spawn FIFA through Frida and keep the suspended process alive until resumed.

The launcher uses the ready file to discover the PID.  The transcript process
creates the resumed file after it has attached its early LSX hooks and resumed
the game.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import frida


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: spawn-fifa-suspended.py FIFA17.exe ready-file resumed-file")
        return 2

    exe = Path(sys.argv[1]).resolve()
    ready_file = Path(sys.argv[2]).resolve()
    resumed_file = Path(sys.argv[3]).resolve()
    if not exe.is_file():
        print(f"FIFA executable not found: {exe}")
        return 2

    device = frida.get_local_device()
    pid = device.spawn([str(exe)], cwd=str(exe.parent))
    ready_file.write_text(str(pid), encoding="ascii")
    print(f"SPAWN_SUSPENDED pid={pid} exe={exe}", flush=True)

    deadline = time.time() + 60.0
    while time.time() < deadline:
        if resumed_file.exists():
            print(f"RESUME_CONFIRMED pid={pid}", flush=True)
            return 0
        time.sleep(0.05)

    print(f"ERROR resume signal timeout pid={pid}", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
